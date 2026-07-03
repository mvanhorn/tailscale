// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package gp contains [Group Policy]-related functions and types.
//
// [Group Policy]: https://web.archive.org/web/20240630210707/https://learn.microsoft.com/en-us/previous-versions/windows/desktop/policy/group-policy-start-page
package gp

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"golang.org/x/sys/windows"
	"tailscale.com/types/logger"
	"tailscale.com/util/winutil/gp/regext"
)

// Scope is a user or machine policy scope.
type Scope int

const (
	// MachinePolicy indicates a machine policy.
	// Registry-based machine policies reside in HKEY_LOCAL_MACHINE.
	MachinePolicy Scope = iota
	// UserPolicy indicates a user policy.
	// Registry-based user policies reside in HKEY_CURRENT_USER of the corresponding user.
	UserPolicy
)

// _RP_FORCE causes RefreshPolicyEx to reapply policy even if no policy change was detected.
// See [RP_FORCE] for details.
//
// [RP_FORCE]: https://web.archive.org/save/https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-refreshpolicyex
const _RP_FORCE = 0x1

// RefreshUserPolicy triggers a machine policy refresh, but does not wait for it to complete.
// When the force parameter is true, it causes the Group Policy to reapply policy even
// if no policy change was detected.
func RefreshMachinePolicy(force bool) error {
	return refreshPolicyEx(true, toRefreshPolicyFlags(force))
}

// RefreshUserPolicy triggers a user policy refresh, but does not wait for it to complete.
// When the force parameter is true, it causes the Group Policy to reapply policy even
// if no policy change was detected.
//
// The token indicates user whose policy should be refreshed.
// If specified, the token must be either a primary token with TOKEN_QUERY and TOKEN_DUPLICATE
// access, or an impersonation token with TOKEN_QUERY and TOKEN_IMPERSONATE access,
// and the specified user must be logged in interactively.
//
// Otherwise, a zero token value indicates the current user. It should not
// be used by services or other applications running under system identities.
//
// The function fails with windows.ERROR_ACCESS_DENIED if the user represented by the token
// is not logged in interactively at the time of the call.
func RefreshUserPolicy(token windows.Token, force bool) error {
	if token != 0 {
		// Impersonate the user whose policy we need to refresh.
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if err := impersonateLoggedOnUser(token); err != nil {
			return err
		}
		defer func() {
			if err := windows.RevertToSelf(); err != nil {
				// RevertToSelf errors are non-recoverable.
				panic(fmt.Errorf("could not revert impersonation: %w", err))
			}
		}()
	}

	return refreshPolicyEx(true, toRefreshPolicyFlags(force))
}

func toRefreshPolicyFlags(force bool) uint32 {
	if force {
		return _RP_FORCE
	}
	return 0
}

func IsDomainPolicyAppliedToRegistry() (bool, error) {
	itr, err := AppliedGPOsForLocalMachine(&regext.REGISTRY_EXTENSION_GUID)
	if err != nil {
		return false, err
	}

	for gpo, err := range itr {
		if err != nil {
			return false, err
		}

		if !gpo.IsDisabled() && !gpo.IsLocal() {
			return true, nil
		}
	}

	return false, nil
}

func openMachineRegistryPolicyArchive() (*os.File, error) {
	programData, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return nil, err
	}

	// https://web.archive.org/web/20260120022445/https://sdmsoftware.com/security-related/understanding-the-registry-policy-archive-file/
	return os.Open(filepath.Join(programData, "ntuser.pol"))
}

func IsPolicyAppliedToMachineRegistryKey(subKeyMatcher func(string) bool) (bool, error) {
	if subKeyMatcher == nil {
		return false, os.ErrInvalid
	}

	lock := NewMachinePolicyLock()
	if lock.Lock() == nil {
		defer lock.Unlock()
	}

	haveReg, err := IsDomainPolicyAppliedToRegistry()
	if err != nil || !haveReg {
		return haveReg, err
	}

	archive, err := openMachineRegistryPolicyArchive()
	if err != nil {
		return false, err
	}

	rr, err := regext.NewReaderTakeOwnership(archive)
	if err != nil {
		return false, err
	}
	defer rr.Close()

	for rc, err := range rr.Entries() {
		if err != nil {
			return false, err
		}
		if subKeyMatcher(rc.SubKey) {
			return true, nil
		}
	}

	return false, nil
}

func DumpAppliedRegistryGPOs(logf logger.Logf) {
	if logf == nil {
		return
	}

	lock := NewMachinePolicyLock()
	if lock.Lock() == nil {
		defer lock.Unlock()
	}

	itr, err := AppliedGPOsForLocalMachine(&regext.REGISTRY_EXTENSION_GUID)
	if err != nil {
		logf("AppliedGPOsForLocalMachine failed: %v", err)
	}

	for v, err := range itr {
		if err != nil {
			logf("Conversion failed: %v", err)
			return
		}
		logf("Entry:\n%#v", v)

		rr, err := regext.NewReaderFromPolicyPath(v.FileSysPath)
		if err != nil {
			logf("NewReaderFromPolicyPath error: %v", err)
			return
		}

		err = func() error {
			defer rr.Close()
			for cmd, err := range rr.Entries() {
				if err != nil {
					logf("Error during iteration: %v", err)
					return err
				}
				logf("SubKey: %s", cmd.SubKey)
			}
			return nil
		}()
		if err != nil {
			return
		}
	}
}
