// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package gp

//go:generate go run golang.org/x/sys/windows/mkwinsyscall -output zsyscall_windows.go mksyscall.go

//sys enterCriticalPolicySection(machine bool) (handle policyLockHandle, err error) [int32(failretval)==0] = userenv.EnterCriticalPolicySection
//sys freeGPOList(gpoList *_GROUP_POLICY_OBJECT) (err error) [int32(failretval)==0] = userenv.FreeGPOListW
//sys getAppliedGPOList(flags uint32, machineName *uint16, userSid *windows.SID, extensionID *windows.GUID, gpoList **_GROUP_POLICY_OBJECT) (ret error) = userenv.GetAppliedGPOListW
//sys impersonateLoggedOnUser(token windows.Token) (err error) [int32(failretval)==0] = advapi32.ImpersonateLoggedOnUser
//sys leaveCriticalPolicySection(handle policyLockHandle) (err error) [int32(failretval)==0] = userenv.LeaveCriticalPolicySection
//sys registerGPNotification(event windows.Handle, machine bool) (err error) [int32(failretval)==0] = userenv.RegisterGPNotification
//sys refreshPolicyEx(machine bool, flags uint32) (err error) [int32(failretval)==0] = userenv.RefreshPolicyEx
//sys unregisterGPNotification(event windows.Handle) (err error) [int32(failretval)==0] = userenv.UnregisterGPNotification
