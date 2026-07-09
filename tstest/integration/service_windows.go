// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package integration

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"tailscale.com/tsconst/wintun"
)

// serviceName is the Windows service tailscaled installs itself as
// (see cmd/tailscaled/install_windows.go).
const serviceName = "Tailscale"

// startWindowsServiceDaemon installs and starts tailscaled as a LocalSystem
// Windows service (the mode a customer runs), stages wintun.dll next to the
// binary, delivers the harness environment via tailscaled-env.txt, and waits
// for the LocalAPI. It fails the test on error.
func (n *TestNode) startWindowsServiceDaemon() *Daemon {
	t := n.env.t
	t.Helper()

	// install-system-daemon fails if the service exists; clear any leftover
	// service and stale global state from a prior crashed run first.
	n.uninstallService()
	n.cleanupServiceState()

	stageWintun(t, filepath.Dir(n.env.daemon))
	n.writeServiceEnvFile()

	if out, err := exec.CommandContext(t.Context(), n.env.daemon, "install-system-daemon").CombinedOutput(); err != nil {
		t.Fatalf("install-system-daemon: %v\n%s", err, out)
	}
	// Teardown (LIFO): stop, uninstall, then wipe global state so the next
	// serialized test starts clean.
	t.Cleanup(func() {
		n.stopService()
		n.uninstallService()
		n.cleanupServiceState()
	})

	n.startService()
	n.waitServiceReady(90 * time.Second)
	return &Daemon{svc: n}
}

// startService starts the installed Tailscale service and waits for the SCM to
// report it Running.
func (n *TestNode) startService() {
	t := n.env.t
	t.Helper()
	m := n.connectSCM()
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		t.Fatalf("open service %q: %v", serviceName, err)
	}
	defer s.Close()
	if err := s.Start(); err != nil {
		t.Fatalf("start service %q: %v", serviceName, err)
	}
	n.waitServiceState(s, svc.Running, 60*time.Second)
}

// stopService requests a stop and waits until the service is actually Stopped,
// failing the test if it doesn't stop in time (a stuck stop is a real bug, not
// something to race past).
func (n *TestNode) stopService() {
	t := n.env.t
	t.Helper()
	m := n.connectSCM()
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return // not installed; nothing to stop
	}
	defer s.Close()
	st, err := s.Query()
	if err != nil {
		t.Fatalf("query service %q: %v", serviceName, err)
	}
	if st.State == svc.Stopped {
		return
	}
	if _, err := s.Control(svc.Stop); err != nil {
		t.Fatalf("stop service %q: %v", serviceName, err)
	}
	n.waitServiceState(s, svc.Stopped, 60*time.Second)
}

// uninstallService removes the Tailscale service via tailscaled's
// uninstall-system-daemon subcommand and waits until it's gone. A service that
// isn't installed is fine (the prelude calls this to clear leftovers); any
// other failure fails the test, since a lingering service breaks the next
// install.
func (n *TestNode) uninstallService() {
	t := n.env.t
	t.Helper()
	if !n.serviceExists() {
		return
	}
	// Not t.Context(): this also runs from t.Cleanup, where the test's context
	// is already canceled.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, n.env.daemon, "uninstall-system-daemon").CombinedOutput(); err != nil {
		t.Fatalf("uninstall-system-daemon: %v\n%s", err, out)
	}
	n.waitServiceGone(30 * time.Second)
}

// writeServiceEnvFile writes the harness environment a service can't inherit
// (the SCM starts it without the test process's environment) to the file
// tailscaled reads at startup: %ProgramData%\Tailscale\tailscaled-env.txt.
func (n *TestNode) writeServiceEnvFile() {
	t := n.env.t
	t.Helper()
	dir := filepath.Join(os.Getenv("ProgramData"), "Tailscale")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("creating %s: %v", dir, err)
	}
	dst := filepath.Join(dir, "tailscaled-env.txt")
	body := strings.Join(n.daemonEnv("windows"), "\n") + "\n"
	if err := os.WriteFile(dst, []byte(body), 0o644); err != nil {
		t.Fatalf("writing %s: %v", dst, err)
	}
	// Removed with the rest of the state dir in cleanupServiceState.
}

// cleanupServiceState removes the global state directory the service writes
// (%ProgramData%\Tailscale), so a subsequent serialized test doesn't inherit a
// prior node's identity or state. Called only after the service is stopped.
func (n *TestNode) cleanupServiceState() {
	t := n.env.t
	t.Helper()
	dir := filepath.Join(os.Getenv("ProgramData"), "Tailscale")
	if err := os.RemoveAll(dir); err != nil {
		t.Logf("removing %s: %v", dir, err)
	}
}

// waitServiceReady polls the LocalAPI until BackendState is neither "" nor
// NoState, guarding the post-start race (tailscale/tailscale#8695).
func (n *TestNode) waitServiceReady(timeout time.Duration) {
	t := n.env.t
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		st, err := n.Status()
		if err == nil && st.BackendState != "" && st.BackendState != "NoState" {
			return
		}
		last = err
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("service LocalAPI not ready within %v (last err: %v)", timeout, last)
}

// waitServiceState polls s until it reaches want, failing the test on timeout.
func (n *TestNode) waitServiceState(s *mgr.Service, want svc.State, timeout time.Duration) {
	t := n.env.t
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		st, err := s.Query()
		if err != nil {
			t.Fatalf("query service %q: %v", serviceName, err)
		}
		if st.State == want {
			return
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("service %q did not reach state %d within %v", serviceName, want, timeout)
}

// waitServiceGone polls until the service no longer exists, so a fresh
// install-system-daemon won't collide with a leftover.
func (n *TestNode) waitServiceGone(timeout time.Duration) {
	t := n.env.t
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !n.serviceExists() {
			return
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("service %q still present after %v", serviceName, timeout)
}

// serviceExists reports whether the Tailscale service is currently installed.
func (n *TestNode) serviceExists() bool {
	t := n.env.t
	t.Helper()
	m := n.connectSCM()
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return false
	}
	s.Close()
	return true
}

// connectSCM connects to the Windows service manager, failing the test on error.
func (n *TestNode) connectSCM() *mgr.Mgr {
	t := n.env.t
	t.Helper()
	m, err := mgr.Connect()
	if err != nil {
		t.Fatalf("connect to service manager: %v", err)
	}
	return m
}

// stageWintun makes a verified wintun.dll a sibling of tailscaled.exe in dir;
// tailscaled loads it from the directory of its own executable (see
// fullyQualifiedWintunPath in cmd/tailscaled/tailscaled_windows.go), so the
// adapter only comes up if the DLL is next to the binary.
func stageWintun(t testing.TB, dir string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), "GET", wintun.URL, nil)
	if err != nil {
		t.Fatalf("wintun request: %v", err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("downloading wintun: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("downloading %s: HTTP %s", wintun.URL, res.Status)
	}
	zipBytes, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("reading wintun zip: %v", err)
	}
	if sum := sha256.Sum256(zipBytes); hex.EncodeToString(sum[:]) != wintun.SHA256 {
		t.Fatalf("wintun zip sha256 = %s, want %s", hex.EncodeToString(sum[:]), wintun.SHA256)
	}
	zr, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		t.Fatalf("opening wintun zip: %v", err)
	}
	member := wintun.DLLZipPath("amd64")
	f, err := zr.Open(member)
	if err != nil {
		t.Fatalf("wintun zip missing %q: %v", member, err)
	}
	defer f.Close()
	out, err := os.Create(filepath.Join(dir, "wintun.dll"))
	if err != nil {
		t.Fatalf("creating wintun.dll: %v", err)
	}
	if _, err := io.Copy(out, f); err != nil {
		out.Close()
		t.Fatalf("extracting wintun.dll: %v", err)
	}
	if err := out.Close(); err != nil {
		t.Fatalf("closing wintun.dll: %v", err)
	}
}
