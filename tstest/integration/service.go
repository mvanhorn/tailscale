// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

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

	"tailscale.com/tsconst/wintun"
)

// startWindowsServiceDaemon installs and starts tailscaled as a real
// LocalSystem Windows service (the mode a customer runs), staging wintun.dll
// next to the binary and delivering the harness environment via
// tailscaled-env.txt, then waits for the LocalAPI. It fails the test on error.
func (n *TestNode) startWindowsServiceDaemon() *Daemon {
	t := n.env.t

	// install-system-daemon errors if the service exists; clear any leftover.
	scRun(n.env.daemon, "uninstall-system-daemon")
	n.waitServiceGone("Tailscale", 30*time.Second)

	stageWintun(t, filepath.Dir(n.env.daemon))
	n.writeServiceEnvFile()

	if out, err := exec.Command(n.env.daemon, "install-system-daemon").CombinedOutput(); err != nil {
		t.Fatalf("install-system-daemon: %v\n%s", err, out)
	}
	t.Cleanup(func() { scRun(n.env.daemon, "uninstall-system-daemon") })

	if out, err := exec.Command("sc", "start", "Tailscale").CombinedOutput(); err != nil {
		t.Fatalf("sc start Tailscale: %v\n%s", err, out)
	}
	n.waitServiceReady(90 * time.Second)
	return &Daemon{svc: n}
}

// writeServiceEnvFile writes the harness environment a service can't inherit
// (the SCM starts it without the test process's env) to the file tailscaled
// reads at startup: %ProgramData%\Tailscale\tailscaled-env.txt.
func (n *TestNode) writeServiceEnvFile() {
	t := n.env.t
	dir := filepath.Join(os.Getenv("ProgramData"), "Tailscale")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("creating %s: %v", dir, err)
	}
	env := []string{
		"TS_DEBUG_PERMIT_HTTP_C2N=1",
		"TS_LOG_TARGET=" + n.env.LogCatcherServer.URL,
		"HTTP_PROXY=" + n.env.TrafficTrapServer.URL,
		"HTTPS_PROXY=" + n.env.TrafficTrapServer.URL,
		"TS_NETCHECK_GENERATE_204_URL=" + n.env.ControlServer.URL + "/generate_204",
		"TS_ASSUME_NETWORK_UP_FOR_TEST=1",
		"TS_PANIC_IF_HIT_MAIN_CONTROL=1",
		"TS_DISABLE_PORTMAPPER=1",
		"TS_DEBUG_LOG_RATE=all",
	}
	dst := filepath.Join(dir, "tailscaled-env.txt")
	if err := os.WriteFile(dst, []byte(strings.Join(env, "\n")+"\n"), 0o644); err != nil {
		t.Fatalf("writing %s: %v", dst, err)
	}
	t.Cleanup(func() { os.Remove(dst) })
}

// serviceCleanShutdown stops the Tailscale service. There is no owned process to
// signal and no exit code to assert, unlike the child-process path.
func (n *TestNode) serviceCleanShutdown(t testing.TB) {
	if out, err := exec.Command("sc", "stop", "Tailscale").CombinedOutput(); err != nil {
		t.Errorf("sc stop Tailscale: %v\n%s", err, out)
	}
}

// waitServiceReady polls the LocalAPI until BackendState is neither "" nor
// NoState, guarding the post-start race (tailscale/tailscale#8695).
func (n *TestNode) waitServiceReady(timeout time.Duration) {
	t := n.env.t
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

// waitServiceGone polls until the named service no longer exists, so a fresh
// install-system-daemon won't collide with a leftover.
func (n *TestNode) waitServiceGone(name string, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if err := exec.Command("sc", "query", name).Run(); err != nil {
			return // sc query non-zero => not present
		}
		time.Sleep(time.Second)
	}
	n.env.t.Logf("service %q still present after %v; proceeding anyway", name, timeout)
}

// scRun runs a tailscaled subcommand best-effort (teardown, where a non-zero
// exit is expected/benign).
func scRun(bin string, args ...string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	exec.CommandContext(ctx, bin, args...).Run()
}

// stageWintun makes a verified wintun.dll a sibling of tailscaled.exe in dir;
// tailscaled loads it from its own directory (fullyQualifiedWintunPath), so the
// real adapter only comes up if the DLL is next to the binary.
// TS_TEST_WINTUN_DLL overrides the download for runners with restricted egress.
func stageWintun(t testing.TB, dir string) {
	dst := filepath.Join(dir, "wintun.dll")
	if override := os.Getenv("TS_TEST_WINTUN_DLL"); override != "" {
		if err := copyFileTo(override, dst); err != nil {
			t.Fatalf("staging TS_TEST_WINTUN_DLL=%q: %v", override, err)
		}
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", wintun.URL, nil)
	if err != nil {
		t.Fatalf("wintun request: %v", err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("downloading wintun (set TS_TEST_WINTUN_DLL to pre-stage it): %v", err)
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
	f, err := zr.Open(wintun.ZipMember)
	if err != nil {
		t.Fatalf("wintun zip missing %q: %v", wintun.ZipMember, err)
	}
	defer f.Close()
	out, err := os.Create(dst)
	if err != nil {
		t.Fatalf("creating %q: %v", dst, err)
	}
	if _, err := io.Copy(out, f); err != nil {
		out.Close()
		t.Fatalf("extracting wintun.dll: %v", err)
	}
	if err := out.Close(); err != nil {
		t.Fatalf("closing wintun.dll: %v", err)
	}
}

// copyFileTo copies src to dst, creating/truncating dst.
func copyFileTo(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
