// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows

package integration

// The Windows service backend only compiles and runs on Windows. These stubs
// let the package build on other platforms; they're never called, because
// windowsService is only set when runtime.GOOS == "windows".

func (n *TestNode) startWindowsServiceDaemon() *Daemon {
	n.env.t.Fatal("Windows service daemon is only supported on Windows")
	return nil
}

func (n *TestNode) stopService() {
	n.env.t.Fatal("Windows service daemon is only supported on Windows")
}
