// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest_test

import (
	"fmt"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/tstest/natlab/vmtest"
	"tailscale.com/tstest/natlab/vnet"
	"tailscale.com/types/key"
)

// TestDERPReceiveAfterRestart reproduces the asymmetric DERP receive stall from
// tailscale/tailscale#19422. The two nodes have no usable direct path and use
// different home DERPs. Restarting pod preserves its node identity, as a
// Tailscale Kubernetes sidecar with persistent state does.
func TestDERPReceiveAfterRestart(t *testing.T) {
	env := vmtest.New(t, vmtest.AllOnline())

	podNet := env.AddNetwork("1.0.0.1", "192.168.1.1/24", vnet.HardNAT)
	peerNet := env.AddNetwork("2.0.0.1", "192.168.2.1/24", vnet.HardNAT)
	derpOnly := vnet.TailscaledEnv{Key: "TS_DEBUG_STRIP_ENDPOINTS", Value: "1"}
	pod := env.AddNode("pod", podNet, derpOnly, vmtest.OS(vmtest.Gokrazy))
	peer := env.AddNode("peer", peerNet, derpOnly, vmtest.OS(vmtest.Gokrazy))

	pinDERPStep := env.AddStep("Pin pod and peer to different home DERPs")
	baselineStep := env.AddStep("Verify bidirectional DERP connectivity")
	restartStep := env.AddStep("Restart pod tailscaled with persistent identity")
	outboundStep := env.AddStep("Ping pod → peer over DERP after restart")
	inboundStep := env.AddStep("Ping peer → pod over DERP after restart")

	env.Start()

	podKey := env.Status(pod).Self.PublicKey
	peerKey := env.Status(peer).Self.PublicKey
	cs := env.ControlServer()
	waitHomeDERP := func(n *vmtest.Node, nodeKey key.NodePublic, region int) {
		t.Helper()
		if err := tstest.WaitFor(30*time.Second, func() error {
			cn := cs.Node(nodeKey)
			if cn == nil {
				return fmt.Errorf("control has no node for %s", n.Name())
			}
			if cn.HomeDERP != region {
				return fmt.Errorf("%s home DERP = %d, want %d", n.Name(), cn.HomeDERP, region)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}

	pinDERPStep.Begin()
	env.ForcePreferredDERP(pod, 1)
	env.ForcePreferredDERP(peer, 2)
	waitHomeDERP(pod, podKey, 1)
	waitHomeDERP(peer, peerKey, 2)
	pinDERPStep.End(nil)

	baselineStep.Begin()
	if err := env.PingExpect(pod, peer, vmtest.PingRouteDERP, 30*time.Second); err != nil {
		baselineStep.Fatalf("pod → peer baseline route: %v", err)
	}
	if err := env.PingExpect(peer, pod, vmtest.PingRouteDERP, 30*time.Second); err != nil {
		baselineStep.Fatalf("peer → pod baseline route: %v", err)
	}
	if err := env.Ping(pod, peer, tailcfg.PingTSMP, 30*time.Second); err != nil {
		baselineStep.Fatalf("pod → peer baseline: %v", err)
	}
	if err := env.Ping(peer, pod, tailcfg.PingTSMP, 30*time.Second); err != nil {
		baselineStep.Fatalf("peer → pod baseline: %v", err)
	}
	baselineStep.End(nil)

	restartStep.Begin()
	env.RestartTailscaled(pod)
	if got := env.Status(pod).Self.PublicKey; got != podKey {
		restartStep.Fatalf("pod node key changed across restart: %v → %v", podKey, got)
	}
	restartStep.End(nil)

	// This direction targets peer's still-live home DERP connection. It
	// succeeds during the bug and demonstrates that the restarted pod can send.
	outboundStep.Begin()
	if err := env.PingExpect(pod, peer, vmtest.PingRouteDERP, 10*time.Second); err != nil {
		outboundStep.Fatalf("pod → peer after restart: %v", err)
	}
	outboundStep.End(nil)

	// The reverse direction targets the restarted pod through its home DERP.
	// Before netmon is rescanned after the initial router config,
	// this receive path stalls until a later link-monitor event causes a reSTUN.
	inboundStep.Begin()
	if err := env.Ping(peer, pod, tailcfg.PingTSMP, 10*time.Second); err != nil {
		podMetrics := env.ClientMetrics(pod)
		peerMetrics := env.ClientMetrics(peer)
		env.DumpStatus(pod)
		env.DumpStatus(peer)
		inboundStep.Fatalf("asymmetric DERP connectivity after pod restart: pod → peer succeeded via DERP, but peer → pod failed: %v; pod DERP sent=%d recv=%d conns=%d; peer DERP sent=%d recv=%d conns=%d; control home DERPs: pod=%d peer=%d",
			err,
			podMetrics["magicsock_send_data_derp"].Value,
			podMetrics["magicsock_recv_data_derp"].Value,
			podMetrics["magicsock_num_derp_conns"].Value,
			peerMetrics["magicsock_send_data_derp"].Value,
			peerMetrics["magicsock_recv_data_derp"].Value,
			peerMetrics["magicsock_num_derp_conns"].Value,
			cs.Node(podKey).HomeDERP,
			cs.Node(peerKey).HomeDERP)
	}
	inboundStep.End(nil)
}
