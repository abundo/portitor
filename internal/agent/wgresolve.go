// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/abundo/portitor/internal/fwconfig"
)

// wg(8) resolves a peer's endpoint name once, when the config is set. A
// site on a dynamic address moves away from it, so the agent sets the
// endpoint again (wg resolves it anew) for peers with a name as endpoint
// and no recent handshake, as wireguard-tools' reresolve-dns.sh does.
const (
	wgResolveInterval = time.Minute
	// A handshake is renewed every 2 minutes while traffic flows; older
	// than this, the peer is unreachable or idle.
	wgResolveStale = 135 * time.Second
)

// resolveLoop re-resolves endpoints of the applied document until ctx is
// done.
func (a *Agent) resolveLoop(ctx context.Context) {
	t := time.NewTicker(wgResolveInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.reresolve(ctx)
		}
	}
}

// reresolve runs under a.mu so an apply cannot remove a peer between the
// check and `wg set`, which would add it back.
func (a *Agent) reresolve(ctx context.Context) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.applied == nil {
		return
	}
	for i := range a.applied.Instances {
		in := &a.applied.Instances[i]
		ns := in.NetnsName()
		for _, ifc := range in.Interfaces {
			if ifc.Kind != fwconfig.KindWireGuard || !ifc.Enabled || ifc.WireGuard == nil || !hasNamedEndpoint(ifc.WireGuard.Peers) {
				continue
			}
			out, err := a.bg.Run(ctx, ns, "wg", "show", ifc.Name, "dump")
			if err != nil {
				continue
			}
			for _, c := range planReresolve(ns, ifc.Name, ifc.WireGuard.Peers, parseWGDump(prefixDump(ifc.Name, string(out))), time.Now()) {
				slog.Info("re-resolving WireGuard endpoint", "netns", ns, "interface", ifc.Name, "endpoint", c.Args[len(c.Args)-1])
				if _, err := a.bg.Run(ctx, c.Netns, c.Name, c.Args...); err != nil {
					slog.Warn("re-resolve WireGuard endpoint", "err", err)
				}
			}
		}
	}
}

// prefixDump turns `wg show <if> dump` into the `wg show all dump` format
// parseWGDump reads: every line starts with the interface name.
func prefixDump(iface, s string) string {
	var b strings.Builder
	for line := range strings.Lines(s) {
		b.WriteString(iface + "\t" + line)
	}
	return b.String()
}

// planReresolve returns `wg set` commands for the peers whose endpoint is
// a name and whose last handshake is older than wgResolveStale (or never
// happened). Peers missing from the dump are left alone: `wg set` would
// create them.
func planReresolve(ns, iface string, peers []fwconfig.WGPeer, dump []WGStatus, now time.Time) []command {
	seen := map[string]*time.Time{}
	for _, w := range dump {
		if w.Interface != iface {
			continue
		}
		for _, p := range w.Peers {
			seen[p.PublicKey] = p.LatestHandshake
		}
	}
	var cmds []command
	for _, p := range peers {
		if !namedEndpoint(p.Endpoint) {
			continue
		}
		hs, ok := seen[p.PublicKey]
		if !ok || (hs != nil && now.Sub(*hs) < wgResolveStale) {
			continue
		}
		cmds = append(cmds, command{Netns: ns, Name: "wg", Args: []string{"set", iface, "peer", p.PublicKey, "endpoint", p.Endpoint}})
	}
	return cmds
}

func hasNamedEndpoint(peers []fwconfig.WGPeer) bool {
	for _, p := range peers {
		if namedEndpoint(p.Endpoint) {
			return true
		}
	}
	return false
}

func namedEndpoint(ep string) bool {
	host, _, err := net.SplitHostPort(ep)
	if err != nil {
		return false
	}
	_, err = netip.ParseAddr(host)
	return err != nil
}

// withoutNamedEndpoints drops the Endpoint lines of a rendered WireGuard
// config whose endpoint is a name. syncconf keeps a peer's current
// endpoint when the config has none.
func withoutNamedEndpoints(conf string) string {
	var b strings.Builder
	for line := range strings.Lines(conf) {
		if k, v, ok := strings.Cut(line, "="); ok && strings.TrimSpace(k) == "Endpoint" && namedEndpoint(strings.TrimSpace(v)) {
			continue
		}
		b.WriteString(line)
	}
	return b.String()
}

// setNamedEndpoints sets the endpoints that are names, which apply leaves
// out of syncconf, once the instance's addresses and routes are set. A
// name that does not resolve (no DNS yet, at boot) is only logged: the
// rest of the instance must still come up, and resolveLoop tries again.
func (a *Agent) setNamedEndpoints(ctx context.Context, in *fwconfig.Instance) {
	for _, ifc := range in.Interfaces {
		if ifc.Kind != fwconfig.KindWireGuard || ifc.WireGuard == nil {
			continue
		}
		for _, p := range ifc.WireGuard.Peers {
			if !namedEndpoint(p.Endpoint) {
				continue
			}
			if err := a.do(ctx, command{Netns: in.NetnsName(), Name: "wg", Args: []string{"set", ifc.Name, "peer", p.PublicKey, "endpoint", p.Endpoint}}); err != nil {
				slog.Warn("set WireGuard endpoint", "netns", in.NetnsName(), "interface", ifc.Name, "endpoint", p.Endpoint, "err", err)
			}
		}
	}
}
