// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"net/netip"
	"path/filepath"
	"strings"

	"github.com/abundo/portitor/internal/fwconfig"
)

// Static neighbours are permanent ARP and ND entries. The kernel can't tag
// them as ours, so the agent keeps the ones it added in
// <state>/neighbours.json and removes only those when they go.

func (a *Agent) staticNeighFile(in *fwconfig.Instance) string {
	return filepath.Join(a.cfg.Paths.InstanceState(in.Name), "neighbours.json")
}

func (a *Agent) applyStaticNeighbours(ctx context.Context, in *fwconfig.Instance) error {
	ns := in.NetnsName()
	var applied []fwconfig.StaticNeighbour
	_ = readJSON(a.staticNeighFile(in), &applied) // none yet, or unreadable: nothing to remove
	if len(in.StaticNeighbours) == 0 && len(applied) == 0 {
		return nil
	}
	var have []IPNeighbour
	for _, fam := range []string{"-4", "-6"} {
		out, err := a.run.Run(ctx, ns, "ip", "-j", fam, "neigh", "show", "nud", "permanent")
		if err != nil {
			return err
		}
		have = append(have, parseIPNeigh(out, fam == "-6")...)
	}
	if err := a.doAll(ctx, planStaticNeighbours(ns, in.StaticNeighbours, have, applied)); err != nil {
		return err
	}
	want := in.StaticNeighbours
	if want == nil {
		want = []fwconfig.StaticNeighbour{}
	}
	return writeJSON(a.staticNeighFile(in), want, 0o644)
}

// planStaticNeighbours adds the wanted entries the kernel lacks (have: its
// permanent ones) and removes the ones applied before that are no longer
// wanted.
func planStaticNeighbours(ns string, want []fwconfig.StaticNeighbour, have []IPNeighbour, applied []fwconfig.StaticNeighbour) []command {
	key := func(dev, addr string) string {
		if a, err := netip.ParseAddr(addr); err == nil {
			addr = a.String()
		}
		return dev + "|" + addr
	}
	haveMAC := map[string]string{}
	for _, n := range have {
		haveMAC[key(n.Interface, n.Address)] = strings.ToLower(n.MAC)
	}
	wanted := map[string]bool{}
	for _, n := range want {
		wanted[key(n.Interface, n.Address)] = true
	}
	var cmds []command
	for _, n := range applied {
		k := key(n.Interface, n.Address)
		if _, ok := haveMAC[k]; ok && !wanted[k] {
			cmds = append(cmds, ipCmd(ns, "neigh", "del", n.Address, "dev", n.Interface))
		}
	}
	for _, n := range want {
		mac := strings.ToLower(strings.ReplaceAll(n.MAC, "-", ":"))
		if haveMAC[key(n.Interface, n.Address)] == mac {
			continue
		}
		cmds = append(cmds, ipCmd(ns, "neigh", "replace", n.Address, "lladdr", mac, "dev", n.Interface, "nud", "permanent"))
	}
	return cmds
}
