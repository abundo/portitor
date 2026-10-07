// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/abundo/portitor/internal/fwconfig"
)

// zeroMAC is the forwarding database address of a vxlan's flood list:
// unknown, broadcast and multicast frames go to every such entry's VTEP.
const zeroMAC = "00:00:00:00:00:00"

// fdbEntry is an entry of `bridge -j fdb show` output.
type fdbEntry struct {
	MAC   string   `json:"mac"`
	Dst   string   `json:"dst"`
	Flags []string `json:"flags"`
}

// vxlanFDBs reads the forwarding databases of the instance's vxlan devices
// that exist, by device.
func (a *Agent) vxlanFDBs(ctx context.Context, ns string, in *fwconfig.Instance, have map[string]ipLink) (map[string][]fdbEntry, error) {
	out := map[string][]fdbEntry{}
	for _, ifc := range in.VXLANs() {
		if have[ifc.Name].kind() != "vxlan" {
			continue
		}
		b, err := a.run.Run(ctx, ns, "bridge", "-j", "fdb", "show", "dev", ifc.Name)
		if err != nil {
			return nil, err
		}
		var list []fdbEntry
		if len(b) > 0 {
			if err := json.Unmarshal(b, &list); err != nil {
				return nil, fmt.Errorf("bridge fdb show dev %s: %w", ifc.Name, err)
			}
		}
		out[ifc.Name] = list
	}
	return out, nil
}

// planVXLAN keeps the instance's vxlan devices as EVPN or the flood lists
// want them. With EVPN, zebra learns remote VTEPs and MAC addresses from
// BGP: the device and its bridge port don't learn from packets, the bridge
// answers ARP and ND for the remote hosts (neigh_suppress), and the
// forwarding database is zebra's. Without, the device learns, and its flood
// list is the remotes: the agent owns the all-zero entries.
func planVXLAN(ns string, in *fwconfig.Instance, have map[string]ipLink, fdbs map[string][]fdbEntry) []command {
	evpn := in.EVPNRunning()
	var cmds []command
	for _, ifc := range in.VXLANs() {
		l := have[ifc.Name]
		learning := l.LinkInfo == nil || l.LinkInfo.InfoData.Learning == nil || *l.LinkInfo.InfoData.Learning
		if learning == evpn {
			kw := "learning"
			if evpn {
				kw = "nolearning"
			}
			cmds = append(cmds, ipCmd(ns, "link", "set", "dev", ifc.Name, "type", "vxlan", kw))
		}
		if evpn {
			// Its bridge port's flags; zebra needs the vxlan in a bridge
			// (validated), whose membership planLinkSettings set.
			var port *ipLink
			if l.LinkInfo != nil && l.LinkInfo.InfoSlaveKind == "bridge" {
				port = &l
			}
			if port == nil || !isFalse(port.LinkInfo.InfoSlaveData.Learning) || !isTrue(port.LinkInfo.InfoSlaveData.NeighSuppress) {
				cmds = append(cmds, command{Netns: ns, Name: "bridge", Args: []string{"link", "set", "dev", ifc.Name, "neigh_suppress", "on", "learning", "off"}})
			}
			continue
		}
		var cur []string
		for _, e := range fdbs[ifc.Name] {
			if e.MAC == zeroMAC && e.Dst != "" && !slices.Contains(e.Flags, "extern_learn") {
				cur = append(cur, e.Dst)
			}
		}
		for _, r := range ifc.VXLAN.Remotes {
			if !slices.Contains(cur, r) {
				cmds = append(cmds, command{Netns: ns, Name: "bridge", Args: []string{"fdb", "append", zeroMAC, "dev", ifc.Name, "dst", r}})
			}
		}
		for _, r := range cur {
			if !slices.Contains(ifc.VXLAN.Remotes, r) {
				cmds = append(cmds, command{Netns: ns, Name: "bridge", Args: []string{"fdb", "del", zeroMAC, "dev", ifc.Name, "dst", r}})
			}
		}
	}
	return cmds
}

func isTrue(b *bool) bool  { return b != nil && *b }
func isFalse(b *bool) bool { return b != nil && !*b }
