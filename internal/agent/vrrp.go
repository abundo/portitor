// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/fwconfig"
)

// VRRP: FRR's vrrpd runs the virtual routers (frr.conf); the agent makes
// their macvlan devices (fwconfig.VRRPDevices), which vrrpd finds by
// parent and MAC address and turns on and off with protodown. A new device
// starts protodown, so the firewall never answers for a virtual address
// before vrrpd has decided it is master; later applies leave protodown to
// vrrpd.

// planVRRPCreate returns the commands that create the instance's VRRP
// devices that are missing or wrong (kind, parent, MAC address). Stale
// ones go with the other stale virtual interfaces.
func planVRRPCreate(ns string, devs []fwconfig.VRRPDevice, have map[string]ipLink) []command {
	var cmds []command
	for _, d := range devs {
		if l, ok := have[d.Name]; ok {
			if l.kind() == "macvlan" && (l.Link == "" || l.Link == d.Parent) && strings.EqualFold(l.Address, d.MAC) {
				continue
			}
			cmds = append(cmds, ipCmd(ns, "link", "del", "dev", d.Name))
		}
		// A random link-local address: the backups' devices have the same
		// MAC address, and VRRPv3 sends from the link-local one. Set
		// before the device comes up; the kernel refuses it in link add.
		cmds = append(cmds,
			ipCmd(ns, "link", "add", "link", d.Parent, "name", d.Name, "address", d.MAC, "type", "macvlan", "mode", "bridge"),
			ipCmd(ns, "link", "set", "dev", d.Name, "addrgenmode", "random"),
			ipCmd(ns, "link", "set", "dev", d.Name, "protodown", "on"),
		)
	}
	return cmds
}

// planVRRPDevices gives the devices their addresses and brings them up.
func planVRRPDevices(ns string, devs []fwconfig.VRRPDevice, have map[string]ipLink) []command {
	var cmds []command
	for _, d := range devs {
		l := have[d.Name]
		cmds = append(cmds, planAddresses(ns, fwconfig.Interface{Name: d.Name, IPv4Mode: fwconfig.ModeStatic, Addresses: d.Addresses}, l)...)
		if !l.up() {
			cmds = append(cmds, ipCmd(ns, "link", "set", "dev", d.Name, "up"))
		}
	}
	return cmds
}

// vrrpSysctls: an interface with an IPv4 virtual router answers ARP only
// for its own addresses (arp_ignore 1), so the virtual addresses are
// answered by their devices, with the virtual MAC address, and never by a
// backup's interface. An IPv6 device skips duplicate address detection,
// as the address moves between routers.
func vrrpSysctls(devs []fwconfig.VRRPDevice) []string {
	var out []string
	key := func(name string) string { return strings.ReplaceAll(name, ".", "/") }
	for _, d := range devs {
		if d.Family == 4 {
			s := "net.ipv4.conf." + key(d.Parent) + ".arp_ignore=1"
			if !slices.Contains(out, s) {
				out = append(out, s)
			}
		} else {
			out = append(out, "net.ipv6.conf."+key(d.Name)+".accept_dad=0")
		}
	}
	return out
}

// VRRP asks FRR, through vtysh, for the state of each instance's virtual
// routers.
func (a *Agent) VRRP(ctx context.Context) *agentapi.VRRPResponse {
	resp := &agentapi.VRRPResponse{Instances: []agentapi.VRRPInstance{}}
	a.mu.Lock()
	doc := a.applied
	a.mu.Unlock()
	if doc == nil {
		return resp
	}
	for i := range doc.Instances {
		in := &doc.Instances[i]
		if !in.VRRPRunning() {
			continue
		}
		vi := agentapi.VRRPInstance{Instance: in.Name, Routers: []agentapi.VRRPRouterInfo{}}
		out, err := a.vtysh(ctx, in)("show vrrp json")
		if err != nil {
			vi.Error = vtyshError(out, err)
		} else if vi.Routers, err = parseVRRP(out); err != nil {
			vi.Error = err.Error()
		}
		resp.Instances = append(resp.Instances, vi)
	}
	return resp
}

// parseVRRP reads `show vrrp json`: a list of virtual routers.
func parseVRRP(data []byte) ([]agentapi.VRRPRouterInfo, error) {
	var list []map[string]any
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("unexpected answer from vtysh: %v", err)
	}
	out := []agentapi.VRRPRouterInfo{}
	for _, m := range list {
		o := jsonObj(m)
		num := func(keys ...string) int {
			n, _ := o.num(keys...)
			return int(n)
		}
		r := agentapi.VRRPRouterInfo{
			Interface: o.str("interface"), VRID: num("vrid"), Version: num("version"),
			Priority: num("priority"), Preempt: o.flag("preemptMode"), Shutdown: o.flag("shutdown"),
			AdvertisementInterval: num("advertisementInterval"),
		}
		r.V4 = parseVRRPFamily(o.obj("v4"))
		r.V6 = parseVRRPFamily(o.obj("v6"))
		out = append(out, r)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Interface != out[j].Interface {
			return out[i].Interface < out[j].Interface
		}
		return out[i].VRID < out[j].VRID
	})
	return out, nil
}

// parseVRRPFamily reads one IP version's half of a virtual router; nil
// when it has no addresses (vrrpd keeps it in Initialize).
func parseVRRPFamily(o jsonObj) *agentapi.VRRPFamilyInfo {
	if o == nil {
		return nil
	}
	f := &agentapi.VRRPFamilyInfo{
		State: o.str("status"), Device: o.str("interface"), MAC: o.str("vmac"),
		PrimaryAddress: o.str("primaryAddress"), Addresses: []string{},
	}
	if l, ok := o["addresses"].([]any); ok {
		for _, x := range l {
			if s, ok := x.(string); ok {
				f.Addresses = append(f.Addresses, s)
			}
		}
	}
	if len(f.Addresses) == 0 {
		return nil
	}
	n := func(o jsonObj, keys ...string) int64 { v, _ := o.num(keys...); return v }
	f.EffectivePriority = int(n(o, "effectivePriority"))
	f.MasterAdverInterval = int(n(o, "masterAdverInterval"))
	f.MasterDownInterval = int(n(o, "masterDownInterval"))
	stats := o.obj("stats")
	f.AdvertisementsSent = n(stats, "adverTxCnt", "adverTx")
	f.AdvertisementsRecv = n(stats, "adverRxCnt", "adverRx")
	f.Transitions = n(stats, "transitionCnt", "transitions")
	return f
}
