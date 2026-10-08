// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package fwconfig

import (
	"cmp"
	"fmt"
	"slices"
	"strconv"
)

// VRF is a VRF of an instance (Routing → VRF): a routing table of its own
// for the interfaces in it (Interface.VRF), apart from the instance's main
// table and its other VRFs. Expand makes it a Linux vrf device of the same
// name (KindVRF, with the interfaces as Members). VRFs live in the
// instance's network namespace, so two instances may each have a VRF of
// the same name and table.
//
// Netfilter sees a packet that arrives on a VRF's interface with the VRF
// device as its input interface in the input and forward chains, and the
// interface as meta sdifname; the renderer matches such interfaces that way
// (Instance.VRFOf). Routes go in the table of their VRF (Route.VRF), or of
// their interface's VRF (Instance.RouteTable).
//
// A VRF may run routing protocols of its own (FRR's router bgp, ospf,
// ospf6 and isis ... vrf <name>) on its interfaces, apart from the
// instance's (Instance.BGP and the rest, the main table's): Routings
// lists both.
type VRF struct {
	Name        string `json:"name"`
	Table       int    `json:"table"`
	Description string `json:"description,omitempty"`
	BGP         *BGP   `json:"bgp,omitempty"`
	OSPF        *OSPF  `json:"ospf,omitempty"`
	OSPF6       *OSPF  `json:"ospf6,omitempty"`
	ISIS        *ISIS  `json:"isis,omitempty"`
	// EVPN makes the VRF an L3VPN over EVPN/VXLAN (l3vni.go); nil: off.
	EVPN *VRFEVPN `json:"evpn,omitempty"`
}

// MaxVRFs is the most VRFs an instance may have: each marks the
// connections that come in on its interfaces with a conntrack label bit
// of its own (VRFLabel), and there are 128.
const MaxVRFs = 127

// Routing is the routing protocols of the main table (VRF "") or of a VRF;
// nil or disabled: not run there.
type Routing struct {
	VRF   string
	BGP   *BGP
	OSPF  *OSPF
	OSPF6 *OSPF
	ISIS  *ISIS
	// EVPN is a VRF's L3VNI, nil for none.
	EVPN *VRFEVPN
}

// BGPOn reports whether BGP runs there.
func (r Routing) BGPOn() bool { return r.BGP != nil && r.BGP.Enabled }

// OSPFOn returns OSPF of a version (2 or 3) when it runs there, else nil.
func (r Routing) OSPFOn(version int) *OSPF {
	o := r.OSPF
	if version == 3 {
		o = r.OSPF6
	}
	if o == nil || !o.Enabled {
		return nil
	}
	return o
}

// ISISOn reports whether IS-IS runs there.
func (r Routing) ISISOn() bool { return r.ISIS != nil && r.ISIS.Enabled }

// Routings are the routing protocols of the main table, then of each VRF.
func (in *Instance) Routings() []Routing {
	out := []Routing{{BGP: in.BGP, OSPF: in.OSPF, OSPF6: in.OSPF6, ISIS: in.ISIS}}
	for _, vrf := range in.VRFs {
		out = append(out, Routing{VRF: vrf.Name, BGP: vrf.BGP, OSPF: vrf.OSPF, OSPF6: vrf.OSPF6, ISIS: vrf.ISIS, EVPN: vrf.EVPN})
	}
	return out
}

// IfaceVRF is the name of the VRF an interface is in, "" for none.
func (in *Instance) IfaceVRF(name string) string {
	if vrf := in.VRFOf(name); vrf != nil {
		return vrf.Name
	}
	return ""
}

// RouteVRF is the name of the VRF whose table a route goes in, "" for
// main.
func (in *Instance) RouteVRF(r Route) string {
	if r.VRF != "" {
		return r.VRF
	}
	return in.IfaceVRF(r.Interface)
}

// VRFLabel is the conntrack label bit (1-127) the ruleset sets on the
// connections that come in on a VRF's interfaces (or go out of them from
// the firewall), 0 for a name that is not a VRF.
func (in *Instance) VRFLabel(name string) int {
	for i, vrf := range in.VRFs {
		if vrf.Name == name {
			return i + 1
		}
	}
	return 0
}

// VRF tables the kernel uses, which a VRF can't have.
const (
	tableDefault = 253
	tableMain    = 254
	tableLocal   = 255
)

// MaxVRFTable is the largest VRF table id: below NAT64TableBase, whose
// tables are the agent's.
const MaxVRFTable = NAT64TableBase - 1

// CheckVRFTable checks a VRF's table id, for the GUI.
func CheckVRFTable(t int) string {
	if t < 1 || t > MaxVRFTable || t == tableDefault || t == tableMain || t == tableLocal {
		return fmt.Sprintf("table %d out of range (1-%d, not %d-%d)", t, MaxVRFTable, tableDefault, tableLocal)
	}
	return ""
}

// addVRFDevices adds a device (KindVRF) for each VRF, with the interfaces in
// it as members, for Expand.
func (in *Instance) addVRFDevices() {
	for _, vrf := range in.VRFs {
		if in.Interface(vrf.Name) != nil {
			continue // a name taken; validation says so
		}
		dev := Interface{Name: vrf.Name, Kind: KindVRF, Description: vrf.Description, Enabled: true,
			IPv4Mode: ModeNone, VRFTable: vrf.Table}
		for _, ifc := range in.Interfaces {
			if ifc.VRF == vrf.Name {
				dev.Members = append(dev.Members, ifc.Name)
			}
		}
		in.Interfaces = append(in.Interfaces, dev)
	}
}

// VRFByName returns the instance's VRF of that name, or nil.
func (in *Instance) VRFByName(name string) *VRF { return in.vrfByName(name) }

// vrfByName returns the instance's VRF of that name, or nil.
func (in *Instance) vrfByName(name string) *VRF {
	for i := range in.VRFs {
		if in.VRFs[i].Name == name {
			return &in.VRFs[i]
		}
	}
	return nil
}

// VRFOf returns the VRF the interface name is in, or nil. A VRRP device is
// in its parent's.
func (in *Instance) VRFOf(name string) *VRF {
	if ifc := in.Interface(name); ifc != nil {
		if ifc.VRF != "" {
			return in.vrfByName(ifc.VRF)
		}
		return nil
	}
	if !in.HasVRF() {
		return nil
	}
	for _, r := range in.VRRP {
		for _, fam := range []int{4, 6} {
			if VRRPDeviceName(fam, r.VRID, r.Interface) == name {
				return in.VRFOf(r.Interface)
			}
		}
	}
	return nil
}

// HasVRF reports whether the instance has a VRF.
func (in *Instance) HasVRF() bool { return len(in.VRFs) > 0 }

// RouteTable is the routing table a route goes in, "" for main: its VRF's,
// or else its interface's VRF's.
func (in *Instance) RouteTable(r Route) string {
	vrf := in.vrfByName(r.VRF)
	if r.VRF == "" {
		vrf = in.VRFOf(r.Interface)
	}
	if vrf == nil {
		return ""
	}
	return strconv.Itoa(vrf.Table)
}

// VRFNames are the names of the instance's VRFs.
func (in *Instance) VRFNames() []string {
	var out []string
	for _, vrf := range in.VRFs {
		out = append(out, vrf.Name)
	}
	return out
}

// VRFTables are the tables of the instance's VRFs.
func (in *Instance) VRFTables() []string {
	var out []string
	for _, vrf := range in.VRFs {
		out = append(out, strconv.Itoa(vrf.Table))
	}
	return out
}

// vrfInstance checks the instance's VRFs (their devices, of the expanded
// instance, are checked as interfaces too: name, description), the
// interfaces in them and the routes' VRFs.
func (v *validator) vrfInstance(p string, in *Instance, ifaces map[string]*Interface) {
	names := map[string]bool{}
	tables := map[int]string{}
	if len(in.VRFs) > MaxVRFs {
		v.addf("%s: at most %d vrfs", p, MaxVRFs)
	}
	for _, vrf := range in.VRFs {
		vp := fmt.Sprintf("%s: vrf %q", p, vrf.Name)
		if names[vrf.Name] {
			v.addf("%s: duplicate", vp)
		}
		names[vrf.Name] = true
		if msg := CheckVRFTable(vrf.Table); msg != "" {
			v.addf("%s: %s", vp, msg)
		}
		if other, ok := tables[vrf.Table]; ok {
			v.addf("%s: table %d is also %s's", vp, vrf.Table, other)
		}
		tables[vrf.Table] = vrf.Name
		if d := ifaces[vrf.Name]; d != nil && d.Kind != KindVRF {
			v.addf("%s: an interface has the same name", vp)
		}
	}
	bridged := map[string]string{}
	for _, ifc := range in.Interfaces {
		if ifc.Kind == KindBridge {
			for _, m := range ifc.Members {
				bridged[m] = ifc.Name
			}
		}
	}
	for _, ifc := range in.Interfaces {
		ip := fmt.Sprintf("%s: interface %q", p, ifc.Name)
		if ifc.Kind == KindVRF {
			if !names[ifc.Name] {
				v.addf("%s: a vrf device without a vrf", ip)
			}
			if ifc.VRF != "" {
				v.addf("%s: a vrf can't be in a vrf", ip)
			}
			continue
		}
		if ifc.VRF == "" {
			continue
		}
		if !names[ifc.VRF] {
			v.addf("%s: vrf %q is not a vrf of this instance", ip, ifc.VRF)
		}
		if b := bridged[ifc.Name]; b != "" {
			v.addf("%s: a member of bridge %s can't be in a vrf (put the bridge in it)", ip, b)
		}
		if in.NAT64 != nil && slices.Contains(in.NAT64.Interfaces, ifc.Name) {
			// Jool and its loop devices are the main table's.
			v.addf("%s: 464xlat is not supported on an interface in a vrf", ip)
		}
	}
	for i, r := range in.Routes {
		if r.VRF == "" {
			continue
		}
		rp := fmt.Sprintf("%s: route %d", p, i+1)
		if !names[r.VRF] {
			v.addf("%s: vrf %q is not a vrf of this instance", rp, r.VRF)
		}
	}
	for i, r := range in.Routes {
		// staticd puts a route with BFD in its VRF, on its gateway's
		// interface: they can't be in two.
		if iface := in.RouteBFD(r); iface != "" && in.IfaceVRF(iface) != in.RouteVRF(r) {
			v.addf("%s: route %d: a route with bfd must be in the vrf of its gateway's interface %s", p, i+1, iface)
		}
	}
}

// routingVRF checks that the interfaces a routing's protocols name are in
// its VRF (the main table's: in none), and that EVPN is the main table's.
func (v *validator) routingVRF(p string, in *Instance, r Routing) {
	where := func(name string) string {
		if vrf := in.IfaceVRF(name); vrf != "" {
			return "vrf " + vrf
		}
		return "no vrf"
	}
	check := func(what, name string) {
		if name != "" && in.Interface(name) != nil && in.IfaceVRF(name) != r.VRF {
			v.addf("%s: %s: interface %s is in %s", p, what, name, where(name))
		}
	}
	for _, o := range []struct {
		name string
		ospf *OSPF
	}{{"ospf", r.OSPF}, {"ospf6", r.OSPF6}} {
		if o.ospf != nil {
			for _, ifc := range o.ospf.Interfaces {
				check(o.name, ifc.Name)
			}
		}
	}
	if r.ISIS != nil {
		for _, ifc := range r.ISIS.Interfaces {
			check("isis", ifc.Name)
		}
	}
	b := r.BGP
	if b == nil {
		return
	}
	for _, peer := range slices.Concat(b.PeerGroups, b.Neighbors) {
		id := cmp.Or(peer.Address, peer.Name)
		check("bgp "+id, peer.Interface)
		if _, err := ParseAddr(peer.UpdateSource); err != nil {
			check("bgp "+id+" update source", peer.UpdateSource)
		}
		if r.VRF != "" && peer.EVPN.Activate {
			v.addf("%s: bgp %s: evpn is for the main table's bgp only", p, id)
		}
	}
	if r.VRF != "" && b.EVPN {
		v.addf("%s: bgp: evpn is for the main table's bgp only", p)
	}
}

// vrf checks a VRF device (generated).
func (v *validator) vrf(p string, ifc *Interface) {
	if ifc.IPv4Mode == ModeDHCP || ifc.DHCPv6 {
		v.addf("%s: a vrf has no dhcp client", p)
	}
	if ifc.LLDP {
		v.addf("%s: lldp is not supported on vrf interfaces", p)
	}
}
