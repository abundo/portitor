// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package fwconfig

import (
	"fmt"
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
type VRF struct {
	Name        string `json:"name"`
	Table       int    `json:"table"`
	Description string `json:"description,omitempty"`
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

// vrfByName returns the instance's VRF of that name, or nil.
func (in *Instance) vrfByName(name string) *VRF {
	for i := range in.VRFs {
		if in.VRFs[i].Name == name {
			return &in.VRFs[i]
		}
	}
	return nil
}

// VRFOf returns the VRF the interface name is in, or nil.
func (in *Instance) VRFOf(name string) *VRF {
	if ifc := in.Interface(name); ifc != nil && ifc.VRF != "" {
		return in.vrfByName(ifc.VRF)
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
	}
	for i, r := range in.Routes {
		if r.VRF == "" {
			continue
		}
		rp := fmt.Sprintf("%s: route %d", p, i+1)
		if !names[r.VRF] {
			v.addf("%s: vrf %q is not a vrf of this instance", rp, r.VRF)
		}
		if in.RouteBFD(r) != "" {
			v.addf("%s: a route with bfd can't be in a vrf", rp)
		}
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
