// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package fwconfig

import (
	"fmt"
	"strconv"
)

// A VRF interface (kind vrf) is a Linux VRF device: its Members are routed
// by its own routing table, VRFTable, apart from the instance's main table
// and its other VRFs. VRFs live in the instance's network namespace, so two
// instances may each have a VRF of the same name and table.
//
// Netfilter sees a packet that arrives on a member with the VRF device as
// its input interface in the input and forward chains, and the member as
// meta sdifname; the renderer matches a rule's members that way
// (Instance.VRFOf). Routes go in the table of their VRF (Route.VRF), or of
// their interface's VRF (Instance.RouteTable).

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

// VRFOf returns the VRF interface that name is a member of, or nil.
func (in *Instance) VRFOf(name string) *Interface {
	for i := range in.Interfaces {
		ifc := &in.Interfaces[i]
		if ifc.Kind == KindVRF {
			for _, m := range ifc.Members {
				if m == name {
					return ifc
				}
			}
		}
	}
	return nil
}

// HasVRF reports whether the instance has a VRF interface.
func (in *Instance) HasVRF() bool {
	for _, ifc := range in.Interfaces {
		if ifc.Kind == KindVRF {
			return true
		}
	}
	return false
}

// RouteTable is the routing table a route goes in, "" for main: its VRF's,
// or else its interface's VRF's.
func (in *Instance) RouteTable(r Route) string {
	name := r.VRF
	if name == "" {
		if vrf := in.VRFOf(r.Interface); vrf != nil {
			name = vrf.Name
		}
	}
	for _, ifc := range in.Interfaces {
		if ifc.Kind == KindVRF && ifc.Name == name {
			return strconv.Itoa(ifc.VRFTable)
		}
	}
	return ""
}

// VRFTables are the tables of the instance's VRFs.
func (in *Instance) VRFTables() []string {
	var out []string
	for _, ifc := range in.Interfaces {
		if ifc.Kind == KindVRF {
			out = append(out, strconv.Itoa(ifc.VRFTable))
		}
	}
	return out
}

// vrfInstance checks the instance's VRFs, their members and the routes'
// VRFs.
func (v *validator) vrfInstance(p string, in *Instance, ifaces map[string]*Interface) {
	tables := map[int]string{}
	master := map[string]string{} // member -> bridge or VRF
	for _, ifc := range in.Interfaces {
		if ifc.Kind != KindBridge && ifc.Kind != KindVRF {
			continue
		}
		for _, m := range ifc.Members {
			if other, ok := master[m]; ok && other != ifc.Name {
				v.addf("%s: interface %q is a member of both %s and %s", p, m, other, ifc.Name)
			}
			master[m] = ifc.Name
		}
	}
	for _, ifc := range in.Interfaces {
		if ifc.Kind != KindVRF {
			continue
		}
		ip := fmt.Sprintf("%s: interface %q", p, ifc.Name)
		if other, ok := tables[ifc.VRFTable]; ok {
			v.addf("%s: table %d is also %s's", ip, ifc.VRFTable, other)
		}
		tables[ifc.VRFTable] = ifc.Name
		for _, m := range ifc.Members {
			if d := ifaces[m]; d != nil && d.Kind == KindVRF {
				v.addf("%s: member %q is a vrf", ip, m)
			}
		}
	}
	for i, r := range in.Routes {
		if r.VRF == "" {
			continue
		}
		rp := fmt.Sprintf("%s: route %d", p, i+1)
		if d := ifaces[r.VRF]; d == nil || d.Kind != KindVRF {
			v.addf("%s: vrf %q is not a vrf of this instance", rp, r.VRF)
		}
		if in.RouteBFD(r) != "" {
			v.addf("%s: a route with bfd can't be in a vrf", rp)
		}
	}
}

func (v *validator) vrf(p string, ifc *Interface) {
	if msg := CheckVRFTable(ifc.VRFTable); msg != "" {
		v.addf("%s: %s", p, msg)
	}
	if ifc.IPv4Mode == ModeDHCP || ifc.DHCPv6 {
		v.addf("%s: a vrf has no dhcp client", p)
	}
	if ifc.LLDP {
		v.addf("%s: lldp is not supported on vrf interfaces", p)
	}
	for _, m := range ifc.Members {
		if !ifnameRe.MatchString(m) {
			v.addf("%s: invalid vrf member %q", p, m)
		}
		if m == ifc.Name {
			v.addf("%s: a vrf can't be its own member", p)
		}
	}
}
