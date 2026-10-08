// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package fwconfig

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// VRFEVPN makes a VRF an L3VPN over EVPN (RFC 9136, symmetric IRB): its
// routes are advertised as EVPN type-5 routes with an L3VNI, and the
// routes of the VRFs at other VTEPs with matching route targets come into
// its table. Expand gives the VRF a vxlan device of the VNI (L3VNIDevice,
// not learning) and a bridge in the VRF with it as its port
// (L3VNIBridge), whose MAC address is the router MAC; FRR maps the VNI to
// the VRF (vrf <name> / vni <n>) and its BGP advertises the routes in the
// L2VPN EVPN address family. It needs EVPN on the main table's BGP, which
// carries the routes to the other VTEPs; the VRF's own BGP (VRF.BGP)
// decides what its table holds for BGP, or, when it is off, the VRF's
// connected networks and static routes are advertised.
type VRFEVPN struct {
	// VNI is the L3VNI, unique among the instance's VNIs.
	VNI uint32 `json:"vni"`
	// Local is the VTEP address the vxlan device sends from.
	Local string `json:"local"`
	// Device is the underlay interface; empty: as routed.
	Device string `json:"device,omitempty"`
	// Port is the UDP port; 0 is VXLANPort.
	Port int `json:"port,omitempty"`
	// RD is the route distinguisher; empty: FRR's (router id:index).
	RD string `json:"rd,omitempty"`
	// ImportRTs and ExportRTs are route targets; empty: FRR's (ASN:VNI).
	ImportRTs []string `json:"import_rts,omitempty"`
	ExportRTs []string `json:"export_rts,omitempty"`
	// AdvertiseIPv4 and AdvertiseIPv6 advertise the VRF's routes of the
	// IP version as type-5 routes.
	AdvertiseIPv4 bool `json:"advertise_ipv4,omitempty"`
	AdvertiseIPv6 bool `json:"advertise_ipv6,omitempty"`
}

// Prefixes of the devices of a VRF's L3VNI; no interface may be called
// that.
const (
	L3VNIDevicePrefix = "l3vx-"
	L3VNIBridgePrefix = "l3br-"
)

// L3VNIDevice is the vxlan device of an L3VNI.
func L3VNIDevice(vni uint32) string { return L3VNIDevicePrefix + strconv.FormatUint(uint64(vni), 10) }

// L3VNIBridge is the bridge (the VRF's SVI) of an L3VNI.
func L3VNIBridge(vni uint32) string { return L3VNIBridgePrefix + strconv.FormatUint(uint64(vni), 10) }

// IsL3VNIName reports whether name has a prefix of an L3VNI's devices.
func IsL3VNIName(name string) bool {
	return strings.HasPrefix(name, L3VNIDevicePrefix) || strings.HasPrefix(name, L3VNIBridgePrefix)
}

// addL3VNIDevices adds the vxlan device and the bridge of each VRF's L3VNI,
// for Expand, before the VRF devices (the bridge is in the VRF).
func (in *Instance) addL3VNIDevices() {
	for _, vrf := range in.VRFs {
		e := vrf.EVPN
		if e == nil {
			continue
		}
		vx, br := L3VNIDevice(e.VNI), L3VNIBridge(e.VNI)
		if in.Interface(vx) != nil || in.Interface(br) != nil {
			continue // a name taken; validation says so
		}
		desc := "l3vni of vrf " + vrf.Name
		in.Interfaces = append(in.Interfaces,
			Interface{Name: vx, Kind: KindVXLAN, Description: desc, Enabled: true, IPv4Mode: ModeNone,
				VXLAN: &VXLAN{VNI: e.VNI, Local: e.Local, Device: e.Device, Port: e.Port}},
			Interface{Name: br, Kind: KindBridge, Description: desc, Enabled: true, IPv4Mode: ModeNone,
				Members: []string{vx}, VRF: vrf.Name})
	}
}

// l3vniNames are the names of the instance's L3VNI devices.
func (in *Instance) l3vniNames() map[string]bool {
	out := map[string]bool{}
	for _, vrf := range in.VRFs {
		if vrf.EVPN != nil {
			out[L3VNIDevice(vrf.EVPN.VNI)] = true
			out[L3VNIBridge(vrf.EVPN.VNI)] = true
		}
	}
	return out
}

// L3VNIs are the VRFs with an L3VNI.
func (in *Instance) L3VNIs() []VRF {
	var out []VRF
	for _, vrf := range in.VRFs {
		if vrf.EVPN != nil {
			out = append(out, vrf)
		}
	}
	return out
}

var extCommRe = regexp.MustCompile(`^([0-9]+|[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):([0-9]+)$`)

// CheckExtCommunity checks a route distinguisher or route target as FRR
// takes them: ASN:NN (a 2-byte AS with a 4-byte number, a 4-byte AS with a
// 2-byte one) or IPv4:NN (2 bytes).
func CheckExtCommunity(s string) error {
	m := extCommRe.FindStringSubmatch(s)
	if m == nil {
		return fmt.Errorf("%q is not ASN:NN or IPv4:NN", s)
	}
	nn, err := strconv.ParseUint(m[2], 10, 32)
	if err != nil {
		return fmt.Errorf("%q: number out of range", s)
	}
	if strings.Contains(m[1], ".") {
		a, err := netip.ParseAddr(m[1])
		if err != nil || !a.Is4() || a.String() != m[1] {
			return fmt.Errorf("%q: invalid IPv4 address", s)
		}
		if nn > 65535 {
			return fmt.Errorf("%q: with an address, the number is 0-65535", s)
		}
		return nil
	}
	asn, err := strconv.ParseUint(m[1], 10, 32)
	if err != nil || asn == 0 {
		return fmt.Errorf("%q: AS number out of range", s)
	}
	if asn > 65535 && nn > 65535 {
		return fmt.Errorf("%q: with a 4-byte AS number, the number is 0-65535", s)
	}
	return nil
}

// CheckVRFEVPN checks a VRF's L3VNI settings of their own, for the GUI.
func CheckVRFEVPN(e *VRFEVPN) []string {
	v := &validator{}
	v.vrfEVPN("evpn", e)
	return v.problems
}

func (v *validator) vrfEVPN(p string, e *VRFEVPN) {
	if e.VNI < 1 || e.VNI > MaxVNI {
		v.addf("%s: vni %d out of range (1-%d)", p, e.VNI, MaxVNI)
	}
	if e.Local == "" {
		v.addf("%s: the local VTEP address is needed", p)
	} else if !validVTEP(e.Local) {
		v.addf("%s: invalid local address %q", p, e.Local)
	}
	if e.Device != "" && !ifnameRe.MatchString(e.Device) {
		v.addf("%s: invalid underlay interface %q", p, e.Device)
	}
	if e.Port < 0 || e.Port > 65535 {
		v.addf("%s: udp port %d out of range", p, e.Port)
	}
	if e.RD != "" {
		if err := CheckExtCommunity(e.RD); err != nil {
			v.addf("%s: route distinguisher %v", p, err)
		}
	}
	for _, l := range []struct {
		what string
		rts  []string
	}{{"import", e.ImportRTs}, {"export", e.ExportRTs}} {
		seen := map[string]bool{}
		for _, rt := range l.rts {
			if err := CheckExtCommunity(rt); err != nil {
				v.addf("%s: %s route target %v", p, l.what, err)
			}
			if seen[rt] {
				v.addf("%s: %s route target %s listed twice", p, l.what, rt)
			}
			seen[rt] = true
		}
	}
	if !e.AdvertiseIPv4 && !e.AdvertiseIPv6 {
		v.addf("%s: advertise IPv4, IPv6 or both", p)
	}
}

// l3vniInstance checks the instance's L3VNIs: their settings, the main
// table's EVPN they need, their underlay, and that no interface takes
// their devices' names.
func (v *validator) l3vniInstance(p string, in *Instance) {
	gen := in.l3vniNames()
	for _, ifc := range in.Interfaces {
		if IsL3VNIName(ifc.Name) && !gen[ifc.Name] {
			v.addf("%s: interface %q: %s and %s names are for the devices of the VRFs' L3VNIs", p, ifc.Name, L3VNIDevicePrefix, L3VNIBridgePrefix)
		}
	}
	for _, vrf := range in.L3VNIs() {
		vp := fmt.Sprintf("%s: vrf %q", p, vrf.Name)
		e := vrf.EVPN
		v.vrfEVPN(vp+": evpn", e)
		if !in.EVPNRunning() {
			v.addf("%s: evpn needs bgp with evpn on in the main table", vp)
		}
		if e.Device != "" {
			if d := in.Interface(e.Device); d == nil {
				v.addf("%s: evpn: underlay interface %q is not in this instance", vp, e.Device)
			} else if d.Kind == KindVXLAN {
				v.addf("%s: evpn: underlay interface %q is a vxlan", vp, e.Device)
			} else if d.VRF != "" {
				v.addf("%s: evpn: underlay interface %q is in vrf %s", vp, e.Device, d.VRF)
			}
		}
		if b := vrf.BGP; b != nil && b.Enabled && in.BGP != nil && b.ASN != in.BGP.ASN && (len(e.ImportRTs) == 0 || len(e.ExportRTs) == 0) {
			// FRR derives the route targets from the VRF's AS, the VTEPs'
			// from the main table's.
			v.addf("%s: evpn: with a bgp AS other than the main table's, give the import and export route targets", vp)
		}
	}
}
