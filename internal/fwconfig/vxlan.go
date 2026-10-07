// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package fwconfig

import (
	"fmt"
	"net/netip"
)

// VXLAN is a VXLAN interface's settings (a Linux vxlan device, RFC 7348):
// ethernet carried in UDP between VTEPs. Unknown destinations are flooded
// to Remotes (head-end replication); with EVPN (BGP.EVPN) FRR learns the
// remote VTEPs and MAC addresses from BGP instead, and the interface is a
// member of a bridge, whose VNI zebra advertises. Either way the auto
// input rule accepts VXLAN packets from Remotes only, or from anyone when
// there are none (EVPN).
type VXLAN struct {
	// VNI is the VXLAN network identifier, unique in the instance.
	VNI uint32 `json:"vni"`
	// Local is the firewall's VTEP address, the packets' source; EVPN
	// needs it (it is the VTEP address BGP announces).
	Local string `json:"local,omitempty"`
	// Device is the underlay interface the packets leave by; empty: as
	// routed.
	Device string `json:"device,omitempty"`
	// Port is the UDP port; 0 is VXLANPort.
	Port int `json:"port,omitempty"`
	// Remotes are the VTEPs unknown, broadcast and multicast frames are
	// flooded to; with EVPN, the VTEPs allowed to send (empty: any).
	Remotes []string `json:"remotes,omitempty"`
}

// VXLANPort is the IANA VXLAN UDP port.
const VXLANPort = 4789

// MaxVNI is the largest VXLAN network identifier (24 bits).
const MaxVNI = 1<<24 - 1

// UDPPort is the VXLAN's UDP port.
func (x *VXLAN) UDPPort() int {
	if x.Port == 0 {
		return VXLANPort
	}
	return x.Port
}

// validVTEP reports whether s is a usable VTEP address (unicast, not
// loopback), in canonical form.
func validVTEP(s string) bool {
	a, err := netip.ParseAddr(s)
	return err == nil && a.String() == s && a.Zone() == "" && !a.IsUnspecified() && !a.IsLoopback() && !a.IsMulticast() &&
		!a.IsLinkLocalUnicast() && a != netip.AddrFrom4([4]byte{255, 255, 255, 255})
}

// CheckVXLAN checks a VXLAN interface's own settings, for the GUI.
func CheckVXLAN(name string, x *VXLAN) []string {
	v := &validator{}
	v.vxlan("vxlan", &Interface{Name: name, Kind: KindVXLAN, VXLAN: x})
	return v.problems
}

func (v *validator) vxlan(p string, ifc *Interface) {
	x := ifc.VXLAN
	if x == nil {
		v.addf("%s: vxlan settings missing", p)
		return
	}
	if x.VNI < 1 || x.VNI > MaxVNI {
		v.addf("%s: vni %d out of range (1-%d)", p, x.VNI, MaxVNI)
	}
	if x.Port < 0 || x.Port > 65535 {
		v.addf("%s: udp port %d out of range", p, x.Port)
	}
	if x.Device != "" && !ifnameRe.MatchString(x.Device) {
		v.addf("%s: invalid underlay interface %q", p, x.Device)
	}
	if x.Device == ifc.Name {
		v.addf("%s: the underlay interface can't be the vxlan itself", p)
	}
	var fam netip.Addr // the first address, for the IP version
	if x.Local != "" {
		if !validVTEP(x.Local) {
			v.addf("%s: invalid local address %q", p, x.Local)
		} else {
			fam = netip.MustParseAddr(x.Local)
		}
	}
	seen := map[string]bool{}
	for _, r := range x.Remotes {
		if !validVTEP(r) {
			v.addf("%s: invalid remote address %q", p, r)
			continue
		}
		a := netip.MustParseAddr(r)
		if fam.IsValid() && a.Is4() != fam.Is4() {
			v.addf("%s: remote %s: the local and remote addresses must be of one IP version", p, r)
		}
		if !fam.IsValid() {
			if a.Is6() {
				// The device's socket is IPv4 unless its local
				// address says otherwise.
				v.addf("%s: IPv6 remotes need the local address", p)
			}
			fam = a
		}
		if r == x.Local {
			v.addf("%s: remote %s is the local address", p, r)
		}
		if seen[r] {
			v.addf("%s: remote %s listed twice", p, r)
		}
		seen[r] = true
	}
}

// vxlanInstance checks an instance's VXLAN interfaces against each other
// and its other interfaces and EVPN.
func (v *validator) vxlanInstance(p string, in *Instance, ifaces map[string]*Interface) {
	master := map[string]string{}
	for _, ifc := range in.Interfaces {
		if ifc.Kind == KindBridge {
			for _, m := range ifc.Members {
				master[m] = ifc.Name
			}
		}
	}
	vnis := map[uint32]string{}
	evpn := in.BGPRunning() && in.BGP.EVPN
	vteps := 0
	for _, ifc := range in.Interfaces {
		if ifc.Kind != KindVXLAN || ifc.VXLAN == nil {
			continue
		}
		ip := fmt.Sprintf("%s: interface %q", p, ifc.Name)
		x := ifc.VXLAN
		if other, ok := vnis[x.VNI]; ok {
			v.addf("%s: vni %d is also %s's", ip, x.VNI, other)
		}
		vnis[x.VNI] = ifc.Name
		if x.Device != "" {
			if d := ifaces[x.Device]; d == nil {
				v.addf("%s: underlay interface %q is not in this instance", ip, x.Device)
			} else if d.Kind == KindVXLAN {
				v.addf("%s: underlay interface %q is a vxlan", ip, x.Device)
			}
		}
		if !evpn {
			continue
		}
		if x.Local == "" {
			v.addf("%s: evpn needs the vxlan's local address", ip)
		}
		if master[ifc.Name] == "" {
			v.addf("%s: with evpn, a vxlan must be a member of a bridge", ip)
		}
		if ifc.Enabled {
			vteps++
		}
	}
	if evpn && vteps == 0 {
		v.addf("%s: bgp: evpn needs an enabled vxlan interface", p)
	}
}

// VXLANs returns the instance's enabled VXLAN interfaces.
func (in *Instance) VXLANs() []*Interface {
	var out []*Interface
	for i := range in.Interfaces {
		if ifc := &in.Interfaces[i]; ifc.Kind == KindVXLAN && ifc.Enabled && ifc.VXLAN != nil {
			out = append(out, ifc)
		}
	}
	return out
}

// EVPNRunning reports whether BGP runs with EVPN.
func (in *Instance) EVPNRunning() bool {
	return in.BGPRunning() && in.BGP.EVPN
}
