// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package fwconfig

// Packet normalization on an interface, as PF's scrub does some of it.
//
// MSS clamping (Interface.MSSClamp): the forwarded TCP SYNs (and SYN-ACKs)
// that leave by the interface get an MSS no larger than the route's MTU
// allows, or MSSClampValue, so the other end never sends segments too big
// for a tunnel or a smaller link on the way; those that come in on it
// one no larger than the interface's own MTU allows (MSSClampIn), so the
// hosts behind the firewall don't send them either. The MSS is only ever
// lowered.
//
// The reverse path check (Interface.RPF) drops, before conntrack, what
// comes in on the interface from a source the instance routes out by
// another (fib saddr . iif): spoofed sources. Routing that is asymmetric
// on purpose (two uplinks) fails it.

// MinMSS and MaxMSS bound MSSClampValue (IPv4: the MTU less 40 bytes of
// headers; IPv6 takes 20 bytes more).
const (
	MinMSS = 536
	MaxMSS = 65495
)

// minMSS6 is IPv6's smallest MSS: its minimum MTU, 1280, less 60 bytes.
const minMSS6 = 1220

// DefaultMTU is the MTU an interface of the kind gets when it sets none,
// where that is not ethernet's 1500 (0).
func DefaultMTU(kind string) int {
	switch kind {
	case KindWireGuard:
		return 1420
	case Kind6in4:
		return 1480
	}
	return 0
}

// MSSFamily is the MSS for IP version family (4 or 6) of an IPv4 MSS.
func MSSFamily(mss, family int) int {
	if family == 6 {
		return max(mss-20, minMSS6)
	}
	return mss
}

// MSSClampIn is the IPv4 MSS that the SYNs coming in on the interface are
// clamped to: MSSClampValue, else what its MTU leaves (its own, else its
// kind's DefaultMTU); 0 when neither is known, as the route's MTU is the
// way back in, not the interface's.
func (ifc *Interface) MSSClampIn() int {
	if ifc.MSSClampValue != 0 {
		return ifc.MSSClampValue
	}
	mtu := ifc.MTU
	if mtu == 0 {
		mtu = DefaultMTU(ifc.Kind)
	}
	if mtu == 0 {
		return 0
	}
	return max(mtu-40, MinMSS)
}

// normalizeKind tells the kinds of interface that may clamp the MSS or check
// the reverse path: those that carry traffic of their own.
func normalizeKind(kind string) bool {
	return kind != KindLoopback && kind != KindVRF
}

// normalize checks an interface's MSS clamping and reverse path check.
func (v *validator) normalize(ip string, ifc *Interface) {
	if ifc.MSSClampValue != 0 && (ifc.MSSClampValue < MinMSS || ifc.MSSClampValue > MaxMSS) {
		v.addf("%s: mss %d out of range (%d-%d)", ip, ifc.MSSClampValue, MinMSS, MaxMSS)
	}
	if ifc.MSSClampValue != 0 && !ifc.MSSClamp {
		v.addf("%s: mss without mss clamping", ip)
	}
	if (ifc.MSSClamp || ifc.RPF) && !normalizeKind(ifc.Kind) {
		v.addf("%s: mss clamping and the reverse path check are not supported on %s interfaces", ip, ifc.Kind)
	}
}

// normalizeInstance checks what the interfaces' MSS clamping and reverse
// path checks need of the instance: not on a bridge's members (the bridge
// is the interface packets come in on), and no reverse path check on an
// interface in a VRF with a virtual router, whose device the check can't
// look up in the VRF's table (the device's check is by its parent's name,
// in the main table).
func (v *validator) normalizeInstance(p string, in *Instance, ifaces map[string]*Interface) {
	for _, ifc := range in.Interfaces {
		if ifc.Kind != KindBridge {
			continue
		}
		for _, m := range ifc.Members {
			if mi := ifaces[m]; mi != nil && (mi.MSSClamp || mi.RPF) {
				v.addf("%s: interface %q: member of bridge %q: set mss clamping and the reverse path check on the bridge", p, m, ifc.Name)
			}
		}
	}
	seen := map[string]bool{}
	for _, r := range in.VRRP {
		if pi := ifaces[r.Interface]; pi != nil && pi.RPF && pi.VRF != "" && !seen[r.Interface] {
			v.addf("%s: interface %q: the reverse path check is not supported with VRRP in a VRF", p, r.Interface)
			seen[r.Interface] = true
		}
	}
}
