// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package fwconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// VRRP is a virtual router on an interface of the instance, run by FRR's
// vrrpd: its IPv4 addresses and its IPv6 addresses are two virtual
// routers with the same id (IPv6 needs VRRPv3). Each is a macvlan device
// on the interface (VRRPDevices) with the virtual router's MAC address and
// its addresses, which vrrpd turns on (protodown off) while it is master.
type VRRP struct {
	Interface string `json:"interface"`
	VRID      int    `json:"vrid"`
	// Version is 2 (RFC 3768, IPv4 only) or 3 (RFC 5798); 0 is 3.
	Version int `json:"version,omitempty"`
	// Priority 1-254 (0: FRR's, 100); the highest is master.
	Priority int `json:"priority,omitempty"`
	// AdvertisementInterval in milliseconds, a multiple of 10 (VRRPv2: of
	// 1000); 0: FRR's, 1000.
	AdvertisementInterval int `json:"advertisement_interval,omitempty"`
	// NoPreempt keeps a backup of higher priority from taking over from
	// the master.
	NoPreempt bool `json:"no_preempt,omitempty"`
	// Shutdown keeps the virtual router configured but stopped (backup
	// for good).
	Shutdown bool     `json:"shutdown,omitempty"`
	IPv4     []string `json:"ipv4,omitempty"`
	IPv6     []string `json:"ipv6,omitempty"`
}

// VRRPDevicePrefix4 and VRRPDevicePrefix6 start the names of the macvlan
// devices of virtual routers; no interface may be called that.
const (
	VRRPDevicePrefix4 = "vrrp4-"
	VRRPDevicePrefix6 = "vrrp6-"
)

// VRRPProtocol is VRRP's IP protocol number (IPv4 and IPv6).
const VRRPProtocol = 112

// VRRPDevice is the macvlan device of one virtual router of one IP version
// (Family 4 or 6), on Parent, with the virtual router's MAC address and
// its addresses as host addresses (/32, /128): the parent's prefix route
// stays the parent's.
type VRRPDevice struct {
	Name      string
	Parent    string
	Family    int
	VRID      int
	MAC       string
	Addresses []string
}

// VRRPDeviceName is the macvlan device of a virtual router: vrrp4- or
// vrrp6-, the id, and the parent's name, or a hash of it when that is too
// long for an interface name.
func VRRPDeviceName(family, vrid int, parent string) string {
	prefix := fmt.Sprintf("vrrp%d-%d-", family, vrid)
	if len(prefix)+len(parent) <= 15 {
		return prefix + parent
	}
	sum := sha256.Sum256([]byte(parent))
	return prefix + hex.EncodeToString(sum[:])[:15-len(prefix)]
}

// VRRPMAC is a virtual router's MAC address (RFC 5798 section 7.3).
func VRRPMAC(family, vrid int) string {
	f := 1
	if family == 6 {
		f = 2
	}
	return fmt.Sprintf("00:00:5e:00:%02x:%02x", f, vrid)
}

// VRRPRunning reports whether the instance has virtual routers (FRR's
// vrrpd).
func (in *Instance) VRRPRunning() bool { return len(in.VRRP) > 0 }

// VRRPDevices are the macvlan devices of the instance's virtual routers,
// one per virtual router and IP version with addresses.
func (in *Instance) VRRPDevices() []VRRPDevice {
	var out []VRRPDevice
	for _, r := range in.VRRP {
		for _, fam := range []struct {
			family int
			addrs  []string
		}{{4, r.IPv4}, {6, r.IPv6}} {
			if len(fam.addrs) == 0 {
				continue
			}
			d := VRRPDevice{
				Name: VRRPDeviceName(fam.family, r.VRID, r.Interface), Parent: r.Interface,
				Family: fam.family, VRID: r.VRID, MAC: VRRPMAC(fam.family, r.VRID),
			}
			for _, s := range fam.addrs {
				if a, err := netip.ParseAddr(s); err == nil {
					d.Addresses = append(d.Addresses, netip.PrefixFrom(a, a.BitLen()).String())
				}
			}
			out = append(out, d)
		}
	}
	return out
}

// AddVRRPDevices adds to a list of interface names the VRRP devices on
// them, sorted: what is sent to a virtual router's MAC address comes in on
// its device, not on the interface.
func (in *Instance) AddVRRPDevices(names []string) []string {
	out := slices.Clone(names)
	for _, d := range in.VRRPDevices() {
		if slices.Contains(names, d.Parent) && !slices.Contains(out, d.Name) {
			out = append(out, d.Name)
		}
	}
	slices.Sort(out)
	return out
}

// VRRPParentKinds are the kinds of interface a virtual router can be on:
// ethernet ones.
var VRRPParentKinds = []string{KindPhysical, KindVLAN, KindBridge, KindLink}

// CheckVRRP checks a virtual router against the interface it is on (nil:
// not checked).
func CheckVRRP(r VRRP, parent *Interface) []string {
	v := &validator{}
	v.vrrpRouter("vrrp", r, parent)
	return v.problems
}

// vrrpRouter checks one virtual router; parent, when not nil, is its
// interface.
func (v *validator) vrrpRouter(p string, r VRRP, parent *Interface) {
	p = fmt.Sprintf("%s: virtual router %d on %s", p, r.VRID, r.Interface)
	if !ifnameRe.MatchString(r.Interface) {
		v.addf("%s: invalid interface name", p)
	}
	if r.VRID < 1 || r.VRID > 255 {
		v.addf("%s: id out of range (1-255)", p)
	}
	switch r.Version {
	case 0, 3:
	case 2:
		if len(r.IPv6) > 0 {
			v.addf("%s: IPv6 needs VRRPv3", p)
		}
	default:
		v.addf("%s: version must be 2 or 3", p)
	}
	if r.Priority < 0 || r.Priority > 254 {
		v.addf("%s: priority out of range (1-254)", p)
	}
	switch ai := r.AdvertisementInterval; {
	case ai == 0:
	case ai < 10 || ai > 40950 || ai%10 != 0:
		v.addf("%s: advertisement interval: 10-40950 ms, a multiple of 10", p)
	case r.Version == 2 && ai%1000 != 0:
		v.addf("%s: advertisement interval: VRRPv2 takes whole seconds", p)
	}
	if len(r.IPv4)+len(r.IPv6) == 0 {
		v.addf("%s: at least one address is required", p)
	}
	// The parent's static prefixes, which the addresses must be in.
	var prefixes []netip.Prefix
	if parent != nil {
		if !slices.Contains(VRRPParentKinds, parent.Kind) {
			v.addf("%s: VRRP is not supported on %s interfaces", p, parent.Kind)
		}
		for _, a := range parent.Addresses {
			if pfx, err := ParseInterfaceAddress(a); err == nil {
				prefixes = append(prefixes, pfx.Masked())
			}
		}
	}
	seen := map[netip.Addr]bool{}
	for _, fam := range []struct {
		name string
		v6   bool
		list []string
	}{{"IPv4", false, r.IPv4}, {"IPv6", true, r.IPv6}} {
		for _, s := range fam.list {
			a, err := netip.ParseAddr(s)
			switch {
			case err != nil || a.Zone() != "" || a.String() != s:
				v.addf("%s: %q is not an address", p, s)
				continue
			case a.Is6() != fam.v6:
				v.addf("%s: %s is not an %s address", p, s, fam.name)
				continue
			case a.IsUnspecified() || a.IsMulticast() || a.IsLoopback() || (!fam.v6 && a.IsLinkLocalUnicast()):
				v.addf("%s: %s can't be a virtual address", p, s)
				continue
			}
			if seen[a] {
				v.addf("%s: %s listed twice", p, s)
			}
			seen[a] = true
			if parent == nil || a.IsLinkLocalUnicast() {
				continue
			}
			if !slices.ContainsFunc(prefixes, func(pfx netip.Prefix) bool { return pfx.Contains(a) }) {
				v.addf("%s: %s is in none of the networks of %s", p, s, r.Interface)
			}
		}
	}
}

// vrrp checks the instance's virtual routers: each, and between them and
// the interfaces' addresses (addrOwner: address to interface).
func (v *validator) vrrp(p string, in *Instance, ifaces map[string]*Interface, addrOwner map[netip.Addr]string) {
	ids := map[string]bool{}
	vips := map[netip.Addr]string{}
	devices := map[string]bool{}
	for _, r := range in.VRRP {
		parent := ifaces[r.Interface]
		if parent == nil {
			v.addf("%s: virtual router %d: unknown interface %q", p, r.VRID, r.Interface)
		}
		v.vrrpRouter(p, r, parent)
		rp := fmt.Sprintf("%s: virtual router %d on %s", p, r.VRID, r.Interface)
		key := fmt.Sprintf("%s/%d", r.Interface, r.VRID)
		if ids[key] {
			v.addf("%s: duplicate", rp)
		}
		ids[key] = true
		for _, s := range slices.Concat(r.IPv4, r.IPv6) {
			a, err := netip.ParseAddr(s)
			if err != nil {
				continue
			}
			if owner, ok := addrOwner[a]; ok {
				v.addf("%s: %s is an address of interface %s", rp, s, owner)
			}
			if other, ok := vips[a]; ok && other != key {
				v.addf("%s: %s is also an address of virtual router %s", rp, s, other)
			}
			vips[a] = key
		}
	}
	for _, d := range in.VRRPDevices() {
		if devices[d.Name] {
			v.addf("%s: two virtual routers on interfaces with similar long names get the same device name %s; rename one of the interfaces", p, d.Name)
		}
		devices[d.Name] = true
	}
}

// isVRRPDeviceName reports whether name is reserved for a VRRP device.
func isVRRPDeviceName(name string) bool {
	return strings.HasPrefix(name, VRRPDevicePrefix4) || strings.HasPrefix(name, VRRPDevicePrefix6)
}
