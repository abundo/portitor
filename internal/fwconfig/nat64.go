// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package fwconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"slices"
)

// NAT64 is the instance's stateful NAT64 (the PLAT of 464XLAT), run by Jool
// in its namespace.
//
// Translated packets go round a loop device of the interface they came in
// on (NAT64Devices) and are forwarded again as IPv4, so the forward rules,
// NAT and shapers see them as coming in on that device. Each interface with
// 464XLAT has its own pool4 address, chosen by the packet mark Jool keeps
// (NAT64Device.Mark); its translations leave from that address, which a
// rule (by source, iif lo) routes into the device. A dummy device that
// redirects what it sends to what it receives (tc mirred) is the loop.
// Replies don't go round it: the masquerade's reverse NAT gives them the
// pool4 address at dstnat, and Jool takes them right after, on the
// interface they came in on.
type NAT64 struct {
	Prefix string `json:"prefix"`
	// Pool4 lists the IPv4 prefixes the loop devices' addresses come
	// from, one address per interface with 464XLAT. Empty is
	// NAT64DefaultPool4, which is masqueraded where it leaves.
	Pool4 []string `json:"pool4,omitempty"`
	// Interfaces are where packets to Prefix are translated (the ones with
	// 464XLAT); they are dropped from anywhere else.
	Interfaces []string `json:"interfaces,omitempty"`
}

// Jool's instance in each namespace.
const JoolInstance = "portitor"

// NAT64DefaultPool4 is the IPv4 service continuity prefix (RFC 7335),
// meant for translators and never routed: 8 addresses, for 8 interfaces
// with 464XLAT.
const NAT64DefaultPool4 = "192.0.0.0/29"

// NAT64DevicePrefix starts the names of the loop devices; no interface may
// be called that.
const NAT64DevicePrefix = "n64-"

// NAT64MarkBase is the packet mark of the first loop device's packets to
// the NAT64 prefix, which chooses its pool4 address in Jool. The shapers'
// marks are above it, the hairpin's below.
const NAT64MarkBase = 0x5000

// NAT64TableBase is the routing table, and the preference of the rule
// that looks it up, of the first loop device.
const NAT64TableBase = 6400

// NAT64Device is the loop device of one interface with 464XLAT.
type NAT64Device struct {
	Name   string
	Parent string
	// Address is the device's pool4 address; translations from Parent
	// leave from it, and it is routed to the device.
	Address string
	Mark    int
	Table   int
}

// NAT64DeviceName is the loop device of an interface with 464XLAT: "n64-"
// and the name, or a hash of it when that is too long.
func NAT64DeviceName(parent string) string {
	if len(NAT64DevicePrefix)+len(parent) <= 15 {
		return NAT64DevicePrefix + parent
	}
	sum := sha256.Sum256([]byte(parent))
	return NAT64DevicePrefix + hex.EncodeToString(sum[:])[:15-len(NAT64DevicePrefix)]
}

// Pool4Prefixes are the prefixes the loop devices' addresses come from.
func (n *NAT64) Pool4Prefixes() []string {
	if len(n.Pool4) == 0 {
		return []string{NAT64DefaultPool4}
	}
	return n.Pool4
}

// xlatInterfaces are the interfaces with 464XLAT, sorted, so their pool4
// addresses follow the names.
func (n *NAT64) xlatInterfaces() []string {
	out := slices.Clone(n.Interfaces)
	slices.Sort(out)
	return slices.Compact(out)
}

// pool4Addrs lists up to max addresses of the pool, in order.
func (n *NAT64) pool4Addrs(max int) []netip.Addr {
	var out []netip.Addr
	for _, s := range n.Pool4Prefixes() {
		p, err := netip.ParsePrefix(s)
		if err != nil || !p.Addr().Is4() {
			continue // Validate refuses it
		}
		for a := p.Masked().Addr(); p.Contains(a) && len(out) < max; a = a.Next() {
			out = append(out, a)
		}
	}
	return out
}

// NAT64Devices are the loop devices of the interfaces with 464XLAT; none
// without NAT64. An interface the pool has no address for is left out
// (Validate refuses that).
func (in *Instance) NAT64Devices() []NAT64Device {
	if in.NAT64 == nil {
		return nil
	}
	names := in.NAT64.xlatInterfaces()
	var out []NAT64Device
	for i, a := range in.NAT64.pool4Addrs(len(names)) {
		out = append(out, NAT64Device{
			Name: NAT64DeviceName(names[i]), Parent: names[i], Address: a.String(),
			Mark: NAT64MarkBase + i, Table: NAT64TableBase + i,
		})
	}
	return out
}

// AddNAT64Devices adds to a list of interface names the loop devices of
// the ones with 464XLAT: their translated IPv4 comes in on them.
func (in *Instance) AddNAT64Devices(names []string) []string {
	out := slices.Clone(names)
	for _, d := range in.NAT64Devices() {
		if slices.Contains(names, d.Parent) && !slices.Contains(out, d.Name) {
			out = append(out, d.Name)
		}
	}
	slices.Sort(out)
	return out
}

// Equal reports whether two NAT64 configs make the same Jool instance;
// nil is none.
func (n *NAT64) Equal(o *NAT64) bool {
	if n == nil || o == nil {
		return n == o
	}
	return n.Prefix == o.Prefix && slices.Equal(n.Pool4, o.Pool4) && slices.Equal(n.xlatInterfaces(), o.xlatInterfaces())
}

func (v *validator) nat64(p string, in *Instance, ifaces map[string]*Interface) {
	n := in.NAT64
	if err := CheckNAT64Prefix(n.Prefix); err != nil {
		v.addf("%s: nat64: %v", p, err)
	}
	var pool []netip.Prefix
	for _, s := range n.Pool4 {
		pfx, err := netip.ParsePrefix(s)
		if err != nil || !pfx.Addr().Is4() || pfx != pfx.Masked() {
			v.addf("%s: nat64: invalid IPv4 pool prefix %q", p, s)
			continue
		}
		pool = append(pool, pfx)
	}
	for _, name := range n.Interfaces {
		if ifaces[name] == nil {
			v.addf("%s: nat64: unknown interface %q", p, name)
		}
	}
	if len(pool) < len(n.Pool4) {
		return
	}
	names := n.xlatInterfaces()
	if have := len(n.pool4Addrs(len(names))); have < len(names) {
		what := "the IPv4 pool has"
		if len(n.Pool4) == 0 {
			what = "the default pool " + NAT64DefaultPool4 + " has; set the NAT64 IPv4 pool, it has"
		}
		v.addf("%s: nat64: %d interfaces with 464XLAT need %d IPv4 pool addresses, one each; %s %d", p, len(names), len(names), what, have)
	}
	// The pool's addresses are routed to the loop devices, so they must
	// not be anything else's.
	for _, s := range n.Pool4 {
		pfx, _ := netip.ParsePrefix(s)
		for _, ifc := range in.Interfaces {
			for _, a := range ifc.Addresses {
				if ap, err := netip.ParsePrefix(a); err == nil && ap.Masked().Overlaps(pfx) {
					v.addf("%s: nat64: IPv4 pool %s overlaps interface %s's address %s", p, s, ifc.Name, a)
				}
			}
		}
		for _, r := range in.Routes {
			if rp, err := netip.ParsePrefix(r.Destination); err == nil && rp.Bits() > 0 && rp.Masked().Overlaps(pfx) {
				v.addf("%s: nat64: IPv4 pool %s overlaps the route to %s", p, s, r.Destination)
			}
		}
	}
}

// NAT64WellKnownPrefix is the well-known NAT64 prefix (RFC 6052).
const NAT64WellKnownPrefix = "64:ff9b::/96"

// CheckNAT64Prefix checks a NAT64 prefix as RFC 6052 has them: IPv6, of
// length 32, 40, 48, 56, 64 or 96, and with bits 64 to 71 (the "u" octet)
// zero. BIND's dns64 and radvd's nat64prefix take the same.
func CheckNAT64Prefix(s string) error {
	pfx, err := netip.ParsePrefix(s)
	if err != nil || !pfx.Addr().Is6() || pfx != pfx.Masked() {
		return fmt.Errorf("invalid NAT64 prefix %q", s)
	}
	switch pfx.Bits() {
	case 32, 40, 48, 56, 64, 96:
	default:
		return fmt.Errorf("NAT64 prefix %q: the length must be 32, 40, 48, 56, 64 or 96", s)
	}
	if pfx.Addr().As16()[8] != 0 {
		return fmt.Errorf("NAT64 prefix %q: bits 64 to 71 must be zero", s)
	}
	return nil
}
