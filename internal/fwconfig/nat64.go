// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package fwconfig

import (
	"fmt"
	"net/netip"
	"slices"
)

// NAT64 is the instance's stateful NAT64 (the PLAT of 464XLAT), run by Jool
// in its namespace: IPv6 packets to Prefix leave as IPv4 from Pool4.
type NAT64 struct {
	Prefix string `json:"prefix"`
	// Pool4 lists the IPv4 prefixes translated packets leave from. Empty
	// uses the address of the interface they leave on, ports 61001-65535.
	Pool4 []string `json:"pool4,omitempty"`
	// Interfaces are where packets to Prefix are translated (the ones with
	// 464XLAT); they are dropped from anywhere else.
	Interfaces []string `json:"interfaces,omitempty"`
}

// Jool's instance in each namespace.
const JoolInstance = "portitor"

// Equal reports whether two NAT64 configs make the same Jool instance (the
// Interfaces are the ruleset's); nil is none.
func (n *NAT64) Equal(o *NAT64) bool {
	if n == nil || o == nil {
		return n == o
	}
	return n.Prefix == o.Prefix && slices.Equal(n.Pool4, o.Pool4)
}

func (v *validator) nat64(p string, n *NAT64, ifaces map[string]*Interface) {
	if err := CheckNAT64Prefix(n.Prefix); err != nil {
		v.addf("%s: nat64: %v", p, err)
	}
	for _, s := range n.Pool4 {
		if pfx, err := netip.ParsePrefix(s); err != nil || !pfx.Addr().Is4() || pfx != pfx.Masked() {
			v.addf("%s: nat64: invalid IPv4 pool prefix %q", p, s)
		}
	}
	for _, name := range n.Interfaces {
		if ifaces[name] == nil {
			v.addf("%s: nat64: unknown interface %q", p, name)
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
