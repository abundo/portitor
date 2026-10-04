// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package fwconfig

import (
	"fmt"
	"net/netip"
)

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
