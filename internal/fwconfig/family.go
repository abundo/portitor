// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package fwconfig

// FamilyMatch is a rule's match for one IP version: Family is ipv4 or
// ipv6, and Src/Dst hold only addresses of that version. Family is the
// rule's own (possibly empty) family when the rule has no addresses.
type FamilyMatch struct {
	Family   string
	Src, Dst []string
}

// MatchFamilies splits a match into one FamilyMatch per IP version it can
// apply to (see Rule). A rule without addresses stays a single match. An
// empty result means the addresses, family and protocol exclude each other.
// Unparseable addresses are ignored; Validate reports them.
func MatchFamilies(family, proto string, src, dst []string) []FamilyMatch {
	if len(src) == 0 && len(dst) == 0 {
		return []FamilyMatch{{Family: family}}
	}
	var out []FamilyMatch
	for _, fam := range []string{"ipv4", "ipv6"} {
		if family != "" && family != fam {
			continue
		}
		if (proto == "icmp" && fam != "ipv4") || (proto == "icmpv6" && fam != "ipv6") {
			continue
		}
		s, d := filterFamily(src, fam), filterFamily(dst, fam)
		if (len(src) > 0 && len(s) == 0) || (len(dst) > 0 && len(d) == 0) {
			continue
		}
		out = append(out, FamilyMatch{Family: fam, Src: s, Dst: d})
	}
	return out
}

func filterFamily(list []string, fam string) []string {
	var out []string
	for _, a := range list {
		if p, err := ParseAddrOrPrefix(a); err == nil && p.Addr().Is4() == (fam == "ipv4") {
			out = append(out, a)
		}
	}
	return out
}

// AddrFamily is "ipv4" or "ipv6" for an address or prefix, "" if invalid.
func AddrFamily(s string) string {
	p, err := ParseAddrOrPrefix(s)
	switch {
	case err != nil:
		return ""
	case p.Addr().Is4():
		return "ipv4"
	}
	return "ipv6"
}
