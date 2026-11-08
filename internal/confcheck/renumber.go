// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package confcheck

import (
	"net/netip"
	"slices"

	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/fwconfig"
)

// renumber moves the DHCP and router advertisement settings with an
// interface's address. They are set per IPAM prefix, so changing
// 2001:db8:1::1/64 to 2001:db8:2::1/64 would otherwise leave them on a
// prefix no interface has an address in, which the agent refuses, and
// nothing on the new one. Per IP version, when exactly one prefix leaves
// the interface and one comes in, no other interface of the instance has an
// address in the old one, and the new one has no DHCP or RA yet, the
// settings move: the DHCP range keeps its host part when the prefix length
// is the same and is emptied otherwise.
func renumber(c *Ctx, i, old *datastore.Node) {
	if old == nil {
		return
	}
	gone, added := prefixDiff(old.LeafLists["addresses"], i.LeafLists["addresses"]), prefixDiff(i.LeafLists["addresses"], old.LeafLists["addresses"])
	for _, v4 := range []bool{true, false} {
		from, to := ofVersion(gone, v4), ofVersion(added, v4)
		if len(from) == 1 && len(to) == 1 {
			movePrefixSettings(c, i, from[0], to[0])
		}
	}
}

func movePrefixSettings(c *Ctx, i *datastore.Node, from, to netip.Prefix) {
	in := instanceOf(i)
	src := in.Entry("ipam-prefix", []string{from.String()})
	if src == nil || (!on(src, "dhcp-enabled") && !on(src, "ra-enabled")) {
		return
	}
	for _, o := range in.Lists["interface"] {
		if o != i && slices.Contains(prefixDiff(o.LeafLists["addresses"], nil), from) {
			return // still served there
		}
	}
	dst := in.Entry("ipam-prefix", []string{to.String()})
	if dst == nil {
		dst = in.AddEntry(in.S.Child("ipam-prefix"), map[string]string{"prefix": to.String()})
	} else if on(dst, "dhcp-enabled") || on(dst, "ra-enabled") {
		return // the new prefix has its own settings
	}
	for _, l := range []string{"dhcp-enabled", "ra-enabled"} {
		if on(src, l) {
			set(dst, l, "true")
		}
	}
	if on(src, "ra-slaac") && to.Bits() == 64 {
		set(dst, "ra-slaac", "true")
	}
	if vs := src.LeafLists["dhcp-dns-servers"]; vs != nil {
		dst.LeafLists["dhcp-dns-servers"] = slices.Clone(vs)
	}
	clear(dst, "dhcp-range-start", "dhcp-range-end", "dhcp-gateway")
	if from.Bits() == to.Bits() {
		for _, l := range []string{"dhcp-range-start", "dhcp-range-end", "dhcp-gateway"} {
			if v := rebase(src.Leaf(l), to); v != "" {
				set(dst, l, v)
			}
		}
	}
	if (dst.Leaf("dhcp-range-start") == "") != (dst.Leaf("dhcp-range-end") == "") {
		clear(dst, "dhcp-range-start", "dhcp-range-end")
	}
	clear(src, "dhcp-enabled", "ra-enabled", "ra-slaac")
}

// prefixDiff is the prefixes of the addresses in a that none in b is in.
func prefixDiff(a, b []string) []netip.Prefix {
	in := func(list []string) []netip.Prefix {
		var out []netip.Prefix
		for _, s := range list {
			if fwconfig.IsDelegated(s) {
				continue
			}
			if p, err := netip.ParsePrefix(s); err == nil && !slices.Contains(out, p.Masked()) {
				out = append(out, p.Masked())
			}
		}
		return out
	}
	other := in(b)
	var out []netip.Prefix
	for _, p := range in(a) {
		if !slices.Contains(other, p) {
			out = append(out, p)
		}
	}
	return out
}

func ofVersion(list []netip.Prefix, v4 bool) []netip.Prefix {
	var out []netip.Prefix
	for _, p := range list {
		if p.Addr().Is4() == v4 {
			out = append(out, p)
		}
	}
	return out
}

// rebase puts the host part of address s into prefix p ("" stays "").
func rebase(s string, p netip.Prefix) string {
	a, err := netip.ParseAddr(s)
	if err != nil || a.Is4() != p.Addr().Is4() {
		return ""
	}
	host, net := a.AsSlice(), p.Addr().AsSlice()
	for b := 0; b < p.Bits(); b++ {
		mask := byte(0x80 >> (b % 8))
		host[b/8] = host[b/8]&^mask | net[b/8]&mask
	}
	out, _ := netip.AddrFromSlice(host)
	return out.String()
}
