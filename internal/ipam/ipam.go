// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ipam builds the hierarchical prefix tree. Prefixes and addresses
// are stored flat per instance; nesting follows from CIDR containment, so
// adding 10.0.0.0/8 above existing /24s re-parents them automatically.
package ipam

import (
	"fmt"
	"math"
	"net/netip"
	"sort"

	"github.com/abundo/portitor/models"
)

type Node struct {
	Kind        string  `json:"kind"` // prefix | address
	ID          uint    `json:"id"`
	CIDR        string  `json:"cidr"` // prefix, or address without length
	Description string  `json:"description,omitempty"`
	DnsName     string  `json:"dns_name,omitempty"`
	Mac         string  `json:"mac,omitempty"`
	InterfaceID *uint   `json:"interface_id,omitempty"`
	DhcpEnabled bool    `json:"dhcp_enabled,omitempty"`
	RaEnabled   bool    `json:"ra_enabled,omitempty"`
	DhcpRange   string  `json:"dhcp_range,omitempty"`
	UsedFrac    float64 `json:"used_frac"`
	Children    []*Node `json:"children"`

	pfx      netip.Prefix
	poolSize float64 // DHCP pool addresses, counted as used
}

// Tree nests an instance's prefixes and addresses. Addresses that fall in
// no prefix are returned at the top level.
func Tree(prefixes []models.IpamPrefix, addrs []models.IpamAddress) []*Node {
	var nodes []*Node
	for _, p := range prefixes {
		pfx, err := netip.ParsePrefix(p.Prefix)
		if err != nil {
			continue
		}
		n := &Node{Kind: "prefix", ID: p.ID, CIDR: pfx.Masked().String(), Description: p.Description,
			DhcpEnabled: p.DhcpEnabled, RaEnabled: p.RaEnabled, Children: []*Node{}, pfx: pfx.Masked()}
		if p.DhcpEnabled && p.DhcpRangeStart != "" {
			n.DhcpRange = p.DhcpRangeStart + " - " + p.DhcpRangeEnd
			n.poolSize = rangeSize(p.DhcpRangeStart, p.DhcpRangeEnd)
		}
		nodes = append(nodes, n)
	}
	sortPrefixes(nodes)

	// Nest with a stack: after sorting, a prefix's ancestors are exactly
	// the stack entries that contain it.
	var roots []*Node
	var stack []*Node
	for _, n := range nodes {
		for len(stack) > 0 && !contains(stack[len(stack)-1].pfx, n.pfx) {
			stack = stack[:len(stack)-1]
		}
		if len(stack) == 0 {
			roots = append(roots, n)
		} else {
			parent := stack[len(stack)-1]
			parent.Children = append(parent.Children, n)
		}
		stack = append(stack, n)
	}

	for _, a := range addrs {
		addr, err := netip.ParseAddr(a.Address)
		if err != nil {
			continue
		}
		n := &Node{Kind: "address", ID: a.ID, CIDR: addr.String(), Description: a.Description, DnsName: a.DnsName,
			Mac: a.Mac, InterfaceID: a.InterfaceID, Children: []*Node{}, pfx: netip.PrefixFrom(addr, addr.BitLen())}
		if parent := deepest(roots, addr); parent != nil {
			parent.Children = append(parent.Children, n)
		} else {
			roots = append(roots, n)
		}
	}
	for _, r := range roots {
		finish(r)
	}
	sortPrefixes(roots)
	return roots
}

func contains(outer, inner netip.Prefix) bool {
	return outer.Bits() <= inner.Bits() && outer.Contains(inner.Addr()) && outer != inner
}

func deepest(nodes []*Node, addr netip.Addr) *Node {
	for _, n := range nodes {
		if n.Kind == "prefix" && n.pfx.Contains(addr) {
			if d := deepest(n.Children, addr); d != nil {
				return d
			}
			return n
		}
	}
	return nil
}

// finish sorts children and computes utilisation: child prefixes count
// with their size, addresses as one each.
func finish(n *Node) {
	sortPrefixes(n.Children)
	if n.Kind != "prefix" {
		return
	}
	size := math.Pow(2, float64(n.pfx.Addr().BitLen()-n.pfx.Bits()))
	used := n.poolSize
	for _, c := range n.Children {
		finish(c)
		used += math.Pow(2, float64(c.pfx.Addr().BitLen()-c.pfx.Bits()))
	}
	n.UsedFrac = math.Min(1, used/size)
}

func sortPrefixes(nodes []*Node) {
	sort.SliceStable(nodes, func(i, j int) bool {
		a, b := nodes[i].pfx, nodes[j].pfx
		if a.Addr().Is4() != b.Addr().Is4() {
			return a.Addr().Is4()
		}
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c < 0
		}
		return a.Bits() < b.Bits()
	})
}

// rangeSize is the number of addresses in start..end (0 if invalid),
// approximate for large IPv6 ranges.
func rangeSize(start, end string) float64 {
	s, err1 := netip.ParseAddr(start)
	e, err2 := netip.ParseAddr(end)
	if err1 != nil || err2 != nil || s.Is4() != e.Is4() || s.Compare(e) > 0 {
		return 0
	}
	u := func(a netip.Addr) float64 {
		var f float64
		for _, b := range a.AsSlice() {
			f = f*256 + float64(b)
		}
		return f
	}
	return u(e) - u(s) + 1
}

// Enclosing returns the longest prefix containing addr, if any.
func Enclosing(prefixes []models.IpamPrefix, addr netip.Addr) (netip.Prefix, bool) {
	best := netip.Prefix{}
	found := false
	for _, p := range prefixes {
		pfx, err := netip.ParsePrefix(p.Prefix)
		if err != nil {
			continue
		}
		pfx = pfx.Masked()
		if pfx.Contains(addr) && (!found || pfx.Bits() > best.Bits()) {
			best, found = pfx, true
		}
	}
	return best, found
}

// NextFree returns the first host address in prefix that is not used by an
// address, a child prefix, or the DHCP range. For IPv4, network and
// broadcast addresses are skipped (except /31, /32); for IPv6 the
// subnet-router anycast address (except /127, /128).
func NextFree(prefix models.IpamPrefix, prefixes []models.IpamPrefix, addrs []models.IpamAddress) (netip.Addr, error) {
	pfx, err := netip.ParsePrefix(prefix.Prefix)
	if err != nil {
		return netip.Addr{}, err
	}
	pfx = pfx.Masked()
	used := map[netip.Addr]bool{}
	for _, a := range addrs {
		if ip, err := netip.ParseAddr(a.Address); err == nil {
			used[ip] = true
		}
	}
	var children []netip.Prefix
	for _, p := range prefixes {
		if c, err := netip.ParsePrefix(p.Prefix); err == nil && contains(pfx, c.Masked()) {
			children = append(children, c.Masked())
		}
	}
	var rs, re netip.Addr
	if prefix.DhcpEnabled {
		rs, _ = netip.ParseAddr(prefix.DhcpRangeStart)
		re, _ = netip.ParseAddr(prefix.DhcpRangeEnd)
	}
	ip := pfx.Addr()
	if (pfx.Addr().Is4() && pfx.Bits() < 31) || (pfx.Addr().Is6() && pfx.Bits() < 127) {
		ip = ip.Next()
	}
	for i := 0; i < 1<<16 && pfx.Contains(ip); i++ {
		if pfx.Addr().Is4() && pfx.Bits() < 31 && !pfx.Contains(ip.Next()) {
			break // broadcast
		}
		free := !used[ip]
		if rs.IsValid() && re.IsValid() && ip.Compare(rs) >= 0 && ip.Compare(re) <= 0 {
			free = false
		}
		for _, c := range children {
			if c.Contains(ip) {
				free = false
				break
			}
		}
		if free {
			return ip, nil
		}
		ip = ip.Next()
	}
	return netip.Addr{}, fmt.Errorf("no free address in %s", pfx)
}
