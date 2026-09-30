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
	"slices"
	"sort"
	"strings"

	"github.com/abundo/portitor/models"
)

// Node is a prefix or address of the tree. ID is its IpamPrefix or
// IpamAddress id, or 0 when it is there only because an interface has the
// address (Auto): a prefix of an interface address, or the address itself;
// or because a DNS zone has an A/AAAA record for it (Auto, ZoneID set).
// InterfaceID is the interface an address is configured on, or a prefix
// of one of its addresses (the first such interface).
type Node struct {
	Kind        string  `json:"kind"` // prefix | address
	ID          uint    `json:"id"`
	Auto        bool    `json:"auto,omitempty"`
	CIDR        string  `json:"cidr"` // prefix, or address without length
	Description string  `json:"description,omitempty"`
	DnsName     string  `json:"dns_name,omitempty"`
	Mac         string  `json:"mac,omitempty"`
	InterfaceID *uint   `json:"interface_id,omitempty"`
	ZoneID      *uint   `json:"zone_id,omitempty"` // zone of the first A/AAAA record for the address
	DhcpEnabled bool    `json:"dhcp_enabled,omitempty"`
	RaEnabled   bool    `json:"ra_enabled,omitempty"`
	RaSlaac     bool    `json:"ra_slaac,omitempty"`
	DhcpRange   string  `json:"dhcp_range,omitempty"`
	UsedFrac    float64 `json:"used_frac"`
	Children    []*Node `json:"children"`

	pfx      netip.Prefix
	poolSize float64 // DHCP pool addresses, counted as used
}

// RecordAddress is the address of an A or AAAA record of a DNS zone.
type RecordAddress struct {
	ZoneID      uint
	Name        string // fully qualified, without the trailing dot
	Address     string
	Mac         string
	Description string
}

// Tree nests an instance's prefixes and addresses, with its interfaces'
// addresses and their prefixes, and the addresses of its A/AAAA records
// that fall in a prefix. Other addresses that fall in no prefix are
// returned at the top level.
func Tree(prefixes []models.IpamPrefix, addrs []models.IpamAddress, ifaces []models.Interface, records []RecordAddress) []*Node {
	var nodes []*Node
	stored := map[netip.Prefix]*Node{}
	for _, p := range prefixes {
		pfx, err := netip.ParsePrefix(p.Prefix)
		if err != nil {
			continue
		}
		n := &Node{Kind: "prefix", ID: p.ID, CIDR: pfx.Masked().String(), Description: p.Description,
			DhcpEnabled: p.DhcpEnabled, RaEnabled: p.RaEnabled, RaSlaac: p.RaSlaac, Children: []*Node{}, pfx: pfx.Masked()}
		if p.DhcpEnabled && p.DhcpRangeStart != "" {
			n.DhcpRange = p.DhcpRangeStart + " - " + p.DhcpRangeEnd
			n.poolSize = rangeSize(p.DhcpRangeStart, p.DhcpRangeEnd)
		}
		nodes = append(nodes, n)
		stored[n.pfx] = n
	}
	onIface := map[netip.Addr]uint{}
	for _, ia := range InterfaceAddresses(ifaces) {
		onIface[ia.Prefix.Addr()] = ia.InterfaceID
		pfx := ia.Prefix.Masked()
		id := ia.InterfaceID
		if n := stored[pfx]; n != nil {
			if n.InterfaceID == nil {
				n.InterfaceID = &id
			}
			continue
		}
		if pfx.IsSingleIP() {
			continue
		}
		n := &Node{Kind: "prefix", Auto: true, CIDR: pfx.String(), InterfaceID: &id, Children: []*Node{}, pfx: pfx}
		nodes = append(nodes, n)
		stored[pfx] = n
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

	var addrNodes []*Node
	for _, a := range addrs {
		addr, err := netip.ParseAddr(a.Address)
		if err != nil {
			continue
		}
		n := &Node{Kind: "address", ID: a.ID, CIDR: addr.String(), Description: a.Description, DnsName: a.DnsName,
			Mac: a.Mac, Children: []*Node{}, pfx: netip.PrefixFrom(addr, addr.BitLen())}
		if id, ok := onIface[addr]; ok {
			n.InterfaceID = &id
			delete(onIface, addr)
		}
		addrNodes = append(addrNodes, n)
	}
	for addr, id := range onIface {
		addrNodes = append(addrNodes, &Node{Kind: "address", Auto: true, CIDR: addr.String(), InterfaceID: &id,
			Children: []*Node{}, pfx: netip.PrefixFrom(addr, addr.BitLen())})
	}
	byAddr := map[netip.Addr]*Node{}
	for _, n := range addrNodes {
		byAddr[n.pfx.Addr()] = n
		if parent := deepest(roots, n.pfx.Addr()); parent != nil {
			parent.Children = append(parent.Children, n)
		} else {
			roots = append(roots, n)
		}
	}
	// A record's address joins the node the address already has, or gets
	// its own under the deepest prefix that holds it.
	for _, r := range records {
		addr, err := netip.ParseAddr(r.Address)
		if err != nil {
			continue
		}
		addr = addr.Unmap()
		n := byAddr[addr]
		if n == nil {
			parent := deepest(roots, addr)
			if parent == nil {
				continue
			}
			n = &Node{Kind: "address", Auto: true, CIDR: addr.String(), Children: []*Node{},
				pfx: netip.PrefixFrom(addr, addr.BitLen())}
			parent.Children = append(parent.Children, n)
			byAddr[addr] = n
		}
		if n.ZoneID == nil {
			id := r.ZoneID
			n.ZoneID = &id
		}
		if !slices.Contains(strings.Split(n.DnsName, ", "), r.Name) {
			n.DnsName = strings.TrimPrefix(n.DnsName+", "+r.Name, ", ")
		}
		if n.Mac == "" {
			n.Mac = r.Mac
		}
		if n.Description == "" {
			n.Description = r.Description
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

// IfaceAddress is an address configured on an interface.
type IfaceAddress struct {
	InterfaceID uint
	Prefix      netip.Prefix // the address with its prefix length
}

// InterfaceAddresses returns the valid addresses of ifaces.
func InterfaceAddresses(ifaces []models.Interface) []IfaceAddress {
	var out []IfaceAddress
	for _, i := range ifaces {
		for _, a := range i.Addresses {
			if p, err := netip.ParsePrefix(a); err == nil {
				out = append(out, IfaceAddress{i.ID, p})
			}
		}
	}
	return out
}

// Used returns addrs with the interfaces' addresses added, as NextFree
// takes them: addresses that are taken.
func Used(addrs []models.IpamAddress, ifaces []models.Interface) []models.IpamAddress {
	out := append([]models.IpamAddress{}, addrs...)
	for _, ia := range InterfaceAddresses(ifaces) {
		out = append(out, models.IpamAddress{Address: ia.Prefix.Addr().String()})
	}
	return out
}

// NextFree returns the first host address in prefix that is not used by an
// address, a child prefix, or the DHCP range. For IPv4, network and
// broadcast addresses are skipped (except /31, /32); for IPv6 the
// subnet-router anycast address (except /127, /128).
func NextFree(prefix models.IpamPrefix, prefixes []models.IpamPrefix, addrs []models.IpamAddress) (netip.Addr, error) {
	ips, err := NextFreeCommon([]models.IpamPrefix{prefix}, prefixes, addrs)
	if err != nil {
		return netip.Addr{}, err
	}
	return ips[0], nil
}

// NextFreeCommon is NextFree over several prefixes at once: it picks the
// lowest host number that is free in every one of them, so a dual-stack
// peer gets e.g. 10.99.0.2 and fd99::2. It returns one address per prefix.
func NextFreeCommon(targets []models.IpamPrefix, prefixes []models.IpamPrefix, addrs []models.IpamAddress) ([]netip.Addr, error) {
	used := map[netip.Addr]bool{}
	for _, a := range addrs {
		if ip, err := netip.ParseAddr(a.Address); err == nil {
			used[ip] = true
		}
	}
	type target struct {
		pfx      netip.Prefix
		children []netip.Prefix
		rs, re   netip.Addr
	}
	var ts []target
	var names []string
	for _, p := range targets {
		pfx, err := netip.ParsePrefix(p.Prefix)
		if err != nil {
			return nil, err
		}
		t := target{pfx: pfx.Masked()}
		for _, q := range prefixes {
			if c, err := netip.ParsePrefix(q.Prefix); err == nil && contains(t.pfx, c.Masked()) {
				t.children = append(t.children, c.Masked())
			}
		}
		if p.DhcpEnabled {
			t.rs, _ = netip.ParseAddr(p.DhcpRangeStart)
			t.re, _ = netip.ParseAddr(p.DhcpRangeEnd)
		}
		ts = append(ts, t)
		names = append(names, t.pfx.String())
	}
	if len(ts) == 0 {
		return nil, fmt.Errorf("no prefix")
	}
	// free reports whether host number n of t is a usable, unused address;
	// ok is false once n is past the end of the prefix.
	free := func(t target, n int) (ip netip.Addr, isFree, ok bool) {
		ip = addHost(t.pfx.Addr(), n)
		if !ip.IsValid() || !t.pfx.Contains(ip) {
			return ip, false, false
		}
		small := (ip.Is4() && t.pfx.Bits() >= 31) || (ip.Is6() && t.pfx.Bits() >= 127)
		if !small && (n == 0 || (ip.Is4() && !t.pfx.Contains(ip.Next()))) {
			return ip, false, true // network/anycast or broadcast
		}
		if used[ip] || (t.rs.IsValid() && t.re.IsValid() && ip.Compare(t.rs) >= 0 && ip.Compare(t.re) <= 0) {
			return ip, false, true
		}
		for _, c := range t.children {
			if c.Contains(ip) {
				return ip, false, true
			}
		}
		return ip, true, true
	}
	for n := 0; n < 1<<16; n++ {
		out := make([]netip.Addr, len(ts))
		all := true
		for i, t := range ts {
			ip, isFree, ok := free(t, n)
			if !ok {
				return nil, fmt.Errorf("no free address in %s", strings.Join(names, ", "))
			}
			out[i] = ip
			all = all && isFree
		}
		if all {
			return out, nil
		}
	}
	return nil, fmt.Errorf("no free address in %s", strings.Join(names, ", "))
}

// addHost returns a+n, or the zero Addr on overflow.
func addHost(a netip.Addr, n int) netip.Addr {
	b := a.AsSlice()
	carry := n
	for i := len(b) - 1; i >= 0 && carry > 0; i-- {
		v := int(b[i]) + carry
		b[i], carry = byte(v), v>>8
	}
	if carry > 0 {
		return netip.Addr{}
	}
	out, _ := netip.AddrFromSlice(b)
	return out
}
