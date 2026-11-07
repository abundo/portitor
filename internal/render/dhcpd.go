// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package render

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"sort"
	"strings"

	"github.com/abundo/portitor/internal/dhcpd"
	"github.com/abundo/portitor/internal/fwconfig"
)

// The DHCP server's config (internal/dhcpd), rendered in full:
// reservations come from A/AAAA records with a MAC (the dnsmgr2
// convention), and the subnets that share an interface are served
// together, so clients get addresses from all of them. The same process
// sends the router advertisements (Instance.RA).

// DHCP4Subnets returns the instance's IPv4 DHCP subnets, sorted by prefix.
func DHCP4Subnets(in *fwconfig.Instance) []fwconfig.DHCPSubnet {
	return dhcpSubnets(in, "ipv4")
}

// DHCP6Subnets returns the instance's IPv6 DHCP subnets, sorted by prefix.
func DHCP6Subnets(in *fwconfig.Instance) []fwconfig.DHCPSubnet {
	return dhcpSubnets(in, "ipv6")
}

// DHCPRunning says whether the instance serves DHCP: it has leases, and
// on an HA pair replicates them.
func DHCPRunning(in *fwconfig.Instance) bool {
	return len(DHCP4Subnets(in))+len(DHCP6Subnets(in)) > 0
}

// DHCPDRunning says whether the instance runs the DHCP server's process
// (portitor-dhcpd@), which also sends the router advertisements.
func DHCPDRunning(in *fwconfig.Instance) bool {
	return DHCPRunning(in) || len(in.RA) > 0
}

// subnetInterfaces are the subnets' interfaces, sorted.
func subnetInterfaces(subs []fwconfig.DHCPSubnet) []string {
	var ifs []string
	for _, s := range subs {
		ifs = appendUnique(ifs, s.Interface)
	}
	sort.Strings(ifs)
	return ifs
}

func dhcpSubnets(in *fwconfig.Instance, family string) []fwconfig.DHCPSubnet {
	var out []fwconfig.DHCPSubnet
	if !in.DHCP.Enabled {
		return nil
	}
	for _, s := range in.DHCP.Subnets {
		if fwconfig.AddrFamily(s.Prefix) == family {
			out = append(out, s)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Prefix < out[j].Prefix })
	return out
}

// dhcpReservations are the reservations of one IP version, sorted by
// address; a record repeated (same MAC and address) is one reservation.
func dhcpReservations(in *fwconfig.Instance, v6 bool) []dhcpd.Reservation {
	var out []dhcpd.Reservation
	seen := map[string]bool{}
	typ := "A"
	if v6 {
		typ = "AAAA"
	}
	for _, z := range in.DNS.Zones {
		for _, r := range z.Records {
			a, err := netip.ParseAddr(r.Value)
			if r.Type != typ || r.MAC == "" || err != nil {
				continue
			}
			mac := strings.ToLower(strings.ReplaceAll(r.MAC, "-", ":"))
			if seen[mac+" "+a.String()] {
				continue
			}
			seen[mac+" "+a.String()] = true
			host := z.Name
			if r.Name != "@" {
				host = r.Name + "." + z.Name
			}
			out = append(out, dhcpd.Reservation{MAC: mac, Addr: a, Hostname: host})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Addr.Less(out[j].Addr) })
	return out
}

// DHCPServerDUID is the DHCPv6 server's DUID: a DUID-UUID (type 4) made
// from the instance's name, the same on both hosts of an HA pair, so a
// client's renewal reaches the host that took over.
func DHCPServerDUID(in *fwconfig.Instance) string {
	h := sha256.Sum256([]byte("portitor dhcpd\x00" + in.Name))
	return "0004" + hex.EncodeToString(h[:16])
}

// serverAddr is the interface's address in the prefix: the DHCPv4
// server id.
func serverAddr(in *fwconfig.Instance, iface string, p netip.Prefix) netip.Addr {
	ifc := in.Interface(iface)
	if ifc == nil {
		return netip.Addr{}
	}
	for _, a := range ifc.Addresses {
		if pfx, err := netip.ParsePrefix(a); err == nil && p.Contains(pfx.Addr()) {
			return pfx.Addr()
		}
	}
	return netip.Addr{}
}

func parseAddrs(list []string) []netip.Addr {
	var out []netip.Addr
	for _, s := range list {
		if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, a)
		}
	}
	return out
}

func pools(s fwconfig.DHCPSubnet) []dhcpd.Range {
	start, err1 := netip.ParseAddr(s.RangeStart)
	end, err2 := netip.ParseAddr(s.RangeEnd)
	if err1 != nil || err2 != nil {
		return nil
	}
	return []dhcpd.Range{{Start: start, End: end}}
}

// DHCPDConfig is the DHCP server's config for the instance.
func DHCPDConfig(in *fwconfig.Instance) dhcpd.Config {
	c := dhcpd.Config{
		Instance:  in.Name,
		LeaseTime: in.DHCP.LeaseTime,
		Domain:    in.DHCP.DomainName,
	}
	if c.LeaseTime <= 0 {
		c.LeaseTime = 86400
	}
	res4 := dhcpReservations(in, false)
	for _, s := range DHCP4Subnets(in) {
		pfx, err := netip.ParsePrefix(s.Prefix)
		if err != nil {
			continue
		}
		pfx = pfx.Masked()
		sub := dhcpd.Subnet4{
			Interface:       s.Interface,
			Prefix:          pfx,
			ServerID:        serverAddr(in, s.Interface, pfx),
			Pools:           pools(s),
			DNS:             parseAddrs(s.DNSServers),
			V6OnlyPreferred: s.IPv6OnlyPreferred,
		}
		if gw, err := netip.ParseAddr(s.Gateway); err == nil {
			sub.Router = gw
		}
		for _, r := range res4 {
			if pfx.Contains(r.Addr) {
				sub.Reservations = append(sub.Reservations, r)
			}
		}
		c.Subnets4 = append(c.Subnets4, sub)
	}
	res6 := dhcpReservations(in, true)
	for _, s := range DHCP6Subnets(in) {
		pfx, err := netip.ParsePrefix(s.Prefix)
		if err != nil {
			continue
		}
		pfx = pfx.Masked()
		sub := dhcpd.Subnet6{
			Interface: s.Interface,
			Prefix:    pfx,
			Pools:     pools(s),
			DNS:       parseAddrs(s.DNSServers),
		}
		for _, r := range res6 {
			if pfx.Contains(r.Addr) {
				sub.Reservations = append(sub.Reservations, r)
			}
		}
		c.Subnets6 = append(c.Subnets6, sub)
	}
	if len(c.Subnets6) > 0 {
		c.DUID = DHCPServerDUID(in)
	}
	c.RA = raConfigs(in)
	return c
}

// raConfigs are the router advertisements, by interface. Delegated
// prefixes are resolved by now (Document.ResolveDelegated).
func raConfigs(in *fwconfig.Instance) []dhcpd.RAConfig {
	var out []dhcpd.RAConfig
	for _, ra := range in.RA {
		c := dhcpd.RAConfig{
			Interface: ra.Interface,
			Managed:   ra.Managed,
			Other:     ra.Other,
			RDNSS:     parseAddrs(ra.RDNSS),
			DNSSL:     ra.DNSSL,
		}
		for _, p := range ra.Prefixes {
			if pfx, err := netip.ParsePrefix(p.Prefix); err == nil {
				c.Prefixes = append(c.Prefixes, dhcpd.RAPrefix{Prefix: pfx.Masked(), Autonomous: p.Autonomous})
			}
		}
		if pfx, err := netip.ParsePrefix(ra.NAT64Prefix); err == nil {
			c.NAT64 = pfx.Masked()
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Interface < out[j].Interface })
	return out
}

// DHCPDConf renders dhcpd.json, after a comment line that LoadConfig
// skips.
func DHCPDConf(in *fwconfig.Instance) string {
	b, _ := json.MarshalIndent(DHCPDConfig(in), "", "  ")
	return "// Generated by portitor-agent, instance " + in.Name + ". Do not edit.\n" + string(b) + "\n"
}
