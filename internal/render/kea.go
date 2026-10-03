// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package render

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/abundo/portitor/internal/fwconfig"
)

// Kea's DHCPv4 and DHCPv6 configs are rendered in full, reservations
// included (from A/AAAA records with a MAC, the dnsmgr2 convention). The
// subnets that share an interface form a shared network, so Kea hands out
// addresses from all of them; dnsmgr2 cannot write one. DHCPv6 subnets and
// shared networks name their interface, which Kea6 needs to serve directly
// connected clients on more than one subnet. DHCPv4 ones need not, as
// before: Kea4 picks the subnet by the receiving interface's address, and
// the shared network adds its siblings.

type keaSubnet struct {
	ID           int              `json:"id"`
	Subnet       string           `json:"subnet"`
	Interface    string           `json:"interface,omitempty"`
	Pools        []keaPool        `json:"pools,omitempty"`
	OptionData   []keaOption      `json:"option-data,omitempty"`
	Reservations []keaReservation `json:"reservations,omitempty"`
}

type keaPool struct {
	Pool string `json:"pool"`
}

type keaOption struct {
	Name string `json:"name"`
	Data string `json:"data"`
}

// keaReservation holds IPAddress for DHCPv4, IPAddresses for DHCPv6.
type keaReservation struct {
	HWAddress   string   `json:"hw-address"`
	IPAddress   string   `json:"ip-address,omitempty"`
	IPAddresses []string `json:"ip-addresses,omitempty"`
	Hostname    string   `json:"hostname,omitempty"`
}

// keaSharedNetwork groups the subnets of one interface, and is named
// after it; its subnets leave the interface to it.
type keaSharedNetwork struct {
	Name      string      `json:"name"`
	Interface string      `json:"interface,omitempty"`
	Subnet4   []keaSubnet `json:"subnet4,omitempty"`
	Subnet6   []keaSubnet `json:"subnet6,omitempty"`
}

// DHCP4Subnets returns the instance's IPv4 DHCP subnets, sorted by prefix.
func DHCP4Subnets(in *fwconfig.Instance) []fwconfig.DHCPSubnet {
	return dhcpSubnets(in, "ipv4")
}

// DHCP6Subnets returns the instance's IPv6 DHCP subnets, sorted by prefix.
func DHCP6Subnets(in *fwconfig.Instance) []fwconfig.DHCPSubnet {
	return dhcpSubnets(in, "ipv6")
}

// dhcpSubnets sorts by the prefix as text, as dnsmgr2 did for DHCPv4, so
// subnet ids (their position) and with them the leases' subnets stay put.
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

func subnetInterfaces(subs []fwconfig.DHCPSubnet) []string {
	ifs := []string{} // never nil: Kea rejects "interfaces": null
	for _, s := range subs {
		ifs = appendUnique(ifs, s.Interface)
	}
	sort.Strings(ifs)
	return ifs
}

// keaReservations returns the reservations of one IP version with their
// addresses, sorted by address; a record repeated (same MAC and address)
// is one reservation.
func keaReservations(in *fwconfig.Instance, v6 bool) ([]netip.Addr, []keaReservation) {
	type res struct {
		addr netip.Addr
		r    keaReservation
	}
	var list []res
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
			kr := keaReservation{HWAddress: mac, Hostname: host}
			if v6 {
				kr.IPAddresses = []string{a.String()}
			} else {
				kr.IPAddress = a.String()
			}
			list = append(list, res{a, kr})
		}
	}
	sort.SliceStable(list, func(i, j int) bool { return list[i].addr.Less(list[j].addr) })
	addrs := make([]netip.Addr, len(list))
	out := make([]keaReservation, len(list))
	for i, r := range list {
		addrs[i], out[i] = r.addr, r.r
	}
	return addrs, out
}

// keaSubnets renders the subnets of one IP version: those alone on their
// interface as a subnet list, those sharing one in a shared network named
// after the interface. Ids follow the sorted prefixes either way.
func keaSubnets(in *fwconfig.Instance, v6 bool) ([]keaSubnet, []keaSharedNetwork) {
	subs := DHCP4Subnets(in)
	if v6 {
		subs = DHCP6Subnets(in)
	}
	perIface := map[string]int{}
	for _, s := range subs {
		perIface[s.Interface]++
	}
	resAddrs, res := keaReservations(in, v6)

	subnets := []keaSubnet{}
	var shared []keaSharedNetwork
	sharedIndex := map[string]int{}
	for i, s := range subs {
		pfx, err := netip.ParsePrefix(s.Prefix)
		if err != nil {
			continue
		}
		pfx = pfx.Masked()
		sub := keaSubnet{ID: i + 1, Subnet: pfx.String()}
		if s.RangeStart != "" {
			sub.Pools = []keaPool{{Pool: s.RangeStart + " - " + s.RangeEnd}}
		}
		if v6 {
			if len(s.DNSServers) > 0 {
				sub.OptionData = append(sub.OptionData, keaOption{Name: "dns-servers", Data: strings.Join(s.DNSServers, ", ")})
			}
			if in.DHCP.DomainName != "" {
				sub.OptionData = append(sub.OptionData, keaOption{Name: "domain-search", Data: in.DHCP.DomainName})
			}
		} else {
			if s.Gateway != "" {
				sub.OptionData = append(sub.OptionData, keaOption{Name: "routers", Data: s.Gateway})
			}
			if len(s.DNSServers) > 0 {
				sub.OptionData = append(sub.OptionData, keaOption{Name: "domain-name-servers", Data: strings.Join(s.DNSServers, ", ")})
			}
			if in.DHCP.DomainName != "" {
				sub.OptionData = append(sub.OptionData, keaOption{Name: "domain-name", Data: in.DHCP.DomainName})
			}
		}
		for j, a := range resAddrs {
			if pfx.Contains(a) {
				sub.Reservations = append(sub.Reservations, res[j])
			}
		}
		iface := ""
		if v6 {
			iface = s.Interface
		}
		if perIface[s.Interface] == 1 {
			sub.Interface = iface
			subnets = append(subnets, sub)
			continue
		}
		k, ok := sharedIndex[s.Interface]
		if !ok {
			k = len(shared)
			sharedIndex[s.Interface] = k
			shared = append(shared, keaSharedNetwork{Name: s.Interface, Interface: iface})
		}
		if v6 {
			shared[k].Subnet6 = append(shared[k].Subnet6, sub)
		} else {
			shared[k].Subnet4 = append(shared[k].Subnet4, sub)
		}
	}
	sort.SliceStable(shared, func(i, j int) bool { return shared[i].Name < shared[j].Name })
	return subnets, shared
}

// keaSubnetsJSON is the subnet list, and the shared networks when there
// are any, as members of the Dhcp4/Dhcp6 object.
func keaSubnetsJSON(in *fwconfig.Instance, v6 bool) string {
	subnets, shared := keaSubnets(in, v6)
	if subnets == nil {
		subnets = []keaSubnet{} // Kea rejects null
	}
	key := "subnet4"
	if v6 {
		key = "subnet6"
	}
	subJSON, _ := json.MarshalIndent(subnets, "    ", "  ")
	out := fmt.Sprintf("%q: %s,", key, subJSON)
	if len(shared) > 0 {
		sharedJSON, _ := json.MarshalIndent(shared, "    ", "  ")
		out += fmt.Sprintf("\n    \"shared-networks\": %s,", sharedJSON)
	}
	return out
}

// KeaDhcp4Conf renders Kea's DHCPv4 config.
func KeaDhcp4Conf(in *fwconfig.Instance, p Paths) string {
	lease := in.DHCP.LeaseTime
	if lease <= 0 {
		lease = 86400
	}
	ifJSON, _ := json.Marshal(subnetInterfaces(DHCP4Subnets(in)))
	b := &strings.Builder{}
	fmt.Fprintf(b, "// Generated by portitor-agent, instance %s. Do not edit.\n", in.Name)
	fmt.Fprintf(b, `{
  "Dhcp4": {
    "interfaces-config": { "interfaces": %s },
    "control-socket": { "socket-type": "unix", "socket-name": %q },
    "lease-database": { "type": "memfile", "persist": true, "lfc-interval": 3600, "name": %q },
    "valid-lifetime": %d,
    "renew-timer": %d,
    "rebind-timer": %d,
    %s
    "loggers": [ { "name": "kea-dhcp4", "output-options": [ { "output": "stdout" } ], "severity": "INFO" } ]
  }
}
`, ifJSON,
		p.Files(in).Kea4Socket,
		p.Files(in).Kea4Lease,
		lease, lease/2, lease*7/8,
		keaSubnetsJSON(in, false))
	return b.String()
}

// KeaDhcp6Conf renders Kea's DHCPv6 config.
func KeaDhcp6Conf(in *fwconfig.Instance, p Paths) string {
	lease := in.DHCP.LeaseTime
	if lease <= 0 {
		lease = 86400
	}
	ifJSON, _ := json.Marshal(subnetInterfaces(DHCP6Subnets(in)))
	b := &strings.Builder{}
	fmt.Fprintf(b, "// Generated by portitor-agent, instance %s. Do not edit.\n", in.Name)
	fmt.Fprintf(b, `{
  "Dhcp6": {
    "interfaces-config": { "interfaces": %s },
    "control-socket": { "socket-type": "unix", "socket-name": %q },
    "lease-database": { "type": "memfile", "persist": true, "lfc-interval": 3600, "name": %q },
    "preferred-lifetime": %d,
    "valid-lifetime": %d,
    "renew-timer": %d,
    "rebind-timer": %d,
    %s
    "loggers": [ { "name": "kea-dhcp6", "output-options": [ { "output": "stdout" } ], "severity": "INFO" } ]
  }
}
`, ifJSON,
		p.Files(in).Kea6Socket,
		p.Files(in).Kea6Lease,
		lease*3/4, lease, lease/2, lease*4/5,
		keaSubnetsJSON(in, true))
	return b.String()
}
