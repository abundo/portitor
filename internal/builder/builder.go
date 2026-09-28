// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package builder turns portitor-web's database into the fwconfig.Document
// that portitor-agent applies. It resolves references (instance ids to names,
// IPAM addresses to interface CIDRs, DHCP prefixes to serving interfaces)
// and reports what it cannot resolve; fwconfig.Validate does the rest.
package builder

import (
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"

	"gorm.io/gorm"

	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/ipam"
	"github.com/abundo/portitor/internal/netobj"
	"github.com/abundo/portitor/models"
)

type data struct {
	instances  []models.Instance
	ifaceZones []models.InterfaceZone
	interfaces []models.Interface
	peers      []models.WgPeer
	links      []models.Link
	routes     []models.Route
	rules      []models.Rule
	nat        []models.NatRule
	prefixes   []models.IpamPrefix
	addrs      []models.IpamAddress
	dnsZones   []models.DnsZone
	records    []models.DnsRecord
	objects    []models.AddressObject
	soas       []models.DnsSoaTemplate
	policies   []models.DnsDnssecPolicy
	templates  []models.DnsTemplate
	dyndns     []models.DyndnsClient
	dyndnsRecs []models.DyndnsRecord
}

func load(db *gorm.DB) (*data, error) {
	d := &data{}
	for _, q := range []struct {
		dst   any
		order string
	}{
		{&d.instances, "is_default desc, name"},
		{&d.ifaceZones, "name"},
		{&d.interfaces, "name"},
		{&d.peers, "name"},
		{&d.links, "name"},
		{&d.routes, "id"},
		{&d.rules, "position, id"},
		{&d.nat, "position, id"},
		{&d.prefixes, "prefix"},
		{&d.addrs, "address"},
		{&d.dnsZones, "name"},
		{&d.records, "zone_id, rank, id"},
		{&d.objects, "name"},
		{&d.soas, "name"},
		{&d.policies, "name"},
		{&d.templates, "name"},
		{&d.dyndns, "name"},
		{&d.dyndnsRecs, "client_id, id"},
	} {
		if err := db.Order(q.order).Find(q.dst).Error; err != nil {
			return nil, err
		}
	}
	return d, nil
}

// Build returns the document for generation. Problems found while
// resolving the database, and by fwconfig.Validate, come back as a
// *fwconfig.ValidationError alongside the (possibly incomplete) document.
func Build(db *gorm.DB, generation int64) (*fwconfig.Document, error) {
	d, err := load(db)
	if err != nil {
		return nil, err
	}
	var problems []string
	addf := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }

	ifaceByID := map[uint]models.Interface{}
	for _, i := range d.interfaces {
		ifaceByID[i.ID] = i
	}
	instName := map[uint]string{}
	for _, in := range d.instances {
		instName[in.ID] = in.Name
	}
	// Named hosts/prefixes are expanded here; the agent sees addresses only.
	objs := netobj.New(d.objects)
	failed := false // set by expand; callers drop what it failed on
	expand := func(where string, fn func([]string) ([]string, error), list []string) []string {
		out, err := fn(list)
		if err != nil {
			addf("%s: %v", where, err)
			failed = true
		}
		return out
	}

	doc := &fwconfig.Document{Version: fwconfig.Version, Generation: generation, Instances: []fwconfig.Instance{}, Links: []fwconfig.Link{}}

	for _, mi := range d.instances {
		in := fwconfig.Instance{
			Name:    mi.Name,
			Default: mi.IsDefault,
			Rules:   []fwconfig.Rule{},
			NAT:     []fwconfig.NATRule{},
			Routes:  []fwconfig.Route{},
		}
		var prefixes []models.IpamPrefix
		for _, p := range d.prefixes {
			if p.InstanceID == mi.ID {
				prefixes = append(prefixes, p)
			}
		}
		var addrs []models.IpamAddress
		for _, a := range d.addrs {
			if a.InstanceID == mi.ID {
				addrs = append(addrs, a)
			}
		}

		in.InterfaceZones = []fwconfig.InterfaceZone{}
		for _, z := range d.ifaceZones {
			if z.InstanceID == mi.ID {
				in.InterfaceZones = append(in.InterfaceZones, fwconfig.InterfaceZone{Name: z.Name, Interfaces: append([]string{}, z.Interfaces...)})
			}
		}

		// Interfaces with their addresses from IPAM.
		for _, mif := range d.interfaces {
			if mif.InstanceID != mi.ID {
				continue
			}
			ifc := fwconfig.Interface{
				Name:         mif.Name,
				Kind:         mif.Kind,
				Description:  mif.Description,
				Enabled:      mif.Enabled,
				Parent:       mif.Parent,
				VLANID:       mif.VlanID,
				Members:      []string(mif.Members),
				MTU:          mif.Mtu,
				IPv4Mode:     mif.Ipv4Mode,
				IPv6AcceptRA: mif.Ipv6AcceptRA,
			}
			for _, a := range addrs {
				if a.InterfaceID == nil || *a.InterfaceID != mif.ID {
					continue
				}
				ip, err := netip.ParseAddr(a.Address)
				if err != nil {
					addf("instance %s: IPAM address %q is invalid", mi.Name, a.Address)
					continue
				}
				enc, ok := ipam.Enclosing(prefixes, ip)
				if !ok {
					addf("instance %s: address %s on %s is not inside any IPAM prefix (the prefix gives its length)", mi.Name, ip, mif.Name)
					continue
				}
				ifc.Addresses = append(ifc.Addresses, netip.PrefixFrom(ip, enc.Bits()).String())
			}
			if mif.Kind == fwconfig.KindWireGuard {
				wg := &fwconfig.WireGuard{PrivateKey: mif.WgPrivateKey, ListenPort: mif.WgListenPort, Peers: []fwconfig.WGPeer{}}
				for _, p := range d.peers {
					if p.InterfaceID != mif.ID || !p.Enabled {
						continue
					}
					wg.Peers = append(wg.Peers, fwconfig.WGPeer{
						Name:         p.Name,
						PublicKey:    p.PublicKey,
						PresharedKey: p.PresharedKey,
						Endpoint:     p.Endpoint,
						AllowedIPs:   []string(p.AllowedIPs),
						Keepalive:    p.Keepalive,
					})
				}
				for i := range wg.Peers {
					wg.Peers[i].AllowedIPs = expand(fmt.Sprintf("instance %s: %s peer %s: allowed IPs", mi.Name, mif.Name, wg.Peers[i].Name), objs.Prefixes, wg.Peers[i].AllowedIPs)
				}
				ifc.WireGuard = wg
			}
			in.Interfaces = append(in.Interfaces, ifc)
		}

		for _, r := range d.rules {
			if r.InstanceID != mi.ID || !r.Enabled {
				continue
			}
			if r.Kind == models.RuleKindComment {
				in.Rules = append(in.Rules, fwconfig.Rule{Chain: r.Chain, Kind: fwconfig.RuleKindComment, Description: r.Description})
				continue
			}
			where := fmt.Sprintf("instance %s: rule %d", mi.Name, len(in.Rules)+1)
			failed = false
			rule := fwconfig.Rule{
				Chain:         r.Chain,
				InInterfaces:  []string(r.InInterfaces),
				OutInterfaces: []string(r.OutInterfaces),
				Family:        r.Family,
				Protocol:      r.Protocol,
				SrcAddrs:      expand(where+": source", objs.Expand, r.SrcAddrs),
				DstAddrs:      expand(where+": destination", objs.Expand, r.DstAddrs),
				DstPorts:      r.DstPorts,
				Action:        r.Action,
				Log:           r.Log,
				Description:   r.Description,
			}
			// An unresolved name must not leave an emptier (wider) match.
			if !failed {
				in.Rules = append(in.Rules, rule)
			}
		}
		for _, n := range d.nat {
			if n.InstanceID != mi.ID || !n.Enabled {
				continue
			}
			where := fmt.Sprintf("instance %s: nat rule %d", mi.Name, len(in.NAT)+1)
			failed = false
			rule := fwconfig.NATRule{
				Kind:          n.Kind,
				InInterfaces:  []string(n.InInterfaces),
				OutInterfaces: []string(n.OutInterfaces),
				Protocol:      n.Protocol,
				SrcAddrs:      expand(where+": source", objs.Expand, n.SrcAddrs),
				DstAddrs:      expand(where+": destination", objs.Expand, n.DstAddrs),
				DstPorts:      n.DstPorts,
				ToPort:        n.ToPort,
				Description:   n.Description,
			}
			if failed {
				continue
			}
			if n.Kind == fwconfig.NATMasquerade {
				in.NAT = append(in.NAT, rule)
				continue
			}
			// A target host with an IPv4 and an IPv6 address becomes one
			// rule per IP version.
			targets, err := objs.Host(n.ToAddr)
			if err != nil {
				addf("%s: target: %v", where, err)
			}
			for _, t := range targets {
				r := rule
				r.ToAddr = t
				if len(targets) > 1 && len(fwconfig.MatchFamilies(fwconfig.AddrFamily(t), r.Protocol, r.SrcAddrs, r.DstAddrs)) == 0 {
					continue // the match addresses leave out this version
				}
				in.NAT = append(in.NAT, r)
			}
		}
		for _, r := range d.routes {
			if r.InstanceID != mi.ID || !r.Enabled {
				continue
			}
			where := fmt.Sprintf("instance %s: route %s", mi.Name, r.Destination)
			dests := []string{r.Destination}
			if r.Destination != "default" {
				dests = expand(where+": destination", objs.Prefixes, dests)
			}
			var gateways []string
			if r.Gateway != "" {
				var err error
				if gateways, err = objs.Host(r.Gateway); err != nil {
					addf("%s: gateway: %v", where, err)
					continue
				}
			}
			// Named destinations and gateways may cover both IP versions:
			// one route per destination, via the gateway of its version.
			for _, dst := range dests {
				fam := fwconfig.AddrFamily(dst)
				route := fwconfig.Route{Destination: dst, Metric: r.Metric}
				if r.InterfaceID != nil {
					route.Interface = ifaceByID[*r.InterfaceID].Name
				}
				if len(gateways) == 0 {
					in.Routes = append(in.Routes, route)
					continue
				}
				matched := false
				for _, gw := range gateways {
					if dst == "default" || fam == "" || fwconfig.AddrFamily(gw) == fam {
						route.Gateway = gw
						in.Routes = append(in.Routes, route)
						matched = true
					}
				}
				if !matched {
					addf("%s: gateway %s has no address of the same IP version as %s", where, r.Gateway, dst)
				}
			}
		}

		// DNS: zones, records from the zone and from IPAM names.
		in.DNS = fwconfig.DNSServer{
			Enabled:         mi.DnsEnabled,
			Forwarders:      expand("instance "+mi.Name+": dns forwarders", objs.Hosts, mi.DnsForwarders),
			ForwardFromDHCP: mi.DnsForwardFromDhcp,
			ForwardMode:     mi.DnsForwardMode,
			AllowRecursion:  expand("instance "+mi.Name+": dns allow recursion", objs.Prefixes, mi.DnsAllowRecursion),
			Zones:           []fwconfig.DNSZone{},
		}
		// interface -> its first IPv4 and first global IPv6 address, which
		// DHCP and router advertisements hand out as the DNS server.
		listenAddr := map[string]map[bool]string{}
		for _, ifc := range in.Interfaces {
			for _, mif := range d.interfaces {
				if mif.InstanceID == mi.ID && mif.Name == ifc.Name && mif.DnsListen {
					in.DNS.ListenInterfaces = append(in.DNS.ListenInterfaces, ifc.Name)
				}
			}
			listenAddr[ifc.Name] = map[bool]string{}
			for _, a := range ifc.Addresses {
				if p, err := netip.ParsePrefix(a); err == nil && !p.Addr().IsLinkLocalUnicast() {
					if _, ok := listenAddr[ifc.Name][p.Addr().Is4()]; !ok {
						listenAddr[ifc.Name][p.Addr().Is4()] = p.Addr().String()
					}
				}
			}
		}
		var forwardZones []*fwconfig.DNSZone
		for _, z := range d.dnsZones {
			if z.InstanceID != mi.ID {
				continue
			}
			dz := fwconfig.DNSZone{Name: z.Name, Type: z.Type}
			if z.DnsTemplateID != nil {
				dz.Template = d.addDNSTemplate(&in.DNS, *z.DnsTemplateID)
				if dz.Template == "" {
					addf("instance %s: dns zone %s: its DNS template no longer exists", mi.Name, z.Name)
				}
			}
			domain := ""
			for _, r := range d.records {
				if r.ZoneID != z.ID {
					continue
				}
				switch r.Type {
				case models.DnsRecordComment:
				case models.DnsRecordDomain:
					domain = r.Name
				default:
					dz.Records = append(dz.Records, fwconfig.DNSRecord{Name: RecordName(domain, r.Name), TTL: r.Ttl, Type: r.Type, Value: r.Value, MAC: r.Mac})
				}
			}
			in.DNS.Zones = append(in.DNS.Zones, dz)
		}
		for i := range in.DNS.Zones {
			if in.DNS.Zones[i].Type == fwconfig.ZoneForward {
				forwardZones = append(forwardZones, &in.DNS.Zones[i])
			}
		}
		for _, a := range addrs {
			if a.DnsName == "" {
				if a.Mac != "" {
					addf("instance %s: address %s has a MAC but no DNS name; DHCP reservations are made from DNS records", mi.Name, a.Address)
				}
				continue
			}
			ip, err := netip.ParseAddr(a.Address)
			if err != nil {
				continue
			}
			zone, label := zoneFor(forwardZones, a.DnsName)
			if zone == nil {
				addf("instance %s: DNS name %s (address %s) is not inside any forward zone", mi.Name, a.DnsName, a.Address)
				continue
			}
			typ := "A"
			if ip.Is6() {
				typ = "AAAA"
			}
			zone.Records = append(zone.Records, fwconfig.DNSRecord{Name: label, Type: typ, Value: ip.String(), MAC: a.Mac})
		}
		if !mi.DnsEnabled {
			for _, z := range in.DNS.Zones {
				for _, r := range z.Records {
					// DHCPv4 reservations go through dnsmgr2 and BIND's
					// records; DHCPv6 ones are rendered directly.
					if r.MAC != "" && r.Type == "A" {
						addf("instance %s: DHCP reservation for %s needs the DNS server enabled (reservations are generated from DNS records)", mi.Name, r.Value)
					}
				}
			}
		}

		// DHCP and IPv6 router advertisements: IPAM prefixes with DHCP or
		// RA on, served on the interface that has an address inside the
		// prefix (with the prefix's length).
		in.DHCP = fwconfig.DHCPServer{Enabled: mi.DhcpEnabled, DomainName: mi.DhcpDomainName, LeaseTime: mi.DhcpLeaseTime, Subnets: []fwconfig.DHCPSubnet{}}
		raIndex := map[string]int{}
		for _, p := range prefixes {
			dhcp := p.DhcpEnabled && mi.DhcpEnabled
			if !dhcp && !p.RaEnabled {
				continue
			}
			pfx, err := netip.ParsePrefix(p.Prefix)
			if err != nil {
				continue
			}
			pfx = pfx.Masked()
			var serveOn, gw string
			for _, ifc := range in.Interfaces {
				for _, a := range ifc.Addresses {
					if ap, err := netip.ParsePrefix(a); err == nil && pfx.Contains(ap.Addr()) && ap.Bits() == pfx.Bits() {
						serveOn, gw = ifc.Name, ap.Addr().String()
						break
					}
				}
				if serveOn != "" {
					break
				}
			}
			if serveOn == "" {
				what := "DHCP"
				if !dhcp {
					what = "router advertisements"
				}
				addf("instance %s: %s for prefix %s: no interface has an address in it", mi.Name, what, pfx)
				continue
			}
			var dns []string
			for _, a := range expand(fmt.Sprintf("instance %s: prefix %s: DNS servers", mi.Name, pfx), objs.Hosts, p.DhcpDnsServers) {
				if fwconfig.AddrFamily(a) == fwconfig.AddrFamily(pfx.String()) {
					dns = append(dns, a)
				}
			}
			if len(dns) == 0 && mi.DnsEnabled && contains(in.DNS.ListenInterfaces, serveOn) {
				if a := listenAddr[serveOn][pfx.Addr().Is4()]; a != "" {
					dns = []string{a}
				}
			}
			if dhcp {
				sub := fwconfig.DHCPSubnet{
					Prefix:     pfx.String(),
					Interface:  serveOn,
					RangeStart: p.DhcpRangeStart,
					RangeEnd:   p.DhcpRangeEnd,
					DNSServers: dns,
				}
				if pfx.Addr().Is4() {
					sub.Gateway = p.DhcpGateway
					if sub.Gateway == "" {
						sub.Gateway = gw
					}
				}
				in.DHCP.Subnets = append(in.DHCP.Subnets, sub)
			}
			if p.RaEnabled && pfx.Addr().Is6() {
				i, ok := raIndex[serveOn]
				if !ok {
					i = len(in.RA)
					raIndex[serveOn] = i
					in.RA = append(in.RA, fwconfig.RAInterface{Interface: serveOn})
				}
				ra := &in.RA[i]
				ra.Prefixes = append(ra.Prefixes, fwconfig.RAPrefix{Prefix: pfx.String(), Autonomous: p.RaSlaac})
				if dhcp {
					ra.Managed, ra.Other = true, true
				}
				for _, a := range dns {
					if !contains(ra.RDNSS, a) {
						ra.RDNSS = append(ra.RDNSS, a)
					}
				}
				if mi.DhcpDomainName != "" && !contains(ra.DNSSL, mi.DhcpDomainName) {
					ra.DNSSL = append(ra.DNSSL, mi.DhcpDomainName)
				}
			}
		}

		for _, c := range d.dyndns {
			if c.InstanceID != mi.ID || !c.Enabled {
				continue
			}
			ifc, ok := ifaceByID[c.InterfaceID]
			if !ok || ifc.InstanceID != mi.ID {
				addf("instance %s: dynamic DNS %s: its interface is not in this instance", mi.Name, c.Name)
				continue
			}
			var recs []models.DyndnsRecord
			for _, r := range d.dyndnsRecs {
				if r.ClientID == c.ID {
					recs = append(recs, r)
				}
			}
			in.DynDNS = append(in.DynDNS, DynDNS(&c, ifc.Name, recs))
		}

		doc.Instances = append(doc.Instances, in)
	}

	for _, l := range d.links {
		doc.Links = append(doc.Links, fwconfig.Link{
			Name: l.Name,
			A:    fwconfig.LinkEnd{Instance: instName[l.InstanceAID], Interface: l.InterfaceA, Addresses: []string(l.AddressesA)},
			B:    fwconfig.LinkEnd{Instance: instName[l.InstanceBID], Interface: l.InterfaceB, Addresses: []string(l.AddressesB)},
		})
	}

	if err := doc.Validate(); err != nil {
		if ve, ok := err.(*fwconfig.ValidationError); ok {
			problems = append(problems, ve.Problems...)
		} else {
			problems = append(problems, err.Error())
		}
	}
	if len(doc.Instances) == 0 {
		problems = append(problems, "no instances configured")
	}
	if len(problems) > 0 {
		return doc, &fwconfig.ValidationError{Problems: problems}
	}
	return doc, nil
}

// DynDNS is a dynamic DNS client with its records as the document holds
// it; iface is the name of its interface.
func DynDNS(c *models.DyndnsClient, iface string, records []models.DyndnsRecord) fwconfig.DynDNS {
	d := fwconfig.DynDNS{
		Name: c.Name, Interface: iface, Server: c.Server, Zone: c.Zone,
		RetryInterval: c.RetryInterval, VerifyInterval: c.VerifyInterval,
		Records: []fwconfig.DynDNSRecord{},
	}
	if c.TsigName != "" {
		d.TSIG = &fwconfig.TSIG{Name: c.TsigName, Algorithm: c.TsigAlgorithm, Secret: c.TsigSecret}
	}
	for _, r := range records {
		d.Records = append(d.Records, fwconfig.DynDNSRecord{Name: r.Name, Type: r.Type, TTL: r.Ttl, Value: r.Value})
	}
	return d
}

// zoneFor finds the forward zone a FQDN belongs to (longest suffix match)
// and returns the record label relative to it ("@" for the apex).
// RecordName is a record's name relative to its zone, given the $DOMAIN
// row above it ("" for none): www under $DOMAIN lab is www.lab, @ is lab.
func RecordName(domain, name string) string {
	switch {
	case domain == "":
		return name
	case name == "" || name == "@":
		return domain
	default:
		return name + "." + domain
	}
}

// addDNSTemplate adds the DNS template with the given id to dns, with its
// SOA template and DNSSEC policy, once. Returns the template's name, or ""
// if it doesn't exist.
func (d *data) addDNSTemplate(dns *fwconfig.DNSServer, id uint) string {
	var t *models.DnsTemplate
	for i := range d.templates {
		if d.templates[i].ID == id {
			t = &d.templates[i]
		}
	}
	if t == nil {
		return ""
	}
	if dns.ZoneTemplate(t.Name) != nil {
		return t.Name
	}
	zt := fwconfig.DNSZoneTemplate{Name: t.Name, DefaultTTL: t.DefaultTtl, Nameservers: append([]string{}, t.Nameservers...)}
	for _, s := range d.soas {
		if s.ID != t.SoaTemplateID {
			continue
		}
		zt.SOA = s.Name
		if !slices.ContainsFunc(dns.SOATemplates, func(x fwconfig.DNSSOATemplate) bool { return x.Name == s.Name }) {
			dns.SOATemplates = append(dns.SOATemplates, fwconfig.DNSSOATemplate{
				Name: s.Name, MName: s.Mname, RName: s.Rname,
				Refresh: s.Refresh, Retry: s.Retry, Expire: s.Expire, Minimum: s.Minimum,
			})
		}
	}
	for _, k := range d.policies {
		if t.DnssecPolicyID == nil || k.ID != *t.DnssecPolicyID {
			continue
		}
		zt.DNSSECPolicy = k.Name
		if !slices.ContainsFunc(dns.DNSSECPolicies, func(x fwconfig.DNSSECPolicy) bool { return x.Name == k.Name }) {
			dns.DNSSECPolicies = append(dns.DNSSECPolicies, fwconfig.DNSSECPolicy{
				Name:        k.Name,
				KSKLifetime: k.KskLifetime, KSKAlgorithm: k.KskAlgorithm,
				ZSKLifetime: k.ZskLifetime, ZSKAlgorithm: k.ZskAlgorithm,
				PurgeKeys:                k.PurgeKeys,
				SignaturesValidity:       k.SignaturesValidity,
				SignaturesValidityDNSKEY: k.SignaturesValidityDnskey,
				SignaturesRefresh:        k.SignaturesRefresh,
			})
		}
	}
	dns.ZoneTemplates = append(dns.ZoneTemplates, zt)
	return t.Name
}

func zoneFor(zones []*fwconfig.DNSZone, fqdn string) (*fwconfig.DNSZone, string) {
	name := strings.ToLower(strings.TrimSuffix(fqdn, "."))
	sort.SliceStable(zones, func(i, j int) bool { return len(zones[i].Name) > len(zones[j].Name) })
	for _, z := range zones {
		zname := strings.ToLower(strings.TrimSuffix(z.Name, "."))
		if name == zname {
			return z, "@"
		}
		if strings.HasSuffix(name, "."+zname) {
			return z, strings.TrimSuffix(name, "."+zname)
		}
	}
	return nil, ""
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
