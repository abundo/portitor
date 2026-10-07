// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package builder turns portitor-web's database into the fwconfig.Document
// that portitor-agent applies. It resolves references (instance ids to names,
// DHCP prefixes to serving interfaces, names of hosts and services) and
// reports what it cannot resolve; fwconfig.Validate does the rest.
package builder

import (
	"fmt"
	"maps"
	"math"
	"net/netip"
	"slices"
	"sort"
	"strings"

	"gorm.io/gorm"

	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/netobj"
	"github.com/abundo/portitor/models"
)

type data struct {
	instances      []models.Instance
	ifaceZones     []models.InterfaceZone
	interfaces     []models.Interface
	peers          []models.WgPeer
	links          []models.Link
	routes         []models.Route
	rules          []models.Rule
	nat            []models.NatRule
	prefixes       []models.IpamPrefix
	addrs          []models.IpamAddress
	dnsZones       []models.DnsZone
	records        []models.DnsRecord
	objects        []models.AddressObject
	addressLists   []models.AddressList
	soas           []models.DnsSoaTemplate
	policies       []models.DnsDnssecPolicy
	templates      []models.DnsTemplate
	dyndns         []models.DyndnsClient
	dyndnsRecs     []models.DyndnsRecord
	certs          []models.Certificate
	ipLists        []models.IpList
	tasks          []models.Task
	services       []models.Service
	rateLimits     []models.RateLimit
	prefixLists    []models.RoutePrefixList
	asPathLists    []models.RouteAsPathList
	communityLists []models.RouteCommunityList
	routeMaps      []models.RouteMap
	bgpConfigs     []models.BgpConfig
	bgpGroups      []models.BgpPeerGroup
	bgpNeighbors   []models.BgpNeighbor
	ospfConfigs    []models.OspfConfig
	ospfIfaces     []models.OspfInterface
	vrrpRouters    []models.VrrpRouter
	bfdIfaces      []models.BfdInterface
	vrfs           []models.Vrf
	snmpUsers      []models.SnmpUser
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
		{&d.addressLists, "name"},
		{&d.soas, "name"},
		{&d.policies, "name"},
		{&d.templates, "name"},
		{&d.dyndns, "name"},
		{&d.dyndnsRecs, "client_id, id"},
		{&d.certs, "name"},
		{&d.ipLists, "name"},
		{&d.tasks, "name"},
		{&d.services, "name"},
		{&d.rateLimits, "name"},
		{&d.prefixLists, "name"},
		{&d.asPathLists, "name"},
		{&d.communityLists, "name"},
		{&d.routeMaps, "name"},
		{&d.bgpConfigs, "id"},
		{&d.bgpGroups, "name"},
		{&d.bgpNeighbors, "id"},
		{&d.ospfConfigs, "id"},
		{&d.ospfIfaces, "name"},
		{&d.vrrpRouters, "interface, vrid"},
		{&d.bfdIfaces, "interface"},
		{&d.vrfs, "name"},
		{&d.snmpUsers, "name"},
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
	return build(db, generation, nil)
}

// BuildInstances builds only the named instances, for a deploy that
// changes those and keeps the rest as deployed: no links, IP lists or
// tasks, and no fwconfig.Validate (the caller validates the document it
// merges them into). Problems resolving the database come back as a
// *fwconfig.ValidationError alongside the document.
func BuildInstances(db *gorm.DB, generation int64, only map[string]bool) (*fwconfig.Document, error) {
	return build(db, generation, only)
}

func build(db *gorm.DB, generation int64, only map[string]bool) (*fwconfig.Document, error) {
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
	objs := netobj.New(d.objects, d.addressLists...)
	failed := false // set by expand and expandServices; callers drop what they failed on
	expand := func(where string, fn func([]string) ([]string, error), list []string) []string {
		out, err := fn(list)
		if err != nil {
			addf("%s: %v", where, err)
			failed = true
		}
		return out
	}
	// So are services: the agent sees protocol matches only.
	services := netobj.NewServices(d.services)
	expandServices := func(where string, names []string) []fwconfig.ServiceMatch {
		out, err := services.Expand(names)
		if err != nil {
			addf("%s: %v", where, err)
			failed = true
		}
		return out
	}

	doc := &fwconfig.Document{Version: fwconfig.Version, Generation: generation, Instances: []fwconfig.Instance{}, Links: []fwconfig.Link{}}

	for _, mi := range d.instances {
		if only != nil && !only[mi.Name] {
			continue
		}
		in := fwconfig.Instance{
			Name:    mi.Name,
			Default: mi.IsDefault,
			Rules:   []fwconfig.Rule{},
			NAT:     []fwconfig.NATRule{},
			Routes:  []fwconfig.Route{},
		}
		for _, c := range []string{fwconfig.ChainInput, fwconfig.ChainForward, fwconfig.ChainOutput} {
			if contains(mi.LogDrops, c) {
				in.LogDrops = append(in.LogDrops, c)
			}
			if contains(mi.LogInvalid, c) {
				in.LogInvalid = append(in.LogInvalid, c)
			}
		}
		for _, svc := range mi.LogAuto {
			if !contains(in.LogAuto, svc) {
				in.LogAuto = append(in.LogAuto, svc)
			}
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
				VRF:          mif.Vrf,
				MTU:          mif.Mtu,
				IPv4Mode:     mif.Ipv4Mode,
				Addresses:    []string(mif.Addresses),
				IPv6AcceptRA: mif.Ipv6AcceptRA,
				// Only meaningful for a DHCP client.
				DHCPNoDefaultRoute: mif.DhcpNoDefaultRoute && mif.Ipv4Mode == fwconfig.ModeDHCP,
				DHCPv6:             mif.Dhcpv6,
				DHCPv6PD:           mif.Dhcpv6 && mif.Dhcpv6Pd,
				LLDP:               mif.Lldp && mif.Kind != fwconfig.KindWireGuard && mif.Kind != fwconfig.KindLoopback && mif.Kind != fwconfig.Kind6in4,
				ShapeEgress:        mif.ShapeEgress,
				ShapeIngress:       mif.ShapeIngress,
			}
			if ifc.DHCPv6PD {
				ifc.DHCPv6PDLength = mif.Dhcpv6PdLength
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
						Networks:     []string(p.Networks),
						Keepalive:    p.Keepalive,
					})
				}
				for i := range wg.Peers {
					wg.Peers[i].AllowedIPs = expand(fmt.Sprintf("instance %s: %s peer %s: allowed IPs", mi.Name, mif.Name, wg.Peers[i].Name), objs.Prefixes, wg.Peers[i].AllowedIPs)
					if len(wg.Peers[i].Networks) > 0 {
						wg.Peers[i].Networks = expand(fmt.Sprintf("instance %s: %s peer %s: networks", mi.Name, mif.Name, wg.Peers[i].Name), objs.Prefixes, wg.Peers[i].Networks)
					}
				}
				ifc.WireGuard = wg
			}
			if mif.Kind == fwconfig.KindVXLAN {
				ifc.VXLAN = &fwconfig.VXLAN{VNI: mif.VxlanVni, Local: mif.VxlanLocal, Device: mif.VxlanDevice, Port: mif.VxlanPort,
					Remotes: slices.Clone([]string(mif.VxlanRemotes))}
			}
			if mif.Kind == fwconfig.Kind6in4 {
				ifc.Tunnel = &fwconfig.Tunnel6in4{Remote: mif.TunnelRemote, Local: mif.TunnelLocal}
				if mif.HeTunnelID != "" {
					ifc.Tunnel.TunnelBroker = &fwconfig.TunnelBroker{TunnelID: mif.HeTunnelID, Username: mif.HeUsername, UpdateKey: mif.HeUpdateKey}
				}
			}
			in.Interfaces = append(in.Interfaces, ifc)
		}

		// A filter rule's address lists become the instance's address sets
		// ("$name"), each expanded once; other names expand into the rule.
		ruleAddrs := func(list []string) ([]string, error) {
			var out []string
			for _, e := range list {
				if !objs.IsList(e) {
					x, err := objs.Expand([]string{e})
					if err != nil {
						return nil, err
					}
					for _, a := range x {
						if !slices.Contains(out, a) {
							out = append(out, a)
						}
					}
					continue
				}
				if in.AddressSet(e) == nil {
					addrs, err := objs.Expand([]string{e})
					if err != nil {
						return nil, err
					}
					in.AddressSets = append(in.AddressSets, fwconfig.AddressSet{Name: e, Addresses: addrs})
				}
				if ref := fwconfig.AddressSetRef + e; !slices.Contains(out, ref) {
					out = append(out, ref)
				}
			}
			return out, nil
		}
		for _, r := range d.rules {
			if r.InstanceID != mi.ID || !r.Enabled {
				continue
			}
			if r.IsNote() {
				// A group heading reaches the agent as a comment.
				desc := r.Description
				if r.Kind == models.RuleKindGroup && desc != "" {
					desc = "group: " + desc
				}
				in.Rules = append(in.Rules, fwconfig.Rule{Chain: r.Chain, Kind: fwconfig.RuleKindComment, Description: desc})
				continue
			}
			where := fmt.Sprintf("instance %s: rule %d", mi.Name, len(in.Rules)+1)
			failed = false
			rule := fwconfig.Rule{
				ID:            ruleID(r.ID),
				Chain:         r.Chain,
				InInterfaces:  []string(r.InInterfaces),
				OutInterfaces: []string(r.OutInterfaces),
				Family:        r.Family,
				SrcAddrs:      expand(where+": source", ruleAddrs, r.SrcAddrs),
				DstAddrs:      expand(where+": destination", ruleAddrs, r.DstAddrs),
				Services:      expandServices(where+": services", r.Services),
				Action:        r.Action,
				Log:           r.Log,
				RateLimit:     r.RateLimit,
				Description:   r.Description,
			}
			// An unresolved name must not leave an emptier (wider) match.
			if !failed {
				in.Rules = append(in.Rules, rule)
			}
		}
		for _, l := range d.rateLimits {
			if l.InstanceID == mi.ID {
				in.RateLimits = append(in.RateLimits, fwconfig.RateLimit{
					Name: l.Name, Rate: l.Rate, Unit: l.Unit, Per: l.Per, Burst: l.Burst,
					PerSource: l.PerSource, Connections: l.Connections, Shape: l.Shape,
				})
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
				Hairpin:       n.Hairpin,
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
		// A 6in4 tunnel's default route: the tunnel is point to point, so
		// no gateway.
		for _, mif := range d.interfaces {
			if mif.InstanceID == mi.ID && mif.Kind == fwconfig.Kind6in4 && mif.TunnelDefaultRoute && mif.Enabled {
				in.Routes = append(in.Routes, fwconfig.Route{Destination: "::/0", Interface: mif.Name, Metric: fwconfig.TunnelRouteMetric})
			}
		}
		vrfName := map[uint]string{}
		for _, v := range d.vrfs {
			if v.InstanceID == mi.ID {
				vrfName[v.ID] = v.Name
				in.VRFs = append(in.VRFs, fwconfig.VRF{Name: v.Name, Table: v.RouteTable, Description: v.Description})
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
				route := fwconfig.Route{Destination: dst, Metric: r.Metric, BFD: r.Bfd}
				if r.InterfaceID != nil {
					route.Interface = ifaceByID[*r.InterfaceID].Name
				}
				if r.VrfID != nil {
					route.VRF = vrfName[*r.VrfID]
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
			Enabled:          true,
			Upstream:         mi.DnsUpstream,
			ForwardMode:      mi.DnsForwardMode,
			DNSSECValidation: mi.DnsDnssecValidation,
			AllowRecursion:   expand("instance "+mi.Name+": dns allow recursion", objs.Prefixes, mi.DnsAllowRecursion),
			Zones:            []fwconfig.DNSZone{},
		}
		if mi.Dns64 {
			in.DNS.DNS64 = mi.Nat64Prefix
		}
		if mi.DnsQueryLog {
			in.DNS.QueryLog = &fwconfig.DNSQueryLog{
				Clients: expand("instance "+mi.Name+": dns query log clients", objs.Prefixes, mi.DnsQueryLogClients),
				Names:   mi.DnsQueryLogNames,
				Types:   mi.DnsQueryLogTypes,
			}
		}
		switch mi.DnsUpstream {
		case fwconfig.UpstreamForward, "":
			in.DNS.Forwarders = expand("instance "+mi.Name+": dns forwarders", objs.Hosts, mi.DnsForwarders)
		case fwconfig.UpstreamDHCP:
			for _, mif := range d.interfaces {
				if mif.InstanceID == mi.ID && mif.DnsFromDhcp && mif.Ipv4Mode == fwconfig.ModeDHCP {
					in.DNS.DHCPInterface = mif.Name
				}
			}
			if in.DNS.DHCPInterface == "" {
				addf("instance %s: DNS upstream is the DHCP lease of an interface, but no DHCP client interface is chosen", mi.Name)
			}
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
			if z.Type == fwconfig.ZoneForwardOnly {
				dz.Forwarders = expand("instance "+mi.Name+": dns zone "+z.Name+" forwarders", objs.Hosts, z.Forwarders)
				in.DNS.Zones = append(in.DNS.Zones, dz)
				continue
			}
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
		// The addresses of the templates' nameservers, in the zone their
		// name is in (glue for a nameserver inside its own zone).
		for _, z := range d.dnsZones {
			if z.InstanceID != mi.ID || z.DnsTemplateID == nil {
				continue
			}
			for _, t := range d.templates {
				if t.ID == *z.DnsTemplateID {
					addNameserverRecords(forwardZones, t.Nameservers)
				}
			}
		}

		// DHCP and IPv6 router advertisements: IPAM prefixes with DHCP or
		// RA on, served on the interface that has an address inside the
		// prefix (with the prefix's length). Several on one interface
		// become a Kea shared network (render.KeaDhcp4Conf).
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
			if len(dns) == 0 && contains(in.DNS.ListenInterfaces, serveOn) {
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
					if mif, ok := ifaceByName(d.interfaces, mi.ID, serveOn); ok && mif.Xlat464 {
						sub.IPv6OnlyPreferred = fwconfig.IPv6OnlyWait
					}
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
		delegatedRA(&in, mi)
		for i, ra := range in.RA {
			if mif, ok := ifaceByName(d.interfaces, mi.ID, ra.Interface); ok && mif.Xlat464 {
				in.RA[i].NAT64Prefix = mi.Nat64Prefix
			}
		}
		if mi.Nat64 {
			in.NAT64 = &fwconfig.NAT64{Prefix: mi.Nat64Prefix, Pool4: mi.Nat64Pool4}
			for _, ifc := range in.Interfaces {
				if mif, ok := ifaceByName(d.interfaces, mi.ID, ifc.Name); ok && mif.Xlat464 {
					in.NAT64.Interfaces = append(in.NAT64.Interfaces, ifc.Name)
				}
			}
		}

		if mi.NtpEnabled {
			in.NTP = &fwconfig.NTP{
				Servers: slices.Clone([]fwconfig.NTPServer(mi.NtpServers)),
				Allow:   expand("instance "+mi.Name+": ntp allow", objs.Prefixes, mi.NtpAllow),
			}
			for _, ifc := range in.Interfaces {
				if mif, ok := ifaceByName(d.interfaces, mi.ID, ifc.Name); ok && mif.NtpServe {
					in.NTP.Interfaces = append(in.NTP.Interfaces, ifc.Name)
				}
			}
		}

		if mi.SnmpEnabled {
			in.SNMP = &fwconfig.SNMP{
				Location:  mi.SnmpLocation,
				Contact:   mi.SnmpContact,
				Allow:     expand("instance "+mi.Name+": snmp allow", objs.Prefixes, mi.SnmpAllow),
				Community: mi.SnmpCommunity,
			}
			for _, ifc := range in.Interfaces {
				if mif, ok := ifaceByName(d.interfaces, mi.ID, ifc.Name); ok && mif.SnmpServe {
					in.SNMP.Interfaces = append(in.SNMP.Interfaces, ifc.Name)
				}
			}
			for i := range d.snmpUsers {
				if u := &d.snmpUsers[i]; u.InstanceID == mi.ID && u.Enabled {
					in.SNMP.Users = append(in.SNMP.Users, u.User())
				}
			}
		}

		for _, c := range d.dyndns {
			if c.InstanceID != mi.ID || !c.Enabled {
				continue
			}
			ifc, ok := ifaceByID[c.InterfaceID]
			if !ok || ifc.InstanceID != mi.ID {
				addf("instance %s: DNS update %s: its interface is not in this instance", mi.Name, c.Name)
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

		for _, c := range d.certs {
			if c.InstanceID != mi.ID || !c.Enabled {
				continue
			}
			if c.Source == fwconfig.CertSourceImport {
				in.Certificates = append(in.Certificates, Certificate(&c, ""))
				continue
			}
			var ifc models.Interface
			if c.InterfaceID != nil {
				ifc = ifaceByID[*c.InterfaceID]
			}
			if ifc.ID == 0 || ifc.InstanceID != mi.ID {
				addf("instance %s: certificate %s: its interface is not in this instance", mi.Name, c.Name)
				continue
			}
			in.Certificates = append(in.Certificates, Certificate(&c, ifc.Name))
		}

		d.bgp(&in, mi.ID)
		in.OSPF, in.OSPF6 = d.ospf(mi.ID, 2), d.ospf(mi.ID, 3)
		for i := range d.vrrpRouters {
			if r := &d.vrrpRouters[i]; r.InstanceID == mi.ID {
				in.VRRP = append(in.VRRP, r.Router())
			}
		}
		// A disabled BFD interface is left out: no BFD there.
		for i := range d.bfdIfaces {
			if b := &d.bfdIfaces[i]; b.InstanceID == mi.ID && b.Enabled {
				in.BFD = append(in.BFD, b.BFD())
			}
		}
		if in.FRRRunning() {
			d.routingPolicy(&in, mi.ID)
		}

		doc.Instances = append(doc.Instances, in)
	}

	if only != nil {
		if len(problems) > 0 {
			return doc, &fwconfig.ValidationError{Problems: problems}
		}
		return doc, nil
	}
	for _, l := range d.links {
		doc.Links = append(doc.Links, fwconfig.Link{
			Name: l.Name,
			A:    fwconfig.LinkEnd{Instance: instName[l.InstanceAID], Interface: l.InterfaceA, Addresses: []string(l.AddressesA)},
			B:    fwconfig.LinkEnd{Instance: instName[l.InstanceBID], Interface: l.InterfaceB, Addresses: []string(l.AddressesB)},
		})
	}

	// IP lists stay references ("@name") in rules; the agent downloads
	// them.
	listName := map[uint]string{}
	for _, l := range d.ipLists {
		listName[l.ID] = l.Name
		doc.IPLists = append(doc.IPLists, fwconfig.IPList{
			Name: l.Name, Source: l.Source, URL: l.Url,
			Username: l.Username, Password: l.Password, APIKey: l.ApiKey,
		})
	}
	for _, t := range d.tasks {
		if !t.Enabled {
			continue
		}
		task := fwconfig.Task{Name: t.Name, Schedule: t.Schedule, Kind: t.Kind, Command: t.Command, Timeout: t.Timeout}
		if t.Kind == fwconfig.TaskIPList {
			if t.IpListID == nil || listName[*t.IpListID] == "" {
				addf("task %s: its IP list no longer exists", t.Name)
				continue
			}
			task.IPList = listName[*t.IpListID]
		}
		doc.Tasks = append(doc.Tasks, task)
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

// bgp adds the instance's BGP when it is enabled.
func (d *data) bgp(in *fwconfig.Instance, instanceID uint) {
	var cfg *models.BgpConfig
	for i := range d.bgpConfigs {
		if d.bgpConfigs[i].InstanceID == instanceID {
			cfg = &d.bgpConfigs[i]
		}
	}
	if cfg == nil || !cfg.Enabled {
		return
	}
	b := &fwconfig.BGP{
		Enabled:            true,
		ASN:                cfg.Asn,
		RouterID:           cfg.RouterID,
		Keepalive:          cfg.Keepalive,
		Hold:               cfg.Hold,
		EBGPRequiresPolicy: cfg.EbgpRequiresPolicy,
		LogNeighborChanges: cfg.LogNeighborChanges,
		GracefulRestart:    cfg.GracefulRestart,
		MultipathRelax:     cfg.MultipathRelax,
		MaximumPaths:       cfg.MaximumPaths,
		EVPN:               cfg.Evpn,
		Networks:           slices.Clone([]fwconfig.BGPNetwork(cfg.Networks)),
		Aggregates:         slices.Clone([]fwconfig.BGPAggregate(cfg.Aggregates)),
	}
	for _, r := range []struct {
		on          bool
		family, src string
		routeMap    string
	}{
		{cfg.RedistConnectedV4, "ipv4", fwconfig.RedistConnected, cfg.RedistConnectedV4Map},
		{cfg.RedistStaticV4, "ipv4", fwconfig.RedistStatic, cfg.RedistStaticV4Map},
		{cfg.RedistConnectedV6, "ipv6", fwconfig.RedistConnected, cfg.RedistConnectedV6Map},
		{cfg.RedistStaticV6, "ipv6", fwconfig.RedistStatic, cfg.RedistStaticV6Map},
		{cfg.RedistOspfV4, "ipv4", fwconfig.RedistOSPF, cfg.RedistOspfV4Map},
		{cfg.RedistOspfV6, "ipv6", fwconfig.RedistOSPF, cfg.RedistOspfV6Map},
	} {
		if r.on {
			b.Redistribute = append(b.Redistribute, fwconfig.BGPRedistribute{Family: r.family, Source: r.src, RouteMap: r.routeMap})
		}
	}
	for _, g := range d.bgpGroups {
		if g.InstanceID == instanceID {
			p := g.Peer()
			p.Name = g.Name
			b.PeerGroups = append(b.PeerGroups, p)
		}
	}
	for _, n := range d.bgpNeighbors {
		if n.InstanceID == instanceID && n.Enabled {
			p := n.Peer()
			p.Address, p.PeerGroup, p.Interface = n.Address, n.PeerGroup, n.Interface
			b.Neighbors = append(b.Neighbors, p)
		}
	}
	in.BGP = b
}

// ospf returns the instance's OSPF of a version when it is enabled, or
// nil.
func (d *data) ospf(instanceID uint, version int) *fwconfig.OSPF {
	var cfg *models.OspfConfig
	for i := range d.ospfConfigs {
		if c := &d.ospfConfigs[i]; c.InstanceID == instanceID && c.Version == version {
			cfg = c
		}
	}
	if cfg == nil || !cfg.Enabled {
		return nil
	}
	o := &fwconfig.OSPF{
		Enabled:             true,
		RouterID:            cfg.RouterID,
		ReferenceBandwidth:  cfg.ReferenceBandwidth,
		LogAdjacencyChanges: cfg.LogAdjacencyChanges,
		MaximumPaths:        cfg.MaximumPaths,
		DefaultOriginate:    cfg.DefaultOriginate,
		DefaultAlways:       cfg.DefaultAlways,
		Areas:               slices.Clone([]fwconfig.OSPFArea(cfg.Areas)),
		Ranges:              slices.Clone([]fwconfig.OSPFRange(cfg.Ranges)),
		Summaries:           slices.Clone([]fwconfig.OSPFSummary(cfg.Summaries)),
		Networks:            slices.Clone([]fwconfig.OSPFNetwork(cfg.Networks)),
		Redistribute:        slices.Clone([]fwconfig.OSPFRedistribute(cfg.Redistribute)),
	}
	for i := range d.ospfIfaces {
		if ifc := &d.ospfIfaces[i]; ifc.InstanceID == instanceID && ifc.Version == version {
			o.Interfaces = append(o.Interfaces, ifc.Interface())
		}
	}
	return o
}

// routingPolicy adds the instance's routing policy objects, when FRR runs
// (BGP or OSPF): off, they stay out of the document.
func (d *data) routingPolicy(in *fwconfig.Instance, instanceID uint) {
	rp := &in.RoutingPolicy
	for _, l := range d.prefixLists {
		if l.InstanceID == instanceID {
			rp.PrefixLists = append(rp.PrefixLists, fwconfig.PrefixList{Name: l.Name, Family: l.Family, Description: l.Description, Entries: slices.Clone([]fwconfig.PrefixListEntry(l.Entries))})
		}
	}
	for _, l := range d.asPathLists {
		if l.InstanceID == instanceID {
			rp.ASPathLists = append(rp.ASPathLists, fwconfig.ASPathList{Name: l.Name, Description: l.Description, Entries: slices.Clone([]fwconfig.ASPathEntry(l.Entries))})
		}
	}
	for _, l := range d.communityLists {
		if l.InstanceID == instanceID {
			rp.CommunityLists = append(rp.CommunityLists, fwconfig.CommunityList{Name: l.Name, Kind: l.Kind, Description: l.Description, Entries: slices.Clone([]fwconfig.CommunityEntry(l.Entries))})
		}
	}
	for _, m := range d.routeMaps {
		if m.InstanceID == instanceID {
			rp.RouteMaps = append(rp.RouteMaps, fwconfig.RouteMap{Name: m.Name, Description: m.Description, Entries: slices.Clone([]fwconfig.RouteMapEntry(m.Entries))})
		}
	}
}

// Certificate is a certificate as the document holds it; iface is the
// name of its interface.
func Certificate(c *models.Certificate, iface string) fwconfig.Certificate {
	if c.Source == fwconfig.CertSourceImport {
		return fwconfig.Certificate{Name: c.Name, Source: c.Source, FullChain: c.FullChain, PrivKey: c.PrivKey}
	}
	return fwconfig.Certificate{
		Name: c.Name, Domains: slices.Clone([]string(c.Domains)), CommonName: c.CommonName, Email: c.Email,
		CA: c.Ca, KeyType: c.KeyType, Challenge: c.Challenge, Interface: iface,
	}
}

// DynDNS is a DNS update client with its records as the document holds
// it; iface is the name of its interface.
func DynDNS(c *models.DyndnsClient, iface string, records []models.DyndnsRecord) fwconfig.DynDNS {
	d := fwconfig.DynDNS{
		Name: c.Name, Interface: iface, Provider: c.Provider, Zone: c.Zone,
		RetryInterval: c.RetryInterval, VerifyInterval: c.VerifyInterval,
		Records: []fwconfig.DynDNSRecord{},
	}
	if c.Provider == "" || c.Provider == fwconfig.ProviderRFC2136 {
		d.Server = c.Server
		if c.TsigName != "" {
			d.TSIG = &fwconfig.TSIG{Name: c.TsigName, Algorithm: c.TsigAlgorithm, Secret: c.TsigSecret}
		}
	} else {
		d.ProviderSettings = maps.Clone(map[string]string(c.ProviderSettings))
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
	zt := fwconfig.DNSZoneTemplate{Name: t.Name, DefaultTTL: t.DefaultTtl, Nameservers: t.Nameservers.Names()}
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

// addNameserverRecords adds an A or AAAA record for the address of each
// nameserver whose name is in one of zones, unless the zone has it already.
func addNameserverRecords(zones []*fwconfig.DNSZone, nameservers models.DnsNameserverList) {
	for _, ns := range nameservers {
		ip, err := netip.ParseAddr(ns.Address)
		if err != nil {
			continue
		}
		zone, label := zoneFor(zones, ns.Name)
		if zone == nil {
			continue
		}
		r := fwconfig.DNSRecord{Name: label, Type: "A", Value: ip.String()}
		if ip.Is6() {
			r.Type = "AAAA"
		}
		if !slices.ContainsFunc(zone.Records, func(x fwconfig.DNSRecord) bool {
			return strings.EqualFold(x.Name, r.Name) && x.Type == r.Type && x.Value == r.Value
		}) {
			zone.Records = append(zone.Records, r)
		}
	}
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

// ruleID is a rule's database id as its fwconfig.Rule ID (a connection
// mark, 32 bits); an id that does not fit gets no rule counters.
func ruleID(id uint) uint32 {
	if id > math.MaxUint32 {
		return 0
	}
	return uint32(id)
}

// delegatedRA announces with router advertisements (SLAAC) the /64 of
// each address relative to a delegated prefix: the prefix is not known
// until the agent gets it, so it cannot be an IPAM prefix. The address is
// the DNS server announced when DNS listens on the interface.
func delegatedRA(in *fwconfig.Instance, mi models.Instance) {
	for _, ifc := range in.Interfaces {
		for _, a := range ifc.Addresses {
			d, err := fwconfig.ParseDelegated(a)
			if err != nil || d.Bits != 64 {
				continue
			}
			i := slices.IndexFunc(in.RA, func(ra fwconfig.RAInterface) bool { return ra.Interface == ifc.Name })
			if i < 0 {
				i = len(in.RA)
				in.RA = append(in.RA, fwconfig.RAInterface{Interface: ifc.Name})
			}
			ra := &in.RA[i]
			pfx := d
			pfx.Host = 0
			if !slices.ContainsFunc(ra.Prefixes, func(p fwconfig.RAPrefix) bool { return p.Prefix == pfx.String() }) {
				ra.Prefixes = append(ra.Prefixes, fwconfig.RAPrefix{Prefix: pfx.String(), Autonomous: true})
			}
			if contains(in.DNS.ListenInterfaces, ifc.Name) && !contains(ra.RDNSS, a) {
				ra.RDNSS = append(ra.RDNSS, a)
			}
			if mi.DhcpDomainName != "" && !contains(ra.DNSSL, mi.DhcpDomainName) {
				ra.DNSSL = append(ra.DNSSL, mi.DhcpDomainName)
			}
		}
	}
}

// ifaceByName finds an instance's interface row by name.
func ifaceByName(ifaces []models.Interface, instanceID uint, name string) (models.Interface, bool) {
	for _, i := range ifaces {
		if i.InstanceID == instanceID && i.Name == name {
			return i, true
		}
	}
	return models.Interface{}, false
}
