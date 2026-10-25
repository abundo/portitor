// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package builder turns portitor-web's database into the fwconfig.Document
// that portitor-agent applies. It resolves references (instance ids to names,
// DHCP prefixes to serving interfaces, names of hosts and services) and
// reports what it cannot resolve; fwconfig.Validate does the rest.
package builder

import (
	"errors"
	"fmt"
	"maps"
	"math"
	"net/netip"
	"net/url"
	"slices"
	"sort"
	"strconv"
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
	policyRoutes   []models.PolicyRoute
	neighbours     []models.StaticNeighbour
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
	portNames      []models.PortName
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
	isisConfigs    []models.IsisConfig
	isisIfaces     []models.IsisInterface
	vrrpRouters    []models.VrrpRouter
	bfdIfaces      []models.BfdInterface
	vrfs           []models.Vrf
	snmpUsers      []models.SnmpUser
	proxyPolicies  []models.AcmeProxyPolicy
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
		{&d.policyRoutes, "position, id"},
		{&d.neighbours, "id"},
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
		{&d.portNames, "name"},
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
		{&d.isisConfigs, "id"},
		{&d.isisIfaces, "name"},
		{&d.vrrpRouters, "interface, vrid"},
		{&d.bfdIfaces, "interface"},
		{&d.vrfs, "name"},
		{&d.snmpUsers, "name"},
		{&d.proxyPolicies, "name"},
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
	return build(db, generation, nil, 0)
}

// BuildFirewall is Build for one firewall: its instances, the links
// between them, its tasks, and every IP list. An HA secondary gets its
// primary's, with the peer values (peerValues).
func BuildFirewall(db *gorm.DB, generation int64, firewallID uint) (*fwconfig.Document, error) {
	return BuildFirewallInstances(db, generation, firewallID, nil)
}

// BuildFirewallInstances is BuildInstances for a firewall: only the named
// instances (nil: all) of those it runs, an HA secondary with the peer
// values, and no fwconfig.Validate when only is set.
func BuildFirewallInstances(db *gorm.DB, generation int64, firewallID uint, only map[string]bool) (*fwconfig.Document, error) {
	var fw models.Firewall
	if err := db.First(&fw, firewallID).Error; err != nil {
		return nil, err
	}
	ha, haProblem, err := haBlock(db, &fw)
	if err != nil {
		return nil, err
	}
	runs := firewallID
	if fw.HAPrimaryID != nil {
		runs = *fw.HAPrimaryID
	}
	return buildPeer(db, generation, only, runs, fw.HAPrimaryID != nil, ha, haProblem)
}

// haBlock is the firewall's place in its HA pair, or nil outside one,
// with a problem when the pair can't reach each other's agents.
func haBlock(db *gorm.DB, fw *models.Firewall) (*fwconfig.HA, string, error) {
	var peer models.Firewall
	ha := &fwconfig.HA{}
	switch err := db.Where("ha_primary_id = ?", fw.ID).First(&peer).Error; {
	case fw.HAPrimaryID != nil:
		if err := db.First(&peer, *fw.HAPrimaryID).Error; err != nil {
			return nil, "", err
		}
		ha.Node, ha.Secret, ha.Epoch = fwconfig.HASecondary, fw.HASecret, fw.HAEpoch
		if peer.HAWitness == models.HAWitnessExternal {
			ha.WitnessSecret = peer.HAWitnessSecret
		}
	case err == nil:
		ha.Node, ha.Secret, ha.Epoch = fwconfig.HAPrimary, peer.HASecret, peer.HAEpoch
		if fw.HAWitness == models.HAWitnessExternal {
			ha.WitnessSecret = fw.HAWitnessSecret
		}
	case errors.Is(err, gorm.ErrRecordNotFound):
		return nil, "", nil
	default:
		return nil, "", err
	}
	if peer.ConfigURL != "" && peer.ConfigFingerprint != "" {
		ha.PeerConfig, ha.PeerConfigFingerprint = peer.ConfigURL, peer.ConfigFingerprint
	}
	ha.ConfigPort = configPort(fw.ConfigURL)
	ha.Peer, ha.PeerFingerprint = peer.AgentURL, peer.AgentFingerprint
	if u, err := url.Parse(ha.Peer); err == nil {
		if a, err := netip.ParseAddr(u.Hostname()); (err == nil && a.IsLoopback()) || u.Hostname() == "localhost" {
			return nil, fmt.Sprintf("HA: %s's agent URL is a loopback address, which %s can't reach; set its address on the network", peer.Name, fw.Name), nil
		}
	}
	if ha.PeerFingerprint == "" {
		return nil, fmt.Sprintf("HA: %s needs its agent's certificate fingerprint, which %s pins", peer.Name, fw.Name), nil
	}
	return ha, "", nil
}

// configPort is the port of a portitor-config URL (https://host[:port]),
// 0 for none.
func configPort(s string) int {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return 0
	}
	if u.Port() == "" {
		return 443
	}
	p, err := strconv.Atoi(u.Port())
	if err != nil || p < 1 || p > 65535 {
		return 0
	}
	return p
}

// BuildInstances builds only the named instances, for a deploy that
// changes those and keeps the rest as deployed: no links, IP lists or
// tasks, and no fwconfig.Validate (the caller validates the document it
// merges them into). Problems resolving the database come back as a
// *fwconfig.ValidationError alongside the document.
func BuildInstances(db *gorm.DB, generation int64, only map[string]bool) (*fwconfig.Document, error) {
	return build(db, generation, only, 0)
}

// build builds the instances in only (nil: all) on the firewall (0: all).
func build(db *gorm.DB, generation int64, only map[string]bool, firewallID uint) (*fwconfig.Document, error) {
	return buildPeer(db, generation, only, firewallID, false, nil, "")
}

// buildPeer is build, for the firewall's HA secondary when peer is set,
// with the host's HA block (and a problem with it).
func buildPeer(db *gorm.DB, generation int64, only map[string]bool, firewallID uint, peer bool, ha *fwconfig.HA, haProblem string) (*fwconfig.Document, error) {
	d, err := load(db)
	if err != nil {
		return nil, err
	}
	var problems []string
	addf := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }
	if haProblem != "" {
		problems = append(problems, haProblem)
	}
	// Both hosts' static addresses, for Kea's HA peers (dhcpHA): the
	// primary's before peerValues replaces them on the secondary.
	var pairAddrs map[uint][2][]string
	if ha != nil {
		pairAddrs = map[uint][2][]string{}
		for _, ifc := range d.interfaces {
			var own []string
			for _, a := range ifc.Addresses {
				if !fwconfig.IsDelegated(a) {
					own = append(own, a)
				}
			}
			pairAddrs[ifc.ID] = [2][]string{own, ifc.PeerAddresses}
		}
	}
	if peer {
		peerValues(d, firewallID, addf)
	}

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
	// And custom port names: the agent sees their numbers.
	portNames := make(map[string]int, len(d.portNames))
	for _, p := range d.portNames {
		portNames[p.Name] = p.Port
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

	doc := &fwconfig.Document{Version: fwconfig.Version, Generation: generation, Instances: []fwconfig.Instance{}, Links: []fwconfig.Link{}, HA: ha}

	onFirewall := map[uint]bool{}
	for _, mi := range d.instances {
		if firewallID != 0 && mi.FirewallID != firewallID {
			continue
		}
		onFirewall[mi.ID] = true
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
		// The rate limits of the services that are switched on to them.
		serviceLimit := map[string]string{}
		for _, l := range d.rateLimits {
			if l.InstanceID == mi.ID && l.Service != "" {
				serviceLimit[l.Service] = l.Name
			}
		}
		for s, on := range map[string]bool{"dns": mi.DnsRateLimit, "dhcp": mi.DhcpRateLimit, "ntp": mi.NtpRateLimit} {
			if !on {
				delete(serviceLimit, s)
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
				DstPorts:      resolvePortNames(n.DstPorts, portNames),
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
				in.VRFs = append(in.VRFs, fwconfig.VRF{Name: v.Name, Table: v.RouteTable, Description: v.Description, EVPN: v.EVPN()})
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

		for _, r := range d.policyRoutes {
			if r.InstanceID != mi.ID || !r.Enabled {
				continue
			}
			where := fmt.Sprintf("instance %s: policy route %d", mi.Name, len(in.PolicyRoutes)+1)
			failed = false
			pr := fwconfig.PolicyRoute{
				InInterfaces: []string(r.InInterfaces),
				Family:       r.Family,
				SrcAddrs:     expand(where+": source", ruleAddrs, r.SrcAddrs),
				DstAddrs:     expand(where+": destination", ruleAddrs, r.DstAddrs),
				Services:     expandServices(where+": services", r.Services),
				Description:  r.Description,
			}
			if r.Gateway != "" {
				gws, err := objs.Host(r.Gateway)
				if err != nil {
					addf("%s: gateway: %v", where, err)
					continue
				}
				pr.Gateways = gws
			}
			if r.InterfaceID != nil {
				pr.Interface = ifaceByID[*r.InterfaceID].Name
			}
			// An unresolved name must not leave a wider match.
			if !failed {
				in.PolicyRoutes = append(in.PolicyRoutes, pr)
			}
		}

		for _, n := range d.neighbours {
			ifc, ok := ifaceByID[n.InterfaceID]
			if n.InstanceID != mi.ID || !n.Enabled || !ok || !ifc.Enabled {
				continue
			}
			in.StaticNeighbours = append(in.StaticNeighbours, fwconfig.StaticNeighbour{Interface: ifc.Name, Address: n.Address, MAC: n.MAC})
		}

		// DNS: zones, records from the zone and from IPAM names.
		in.DNS = fwconfig.DNSServer{
			Enabled:          true,
			Upstream:         mi.DnsUpstream,
			ForwardMode:      mi.DnsForwardMode,
			DNSSECValidation: mi.DnsDnssecValidation,
			AllowRecursion:   expand("instance "+mi.Name+": dns allow recursion", objs.Prefixes, mi.DnsAllowRecursion),
			RateLimit:        serviceLimit["dns"],
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
		in.DHCP = fwconfig.DHCPServer{Enabled: mi.DhcpEnabled, DomainName: mi.DhcpDomainName, LeaseTime: mi.DhcpLeaseTime, RateLimit: serviceLimit["dhcp"], Subnets: []fwconfig.DHCPSubnet{}}
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
				Servers:   slices.Clone([]fwconfig.NTPServer(mi.NtpServers)),
				Allow:     expand("instance "+mi.Name+": ntp allow", objs.Prefixes, mi.NtpAllow),
				RateLimit: serviceLimit["ntp"],
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
			if c.Challenge == fwconfig.ChallengeDNS01 {
				i := slices.IndexFunc(d.dyndns, func(dc models.DyndnsClient) bool {
					return c.DyndnsClientID != nil && dc.ID == *c.DyndnsClientID && dc.InstanceID == mi.ID
				})
				if i < 0 {
					addf("instance %s: certificate %s: its DNS update client is not in this instance", mi.Name, c.Name)
					continue
				}
				cert := Certificate(&c, "")
				cert.DNS01 = DNS01(&d.dyndns[i])
				in.Certificates = append(in.Certificates, cert)
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
		if mi.AcmeProxyEnabled {
			in.ACMEProxy = d.acmeProxy(&mi, &in, func(where string, l []string) []string { return expand(where, objs.Prefixes, l) }, addf)
		}

		// The main table's routing, then each VRF's.
		in.BGP = d.bgp(mi.ID, nil)
		in.OSPF, in.OSPF6 = d.ospf(mi.ID, 2, nil), d.ospf(mi.ID, 3, nil)
		in.ISIS = d.isis(mi.ID, nil)
		for i := range in.VRFs {
			v := d.vrfByName(mi.ID, in.VRFs[i].Name)
			in.VRFs[i].BGP = d.bgp(mi.ID, v)
			in.VRFs[i].OSPF, in.VRFs[i].OSPF6 = d.ospf(mi.ID, 2, v), d.ospf(mi.ID, 3, v)
			in.VRFs[i].ISIS = d.isis(mi.ID, v)
		}
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

		if ha != nil && in.DHCP.Enabled && len(in.DHCP.Subnets) > 0 {
			h, problem := dhcpHA(&in, mi.ID, d.interfaces, pairAddrs, ha.Node)
			if problem != "" {
				addf("%s: %s", in.Name, problem)
			}
			in.DHCP.HA = h
		}
		if ha != nil {
			in.ConntrackSync = conntrackSync(&in, mi.ID, d.interfaces, pairAddrs, ha.Node)
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
		if a, b := onFirewall[l.InstanceAID], onFirewall[l.InstanceBID]; !a || !b {
			if a || b {
				addf("link %s: its virtual firewalls are on different firewalls", l.Name)
			}
			continue
		}
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
		if !t.Enabled || (firewallID != 0 && t.FirewallID != firewallID) {
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

// haLink is the link the hosts of an HA pair talk over for an instance
// (Kea's HA peers, conntrackd): prefer if it is on the wire (onWire) with
// a static IPv4 address and its peer address, else the first interface
// (by name) that is. The addresses come from the primary's and their
// peer addresses, this host's first. ok is false when there is none: an
// instance with only internal links has no way to its peer.
func haLink(instanceID uint, ifaces []models.Interface, pair map[uint][2][]string, node, prefer string) (iface, this, peer string, ok bool) {
	try := func(ifc models.Interface) bool {
		addrs := pair[ifc.ID]
		for k, a := range addrs[0] {
			p, err := netip.ParsePrefix(a)
			if err != nil || !p.Addr().Is4() || k >= len(addrs[1]) {
				continue
			}
			q, err := netip.ParsePrefix(addrs[1][k])
			if err != nil {
				continue
			}
			iface, this, peer = ifc.Name, p.Addr().String(), q.Addr().String()
			if node == fwconfig.HASecondary {
				this, peer = peer, this
			}
			return true
		}
		return false
	}
	for _, ifc := range ifaces {
		if ifc.InstanceID == instanceID && ifc.Enabled && ifc.Name == prefer && onWire(ifc, instanceID, ifaces) && try(ifc) {
			return iface, this, peer, true
		}
	}
	for _, ifc := range ifaces {
		if ifc.InstanceID != instanceID || !ifc.Enabled {
			continue
		}
		if onWire(ifc, instanceID, ifaces) && try(ifc) {
			return iface, this, peer, true
		}
	}
	return "", "", "", false
}

// onWire tells whether an interface reaches beyond the host: a physical
// one or a bridge, or a VLAN on one (not on a link between instances).
func onWire(ifc models.Interface, instanceID uint, ifaces []models.Interface) bool {
	switch ifc.Kind {
	case fwconfig.KindPhysical, fwconfig.KindBridge, "":
		return true
	case fwconfig.KindVLAN:
		i := slices.IndexFunc(ifaces, func(p models.Interface) bool { return p.InstanceID == instanceID && p.Name == ifc.Parent })
		return i >= 0 && ifaces[i].Kind != fwconfig.KindVLAN && onWire(ifaces[i], instanceID, ifaces)
	}
	return false
}

// dhcpHA is Kea's HA link of an instance on an HA pair (haLink), the
// interface of its first DHCP subnet (IPv4 first) preferred.
func dhcpHA(in *fwconfig.Instance, instanceID uint, ifaces []models.Interface, pair map[uint][2][]string, node string) (*fwconfig.DHCPHA, string) {
	subs := slices.Clone(in.DHCP.Subnets)
	slices.SortStableFunc(subs, func(a, b fwconfig.DHCPSubnet) int {
		return cmpBool(strings.Contains(a.Prefix, ":"), strings.Contains(b.Prefix, ":"))
	})
	iface, this, peer, ok := haLink(instanceID, ifaces, pair, node, subs[0].Interface)
	if !ok {
		return nil, "DHCP on an HA pair: the DHCP servers talk over an interface with a static IPv4 address and its peer address; there is none"
	}
	h := &fwconfig.DHCPHA{Role: fwconfig.DHCPHAPrimary, Interface: iface, This: this, Peer: peer}
	if node == fwconfig.HASecondary {
		h.Role = fwconfig.DHCPHAStandby
	}
	return h, ""
}

// conntrackSync is the link an instance on an HA pair syncs its
// connections over: Kea's, or haLink's; nil when there is none.
func conntrackSync(in *fwconfig.Instance, instanceID uint, ifaces []models.Interface, pair map[uint][2][]string, node string) *fwconfig.ConntrackSync {
	if h := in.DHCP.HA; h != nil {
		return &fwconfig.ConntrackSync{Interface: h.Interface, This: h.This, Peer: h.Peer}
	}
	iface, this, peer, ok := haLink(instanceID, ifaces, pair, node, "")
	if !ok {
		return nil
	}
	return &fwconfig.ConntrackSync{Interface: iface, This: this, Peer: peer}
}

func cmpBool(a, b bool) int {
	switch {
	case a == b:
		return 0
	case a:
		return 1
	}
	return -1
}

// peerValues puts the HA secondary's values in place of what differs
// between the two hosts, for the instances of the primary: the
// interfaces' addresses, the VRRP priorities and the routers' ids.
func peerValues(d *data, primaryID uint, addf func(string, ...any)) {
	on := map[uint]string{}
	for _, in := range d.instances {
		if in.FirewallID == primaryID {
			on[in.ID] = in.Name
		}
	}
	// Delegated addresses are each host's own prefix; the peer addresses
	// stand for the others, in order. A disabled interface keeps its own.
	for i := range d.interfaces {
		ifc := &d.interfaces[i]
		name, ok := on[ifc.InstanceID]
		if !ok || !ifc.Enabled {
			continue
		}
		var static, delegated models.StringList
		for _, a := range ifc.Addresses {
			if fwconfig.IsDelegated(a) {
				delegated = append(delegated, a)
			} else {
				static = append(static, a)
			}
		}
		if len(static) == 0 {
			continue
		}
		if len(ifc.PeerAddresses) != len(static) {
			addf("%s: interface %s: the HA secondary needs an address of its own for each address (peer addresses)", name, ifc.Name)
			continue
		}
		for j, a := range static {
			pa, err1 := fwconfig.ParseInterfaceAddress(a)
			pb, err2 := fwconfig.ParseInterfaceAddress(ifc.PeerAddresses[j])
			// A host address (/32, /128: a loopback's) may be any other one.
			host := err1 == nil && err2 == nil && pa.Bits() == pa.Addr().BitLen() && pb.Bits() == pa.Bits() && pa.Addr().Is4() == pb.Addr().Is4()
			if err1 != nil || err2 != nil || (pa.Masked() != pb.Masked() && !host) || pa.Addr() == pb.Addr() {
				addf("%s: interface %s: peer address %s is not another address of %s", name, ifc.Name, ifc.PeerAddresses[j], a)
			}
		}
		ifc.Addresses = append(slices.Clone(ifc.PeerAddresses), delegated...)
	}
	for i := range d.vrrpRouters {
		r := &d.vrrpRouters[i]
		if _, ok := on[r.InstanceID]; !ok {
			continue
		}
		if r.PeerPriority != nil {
			r.Priority = *r.PeerPriority
		} else {
			r.Priority = max(1, min(r.Priority, 254)-10)
		}
	}
	for i := range d.bgpNeighbors {
		n := &d.bgpNeighbors[i]
		if _, ok := on[n.InstanceID]; ok && n.HAPeerAddress != "" {
			n.Address = n.HAPeerAddress
		}
	}
	for i := range d.bgpConfigs {
		c := &d.bgpConfigs[i]
		if name, ok := on[c.InstanceID]; ok && c.RouterID != "" {
			if c.PeerRouterID == "" {
				addf("%s: BGP: the HA secondary needs a router id of its own (peer router id)", name)
			}
			c.RouterID = c.PeerRouterID
		}
	}
	for i := range d.ospfConfigs {
		c := &d.ospfConfigs[i]
		if name, ok := on[c.InstanceID]; ok && c.RouterID != "" {
			if c.PeerRouterID == "" {
				addf("%s: OSPF: the HA secondary needs a router id of its own (peer router id)", name)
			}
			c.RouterID = c.PeerRouterID
		}
	}
	for i := range d.isisConfigs {
		c := &d.isisConfigs[i]
		if name, ok := on[c.InstanceID]; ok && c.Net != "" && c.NetInterface == "" {
			if c.PeerNet == "" {
				addf("%s: IS-IS: the HA secondary needs a NET of its own (peer NET)", name)
			}
			c.Net = c.PeerNet
		}
	}
}

// vrfByName is an instance's VRF of that name.
func (d *data) vrfByName(instanceID uint, name string) *models.Vrf {
	for i := range d.vrfs {
		if v := &d.vrfs[i]; v.InstanceID == instanceID && v.Name == name {
			return v
		}
	}
	return nil
}

// inVRF reports whether a row's VRF (id, nil for the main table) is vrf
// (nil for the main table).
func inVRF(id *uint, vrf *models.Vrf) bool {
	if vrf == nil {
		return id == nil
	}
	return id != nil && *id == vrf.ID
}

// ifaceInVRF reports whether an interface (link ends included) of the
// instance is in vrf (nil: in none). OSPF and IS-IS interfaces belong to
// the routing of their interface's VRF.
func (d *data) ifaceInVRF(instanceID uint, name string, vrf *models.Vrf) bool {
	for _, ifc := range d.interfaces {
		if ifc.InstanceID == instanceID && ifc.Name == name {
			if vrf == nil {
				return ifc.Vrf == ""
			}
			return ifc.Vrf == vrf.Name
		}
	}
	return vrf == nil // a link end
}

// bgp returns the BGP of the instance's main table (vrf nil) or a VRF
// when it is enabled, or nil.
func (d *data) bgp(instanceID uint, vrf *models.Vrf) *fwconfig.BGP {
	var cfg *models.BgpConfig
	for i := range d.bgpConfigs {
		if c := &d.bgpConfigs[i]; c.InstanceID == instanceID && inVRF(c.VrfID, vrf) {
			cfg = c
		}
	}
	if cfg == nil || !cfg.Enabled {
		return nil
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
		{cfg.RedistIsisV4, "ipv4", fwconfig.RedistISIS, cfg.RedistIsisV4Map},
		{cfg.RedistIsisV6, "ipv6", fwconfig.RedistISIS, cfg.RedistIsisV6Map},
	} {
		if r.on {
			b.Redistribute = append(b.Redistribute, fwconfig.BGPRedistribute{Family: r.family, Source: r.src, RouteMap: r.routeMap})
		}
	}
	for _, g := range d.bgpGroups {
		if g.InstanceID == instanceID && inVRF(g.VrfID, vrf) {
			p := g.Peer()
			p.Name = g.Name
			b.PeerGroups = append(b.PeerGroups, p)
		}
	}
	for _, n := range d.bgpNeighbors {
		if n.InstanceID == instanceID && n.Enabled && inVRF(n.VrfID, vrf) {
			p := n.Peer()
			p.Address, p.PeerGroup, p.Interface = n.Address, n.PeerGroup, n.Interface
			b.Neighbors = append(b.Neighbors, p)
		}
	}
	return b
}

// ospf returns the OSPF of a version of the instance's main table (vrf
// nil) or a VRF when it is enabled, or nil.
func (d *data) ospf(instanceID uint, version int, vrf *models.Vrf) *fwconfig.OSPF {
	var cfg *models.OspfConfig
	for i := range d.ospfConfigs {
		if c := &d.ospfConfigs[i]; c.InstanceID == instanceID && c.Version == version && inVRF(c.VrfID, vrf) {
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
		if ifc := &d.ospfIfaces[i]; ifc.InstanceID == instanceID && ifc.Version == version && d.ifaceInVRF(instanceID, ifc.Name, vrf) {
			o.Interfaces = append(o.Interfaces, ifc.Interface())
		}
	}
	return o
}

// isis returns the IS-IS of the instance's main table (vrf nil) or a VRF
// when it is enabled, or nil.
func (d *data) isis(instanceID uint, vrf *models.Vrf) *fwconfig.ISIS {
	var cfg *models.IsisConfig
	for i := range d.isisConfigs {
		if c := &d.isisConfigs[i]; c.InstanceID == instanceID && inVRF(c.VrfID, vrf) {
			cfg = c
		}
	}
	if cfg == nil || !cfg.Enabled {
		return nil
	}
	s := &fwconfig.ISIS{
		Enabled:             true,
		NET:                 cfg.Net,
		Level:               cfg.Level,
		MetricStyle:         cfg.MetricStyle,
		LogAdjacencyChanges: cfg.LogAdjacencyChanges,
		IPv6Topology:        cfg.IPv6Topology,
		Overload:            cfg.Overload,
		AreaPassword:        cfg.AreaPassword,
		AreaPasswordType:    cfg.AreaPasswordType,
		DomainPassword:      cfg.DomainPassword,
		DomainPasswordType:  cfg.DomainPasswordType,
		DefaultOriginate:    slices.Clone([]fwconfig.ISISDefault(cfg.DefaultOriginate)),
		Redistribute:        slices.Clone([]fwconfig.ISISRedistribute(cfg.Redistribute)),
	}
	if cfg.NetInterface != "" {
		// The NET follows the interface's IPv4 address; without one, the
		// NET made when it was saved.
		for _, ifc := range d.interfaces {
			if ifc.InstanceID == instanceID && ifc.Name == cfg.NetInterface {
				if net, ok := fwconfig.ISISNetFromAddresses(cfg.NetArea, ifc.Addresses); ok {
					s.NET = net
				}
			}
		}
	}
	for i := range d.isisIfaces {
		if ifc := &d.isisIfaces[i]; ifc.InstanceID == instanceID && d.ifaceInVRF(instanceID, ifc.Name, vrf) {
			s.Interfaces = append(s.Interfaces, ifc.Interface())
		}
	}
	return s
}

// routingPolicy adds the instance's routing policy objects, when FRR runs
// (BGP, OSPF or IS-IS): off, they stay out of the document.
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

// acmeProxy is an instance's ACME proxy, with its enabled policies (names
// expanded, DNS update clients copied in, interfaces by name).
func (d *data) acmeProxy(mi *models.Instance, in *fwconfig.Instance, prefixes func(where string, list []string) []string, addf func(string, ...any)) *fwconfig.ACMEProxy {
	x := &fwconfig.ACMEProxy{Port: mi.AcmeProxyPort, CA: mi.AcmeProxyCa, Email: mi.AcmeProxyEmail, Interfaces: []string{}, Policies: []fwconfig.ACMEProxyPolicy{}}
	for _, ifc := range in.Interfaces {
		if mif, ok := ifaceByName(d.interfaces, mi.ID, ifc.Name); ok && mif.AcmeProxyServe {
			x.Interfaces = append(x.Interfaces, ifc.Name)
		}
	}
	if id := mi.AcmeProxyCertificateID; id != nil {
		i := slices.IndexFunc(d.certs, func(c models.Certificate) bool { return c.ID == *id && c.InstanceID == mi.ID })
		switch {
		case i < 0:
			addf("instance %s: ACME proxy: its certificate is not in this instance", mi.Name)
		case !d.certs[i].Enabled:
			addf("instance %s: ACME proxy: its certificate %s is disabled", mi.Name, d.certs[i].Name)
		default:
			x.Certificate = d.certs[i].Name
		}
	}
	for _, p := range d.proxyPolicies {
		if p.InstanceID != mi.ID || !p.Enabled {
			continue
		}
		pol := fwconfig.ACMEProxyPolicy{
			Name: p.Name, Domains: slices.Clone([]string(p.Domains)),
			Sources: prefixes("instance "+mi.Name+": ACME proxy policy "+p.Name, p.Sources),
		}
		if p.Challenge == fwconfig.ChallengeHTTP01 {
			i := slices.IndexFunc(d.interfaces, func(ifc models.Interface) bool {
				return p.InterfaceID != nil && ifc.ID == *p.InterfaceID && ifc.InstanceID == mi.ID
			})
			if i < 0 {
				addf("instance %s: ACME proxy policy %s: its interface is not in this instance", mi.Name, p.Name)
				continue
			}
			pol.Challenge, pol.Interface = fwconfig.ChallengeHTTP01, d.interfaces[i].Name
		} else {
			i := slices.IndexFunc(d.dyndns, func(dc models.DyndnsClient) bool {
				return p.DyndnsClientID != nil && dc.ID == *p.DyndnsClientID && dc.InstanceID == mi.ID
			})
			if i < 0 {
				addf("instance %s: ACME proxy policy %s: its DNS update client is not in this instance", mi.Name, p.Name)
				continue
			}
			pol.Challenge, pol.DNS01 = fwconfig.ChallengeDNS01, DNS01(&d.dyndns[i])
		}
		x.Policies = append(x.Policies, pol)
	}
	return x
}

// DynDNS is a DNS update client with its records as the document holds
// it; iface is the name of its interface.
func DynDNS(c *models.DyndnsClient, iface string, records []models.DyndnsRecord) fwconfig.DynDNS {
	p := DNS01(c)
	d := fwconfig.DynDNS{
		Name: c.Name, Interface: iface, Provider: c.Provider, Zone: c.Zone,
		ProviderSettings: p.ProviderSettings, Server: p.Server, TSIG: p.TSIG,
		RetryInterval: c.RetryInterval, VerifyInterval: c.VerifyInterval,
		Records: []fwconfig.DynDNSRecord{},
	}
	for _, r := range records {
		d.Records = append(d.Records, fwconfig.DynDNSRecord{Name: r.Name, Type: r.Type, TTL: r.Ttl, Value: r.Value})
	}
	return d
}

// DNS01 is a DNS update client's provider and zone, as a certificate's
// DNS-01 challenge uses them. The client need not be enabled: one that
// only holds the credentials for certificates can be off.
func DNS01(c *models.DyndnsClient) *fwconfig.DNS01 {
	d := &fwconfig.DNS01{Client: c.Name, Provider: c.Provider, Zone: c.Zone}
	if c.Provider == "" || c.Provider == fwconfig.ProviderRFC2136 {
		d.Server = c.Server
		if c.TsigName != "" {
			d.TSIG = &fwconfig.TSIG{Name: c.TsigName, Algorithm: c.TsigAlgorithm, Secret: c.TsigSecret}
		}
	} else {
		d.ProviderSettings = maps.Clone(map[string]string(c.ProviderSettings))
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

// resolvePortNames writes the custom port names in a port list ("web, 443")
// as their numbers; numbers, ranges and built-in names are left as they are.
func resolvePortNames(ports string, names map[string]int) string {
	if ports == "" || len(names) == 0 {
		return ports
	}
	parts := strings.Split(ports, ",")
	for i, part := range parts {
		if p, ok := names[strings.ToLower(strings.TrimSpace(part))]; ok {
			parts[i] = strconv.Itoa(p)
		}
	}
	return strings.Join(parts, ",")
}
