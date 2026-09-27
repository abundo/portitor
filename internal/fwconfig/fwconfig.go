// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package fwconfig is the desired-state document exchanged between
// portitor-web (which builds it from the database) and portitor-agent (which
// renders and applies it on the firewall). The agent never reads the web
// database; this document is the whole contract.
//
// Every virtual instance is a Linux network namespace with its own
// interfaces, routing table, nftables ruleset, DNS and DHCP server. The
// default instance is the root namespace. Links are veth pairs between two
// instances.
package fwconfig

// Version of the document format. Bump when a field changes meaning.
const Version = 1

type Document struct {
	Version    int        `json:"version"`
	Generation int64      `json:"generation"` // monotonic deploy id, set by portitor-web
	Instances  []Instance `json:"instances"`
	Links      []Link     `json:"links"`
}

type Instance struct {
	Name       string      `json:"name"`
	Default    bool        `json:"default"` // root network namespace
	Interfaces []Interface `json:"interfaces"`
	Zones      []Zone      `json:"zones"`
	Rules      []Rule      `json:"rules"`
	NAT        []NATRule   `json:"nat"`
	Routes     []Route     `json:"routes"`
	DHCP       DHCPServer  `json:"dhcp"`
	DNS        DNSServer   `json:"dns"`
	// RA lists the interfaces that send IPv6 router advertisements.
	RA []RAInterface `json:"ra,omitempty"`
}

// Interface kinds.
const (
	KindPhysical  = "physical"
	KindVLAN      = "vlan"
	KindBridge    = "bridge"
	KindWireGuard = "wireguard"
	KindLink      = "link" // one end of a veth Link, generated from Document.Links
)

// IPv4 addressing modes.
const (
	ModeStatic = "static"
	ModeDHCP   = "dhcp"
	ModeNone   = "none"
)

type Interface struct {
	Name        string   `json:"name"`
	Kind        string   `json:"kind"`
	Description string   `json:"description,omitempty"`
	Enabled     bool     `json:"enabled"`
	Parent      string   `json:"parent,omitempty"`  // vlan
	VLANID      int      `json:"vlan_id,omitempty"` // vlan
	Members     []string `json:"members,omitempty"` // bridge
	MTU         int      `json:"mtu,omitempty"`
	Zone        string   `json:"zone,omitempty"`
	IPv4Mode    string   `json:"ipv4_mode"`
	// Addresses are static addresses in CIDR form (192.168.1.1/24,
	// 2001:db8::1/64). IPv6 addresses are always static here; IPv6AcceptRA
	// adds SLAAC on top.
	Addresses    []string   `json:"addresses,omitempty"`
	IPv6AcceptRA bool       `json:"ipv6_accept_ra,omitempty"`
	WireGuard    *WireGuard `json:"wireguard,omitempty"`
}

type WireGuard struct {
	PrivateKey string   `json:"private_key"`
	ListenPort int      `json:"listen_port,omitempty"`
	Peers      []WGPeer `json:"peers"`
}

type WGPeer struct {
	Name         string   `json:"name"`
	PublicKey    string   `json:"public_key"`
	PresharedKey string   `json:"preshared_key,omitempty"`
	Endpoint     string   `json:"endpoint,omitempty"`
	AllowedIPs   []string `json:"allowed_ips"`
	Keepalive    int      `json:"keepalive,omitempty"`
}

// Zone input policies.
const (
	ActionAccept = "accept"
	ActionDrop   = "drop"
	ActionReject = "reject"
)

// Zone groups interfaces for filtering. Traffic to the firewall itself from
// a zone hits that zone's input rules, then InputPolicy. Forwarded traffic
// is dropped unless a forward rule accepts it. Masquerade source-NATs
// everything leaving through the zone (typical for WAN).
type Zone struct {
	Name        string `json:"name"`
	InputPolicy string `json:"input_policy"`
	Masquerade  bool   `json:"masquerade,omitempty"`
}

// Rule chains.
const (
	ChainInput   = "input"
	ChainForward = "forward"
	ChainOutput  = "output"
)

// Rule is one filter rule, evaluated in slice order within its chain.
// Empty match fields match anything. Address lists may mix IPv4 and IPv6;
// the rule is then rendered once per IP version, each with that version's
// addresses. A version is left out when a non-empty list has none of its
// addresses (Family and an icmp/icmpv6 Protocol narrow it further).
type Rule struct {
	Chain       string   `json:"chain"`
	SrcZone     string   `json:"src_zone,omitempty"`
	DstZone     string   `json:"dst_zone,omitempty"`
	Family      string   `json:"family,omitempty"`   // "", ipv4, ipv6
	Protocol    string   `json:"protocol,omitempty"` // "", tcp, udp, icmp, icmpv6
	SrcAddrs    []string `json:"src_addrs,omitempty"`
	DstAddrs    []string `json:"dst_addrs,omitempty"`
	DstPorts    string   `json:"dst_ports,omitempty"` // "22", "80,443", "1000-2000"
	Action      string   `json:"action"`
	Log         bool     `json:"log,omitempty"`
	Description string   `json:"description,omitempty"`
}

// NAT kinds.
const (
	NATMasquerade = "masquerade"
	NATSNAT       = "snat"
	NATDNAT       = "dnat"
)

// NATRule is an explicit NAT rule. Zone masquerade covers the common case;
// use this for port forwards (dnat) and fixed source addresses (snat).
// snat/dnat match only addresses of ToAddr's IP version. Masquerade
// applies to the versions in its address lists, IPv4 when they are empty.
type NATRule struct {
	Kind        string   `json:"kind"`
	InZone      string   `json:"in_zone,omitempty"`  // dnat
	OutZone     string   `json:"out_zone,omitempty"` // snat, masquerade
	Protocol    string   `json:"protocol,omitempty"` // tcp, udp; required with ports
	SrcAddrs    []string `json:"src_addrs,omitempty"`
	DstAddrs    []string `json:"dst_addrs,omitempty"`
	DstPorts    string   `json:"dst_ports,omitempty"`
	ToAddr      string   `json:"to_addr,omitempty"`
	ToPort      int      `json:"to_port,omitempty"`
	Description string   `json:"description,omitempty"`
}

type Route struct {
	Destination string `json:"destination"` // CIDR, or "default"
	Gateway     string `json:"gateway,omitempty"`
	Interface   string `json:"interface,omitempty"`
	Metric      int    `json:"metric,omitempty"`
}

type DHCPServer struct {
	Enabled    bool         `json:"enabled"`
	DomainName string       `json:"domain_name,omitempty"`
	LeaseTime  int          `json:"lease_time,omitempty"` // seconds
	Subnets    []DHCPSubnet `json:"subnets"`
}

// DHCPSubnet is served on Interface: IPv4 prefixes by Kea DHCPv4 through
// dnsmgr2, IPv6 prefixes by Kea DHCPv6. Reservations come from DNS A/AAAA
// records that carry a MAC (dnsmgr2 convention). IPv6 subnets have no
// Gateway; clients learn the router from router advertisements.
type DHCPSubnet struct {
	Prefix     string   `json:"prefix"`
	Interface  string   `json:"interface"`
	RangeStart string   `json:"range_start,omitempty"`
	RangeEnd   string   `json:"range_end,omitempty"`
	Gateway    string   `json:"gateway,omitempty"`
	DNSServers []string `json:"dns_servers,omitempty"`
}

// RAInterface makes the instance send IPv6 router advertisements on
// Interface (radvd), announcing itself as the default router.
type RAInterface struct {
	Interface string     `json:"interface"`
	Prefixes  []RAPrefix `json:"prefixes,omitempty"`
	// Managed (M flag) tells clients to get addresses from DHCPv6.
	Managed bool `json:"managed,omitempty"`
	// Other (O flag) tells clients to get other settings (DNS) from DHCPv6.
	Other bool `json:"other,omitempty"`
	// RDNSS and DNSSL announce DNS servers and search domains (RFC 8106).
	RDNSS []string `json:"rdnss,omitempty"`
	DNSSL []string `json:"dnssl,omitempty"`
}

// RAPrefix is an on-link prefix. Autonomous lets clients configure their
// own addresses in it (SLAAC); that needs a /64.
type RAPrefix struct {
	Prefix     string `json:"prefix"`
	Autonomous bool   `json:"autonomous,omitempty"`
}

type DNSServer struct {
	Enabled bool `json:"enabled"`
	// Forwarders are upstream resolvers. ForwardFromDHCP adds the servers
	// learned by the DHCP client on this instance's WAN interfaces.
	Forwarders      []string `json:"forwarders,omitempty"`
	ForwardFromDHCP bool     `json:"forward_from_dhcp,omitempty"`
	// ListenInterfaces are the interfaces BIND answers on (their addresses).
	ListenInterfaces []string `json:"listen_interfaces,omitempty"`
	// AllowRecursion lists client CIDRs allowed to recurse. Empty means the
	// prefixes of the listen interfaces.
	AllowRecursion []string  `json:"allow_recursion,omitempty"`
	Zones          []DNSZone `json:"zones"`
	// Templates the zones refer to by name. A zone without a template
	// gets a built-in SOA and NS pointing at localhost.
	SOATemplates   []DNSSOATemplate  `json:"soa_templates,omitempty"`
	ZoneTemplates  []DNSZoneTemplate `json:"zone_templates,omitempty"`
	DNSSECPolicies []DNSSECPolicy    `json:"dnssec_policies,omitempty"`
}

// DNSSOATemplate is the SOA of every zone whose template uses it. The
// serial is dnsmgr2's (date based).
type DNSSOATemplate struct {
	Name    string `json:"name"`
	MName   string `json:"mname"` // primary nameserver
	RName   string `json:"rname"` // mailbox, hostmaster.example.com
	Refresh int64  `json:"refresh"`
	Retry   int64  `json:"retry"`
	Expire  int64  `json:"expire"`
	Minimum int64  `json:"minimum"` // negative-caching TTL
}

// DNSZoneTemplate gives a zone its SOA, default TTL, apex NS records and,
// optionally, a DNSSEC policy (the zone is then signed inline by BIND).
type DNSZoneTemplate struct {
	Name         string   `json:"name"`
	SOA          string   `json:"soa"`
	DefaultTTL   int64    `json:"default_ttl"`
	Nameservers  []string `json:"nameservers"`
	DNSSECPolicy string   `json:"dnssec_policy,omitempty"`
}

// DNSSECPolicy is a BIND dnssec-policy. Durations are BIND's (ISO 8601
// like P1Y, or 30d); empty ones keep BIND's defaults.
type DNSSECPolicy struct {
	Name                     string `json:"name"`
	KSKLifetime              string `json:"ksk_lifetime,omitempty"`
	KSKAlgorithm             string `json:"ksk_algorithm"`
	ZSKLifetime              string `json:"zsk_lifetime,omitempty"`
	ZSKAlgorithm             string `json:"zsk_algorithm"`
	PurgeKeys                string `json:"purge_keys,omitempty"`
	SignaturesValidity       string `json:"signatures_validity,omitempty"`
	SignaturesValidityDNSKEY string `json:"signatures_validity_dnskey,omitempty"`
	SignaturesRefresh        string `json:"signatures_refresh,omitempty"`
}

// DNSSECAlgorithms are the key algorithms a DNSSECPolicy may use.
var DNSSECAlgorithms = []string{"ecdsap256sha256", "ecdsap384sha384", "ed25519", "ed448", "rsasha256", "rsasha512"}

// ZoneTemplate returns the named zone template, or nil.
func (d *DNSServer) ZoneTemplate(name string) *DNSZoneTemplate {
	for i := range d.ZoneTemplates {
		if d.ZoneTemplates[i].Name == name {
			return &d.ZoneTemplates[i]
		}
	}
	return nil
}

// DNS zone types (same names as dnsmgr2).
const (
	ZoneForward  = "forward"
	ZoneReverse4 = "reverse4"
	ZoneReverse6 = "reverse6"
)

type DNSZone struct {
	Name     string      `json:"name"` // domain, or CIDR for reverse zones
	Type     string      `json:"type"`
	Template string      `json:"template,omitempty"` // a ZoneTemplates name
	Records  []DNSRecord `json:"records,omitempty"`  // forward zones only
}

type DNSRecord struct {
	Name  string `json:"name"`
	TTL   int64  `json:"ttl,omitempty"`
	Type  string `json:"type"`
	Value string `json:"value"`
	MAC   string `json:"mac,omitempty"` // A/AAAA: DHCP reservation
}

// Link is a point-to-point veth pair between two instances.
type Link struct {
	Name string  `json:"name"`
	A    LinkEnd `json:"a"`
	B    LinkEnd `json:"b"`
}

type LinkEnd struct {
	Instance  string   `json:"instance"`
	Interface string   `json:"interface"`
	Addresses []string `json:"addresses,omitempty"`
	Zone      string   `json:"zone,omitempty"`
}

// Instance returns the named instance, or nil.
func (d *Document) Instance(name string) *Instance {
	for i := range d.Instances {
		if d.Instances[i].Name == name {
			return &d.Instances[i]
		}
	}
	return nil
}

// Interface returns the named interface, or nil.
func (in *Instance) Interface(name string) *Interface {
	for i := range in.Interfaces {
		if in.Interfaces[i].Name == name {
			return &in.Interfaces[i]
		}
	}
	return nil
}

// Expand returns a copy of the document where each Link end appears as a
// KindLink interface in its instance, so renderers only deal with
// interfaces.
func (d Document) Expand() Document {
	out := d
	out.Instances = make([]Instance, len(d.Instances))
	for i, in := range d.Instances {
		cp := in
		cp.Interfaces = append([]Interface(nil), in.Interfaces...)
		out.Instances[i] = cp
	}
	for _, l := range d.Links {
		for _, end := range []LinkEnd{l.A, l.B} {
			if in := out.Instance(end.Instance); in != nil {
				in.Interfaces = append(in.Interfaces, Interface{
					Name:        end.Interface,
					Kind:        KindLink,
					Description: "link " + l.Name,
					Enabled:     true,
					Zone:        end.Zone,
					IPv4Mode:    ModeStatic,
					Addresses:   end.Addresses,
				})
			}
		}
	}
	return out
}

// NetnsName is the network namespace an instance lives in; "" for the
// default instance (root namespace).
func (in *Instance) NetnsName() string {
	if in.Default {
		return ""
	}
	return "fw-" + in.Name
}
