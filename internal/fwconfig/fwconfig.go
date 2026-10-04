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

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
)

// Version of the document format. Bump when a field changes meaning.
const Version = 3

type Document struct {
	Version    int        `json:"version"`
	Generation int64      `json:"generation"` // monotonic deploy id, set by portitor-web
	Instances  []Instance `json:"instances"`
	Links      []Link     `json:"links"`
	// IPLists are address lists the agent downloads (CrowdSec, or a URL
	// with one address per line). Rules refer to one as "@name"; it
	// becomes an nftables set in each instance whose rules use it.
	IPLists []IPList `json:"ip_lists,omitempty"`
	// Tasks run on the firewall on a cron schedule.
	Tasks []Task `json:"tasks,omitempty"`
}

type Instance struct {
	Name       string      `json:"name"`
	Default    bool        `json:"default"` // root network namespace
	Interfaces []Interface `json:"interfaces"`
	// InterfaceZones name groups of interfaces for rules to match on.
	InterfaceZones []InterfaceZone `json:"interface_zones"`
	Rules          []Rule          `json:"rules"`
	// RateLimits are the rate limits the rules name (Rule.RateLimit).
	RateLimits []RateLimit `json:"rate_limits,omitempty"`
	NAT        []NATRule   `json:"nat"`
	Routes     []Route     `json:"routes"`
	DHCP       DHCPServer  `json:"dhcp"`
	DNS        DNSServer   `json:"dns"`
	// RA lists the interfaces that send IPv6 router advertisements.
	RA []RAInterface `json:"ra,omitempty"`
	// DynDNS clients keep records on a nameserver in step with the
	// addresses of this instance's interfaces.
	DynDNS []DynDNS `json:"dyndns,omitempty"`
	// Certificates are TLS certificates the agent gets and renews by
	// ACME (Let's Encrypt).
	Certificates []Certificate `json:"certificates,omitempty"`
	// BGP runs FRR in the instance; nil when it is off.
	BGP *BGP `json:"bgp,omitempty"`
	// OSPF (OSPFv2, IPv4) and OSPF6 (OSPFv3, IPv6) run FRR's ospfd and
	// ospf6d in the instance; nil when off.
	OSPF  *OSPF `json:"ospf,omitempty"`
	OSPF6 *OSPF `json:"ospf6,omitempty"`
	// RoutingPolicy holds the prefix lists, AS path and community lists
	// and route maps BGP and OSPF refer to.
	RoutingPolicy RoutingPolicy `json:"routing_policy,omitzero"`
	// LogDrops lists the filter chains (ChainInput, ...) that log, rate
	// limited, what no rule decided on before the chain's policy drops it.
	LogDrops []string `json:"log_drops,omitempty"`
	// LogInvalid lists the filter chains that log, rate limited, the
	// invalid packets (of no known connection) they drop.
	LogInvalid []string `json:"log_invalid,omitempty"`
	// LogAuto lists the auto input rules (by service: "dhcp server",
	// "wireguard wg0", "anti-lockout") that log, rate limited, what they
	// accept. A service the instance doesn't have is ignored.
	LogAuto []string `json:"log_auto,omitempty"`
}

// Interface kinds.
const (
	KindPhysical  = "physical"
	KindVLAN      = "vlan"
	KindBridge    = "bridge"
	KindWireGuard = "wireguard"
	KindLoopback  = "loopback" // a dummy interface for addresses that stay up (router id, BGP update source)
	KindLink      = "link"     // one end of a veth Link, generated from Document.Links
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
	IPv4Mode    string   `json:"ipv4_mode"`
	// DHCPNoDefaultRoute makes the DHCP client ignore the lease's router
	// (a LAN on DHCP: the default route belongs to the WAN).
	DHCPNoDefaultRoute bool `json:"dhcp_no_default_route,omitempty"`
	// Addresses are static addresses in CIDR form with a host part
	// (192.168.1.1/24, 2001:db8::1/64; ParseInterfaceAddress). IPv6
	// addresses are always static here; IPv6AcceptRA adds SLAAC on top.
	// An IPv6 address may also be relative to a prefix delegated to
	// another interface of the instance ("<wan0>:2000::1/64",
	// Delegated); the agent resolves it (Document.ResolveDelegated).
	Addresses    []string `json:"addresses,omitempty"`
	IPv6AcceptRA bool     `json:"ipv6_accept_ra,omitempty"`
	// DHCPv6 runs a DHCPv6 client that asks for an address (IA_NA) and,
	// with DHCPv6PD, for a delegated prefix (IA_PD), of DHCPv6PDLength
	// bits as a hint to the server (0: no hint). The default route comes
	// from router advertisements (IPv6AcceptRA).
	DHCPv6         bool `json:"dhcpv6,omitempty"`
	DHCPv6PD       bool `json:"dhcpv6_pd,omitempty"`
	DHCPv6PDLength int  `json:"dhcpv6_pd_length,omitempty"`
	// LLDP makes the agent send LLDP frames on the interface and listen
	// for its neighbours' (ethernet kinds: physical, VLAN, bridge).
	LLDP bool `json:"lldp,omitempty"`
	// ShapeEgress and ShapeIngress shape what the interface sends and
	// receives to that many Mbit/s with CAKE (0: not shaped). Receiving
	// is shaped on an IFB device (IFBName) the interface's traffic is
	// redirected to.
	ShapeEgress  int        `json:"shape_egress,omitempty"`
	ShapeIngress int        `json:"shape_ingress,omitempty"`
	WireGuard    *WireGuard `json:"wireguard,omitempty"`
}

// MaxShapeMbit bounds an interface's shaped bandwidth (Mbit/s).
const MaxShapeMbit = 400000

// IFBPrefix starts the names of the IFB devices that shape what an
// interface receives; no interface may be called that.
const IFBPrefix = "ifb-"

// IFBName is the IFB device that shapes what interface name receives:
// "ifb-" and the name, or a hash of it when that is too long.
func IFBName(name string) string {
	if len(IFBPrefix)+len(name) <= 15 {
		return IFBPrefix + name
	}
	sum := sha256.Sum256([]byte(name))
	return IFBPrefix + hex.EncodeToString(sum[:])[:11]
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
	// Networks are the networks behind a site peer. They are allowed
	// IPs too, and the agent routes them through the interface
	// (WireGuardRoutes); AllowedIPs are not routed.
	Networks  []string `json:"networks,omitempty"`
	Keepalive int      `json:"keepalive,omitempty"`
}

// AllAllowedIPs is the peer's AllowedIPs followed by its Networks, without
// duplicates: what wg(8) gets.
func (p *WGPeer) AllAllowedIPs() []string {
	out := slices.Clone(p.AllowedIPs)
	for _, n := range p.Networks {
		if !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	return out
}

// Rule actions.
const (
	ActionAccept = "accept"
	ActionDrop   = "drop"
	ActionReject = "reject"
)

// InterfaceZone is a named group of interfaces of its instance. Rules and
// NAT rules may name it wherever they list interfaces. A zone may be empty;
// a rule whose interface list then matches no enabled interface is skipped,
// never widened to match any interface.
type InterfaceZone struct {
	Name       string   `json:"name"`
	Interfaces []string `json:"interfaces"`
}

// Rule chains.
const (
	ChainInput   = "input"
	ChainForward = "forward"
	ChainOutput  = "output"
)

// Rule is one filter rule, evaluated in slice order within its chain.
// Empty match fields match anything. SrcAddrs and DstAddrs may also hold
// IP list references ("@name"), which match either IP version. InInterfaces/OutInterfaces hold
// interface and InterfaceZone names of the instance. Address lists may mix IPv4 and IPv6;
// the rule is then rendered once per IP version, each with that version's
// addresses. A version is left out when a non-empty list has none of its
// addresses (Family and an icmp/icmpv6 Protocol narrow it further).
type Rule struct {
	// ID identifies the rule across deployments (portitor-web's database
	// id). A rule with an ID gets named nftables counters and marks the
	// connections it accepts with it, so their traffic is counted under
	// the rule (render.RuleCounter); 0 is a plain counter. IDs are unique
	// in the document and not set on comment rows.
	ID    uint32 `json:"id,omitempty"`
	Chain string `json:"chain"`
	// Kind is empty for a rule or RuleKindComment for a comment row, which
	// has only Chain and Description and is rendered as a rule that holds
	// nothing but an nft comment.
	Kind string `json:"kind,omitempty"`
	// InInterfaces match the incoming interface (not for output rules),
	// OutInterfaces the outgoing one (not for input rules).
	InInterfaces  []string `json:"in_interfaces,omitempty"`
	OutInterfaces []string `json:"out_interfaces,omitempty"`
	Family        string   `json:"family,omitempty"` // "", ipv4, ipv6
	SrcAddrs      []string `json:"src_addrs,omitempty"`
	DstAddrs      []string `json:"dst_addrs,omitempty"`
	// Services are the protocol matches of the rule, of which a packet
	// must match one; empty matches any protocol.
	Services []ServiceMatch `json:"services,omitempty"`
	Action   string         `json:"action"`
	Log      bool           `json:"log,omitempty"`
	// RateLimit names one of the instance's RateLimits, which limits or
	// shapes the rule's traffic (RateLimit).
	RateLimit   string `json:"rate_limit,omitempty"`
	Description string `json:"description,omitempty"`
}

// RateLimit is a token bucket: Rate units per Per, with Burst units
// above it allowed at once (0: nftables' default). The rules that name it
// share it; PerSource keeps a bucket for each source address instead of
// one for all.
//
// Without Connections it polices the packets a rule matches, dropping
// what is over the limit before the rule: established connections are
// accepted before the rules, so on an accept rule it limits new
// connections. With Connections it polices all the traffic, both ways, of the
// connections the rules accept (by their ct mark, before the established
// accept), and drops what is over the limit; a rule naming it must be an
// accept rule with an ID. Byte and bit units need Connections.
//
// With Shape it queues instead: the traffic of the connections the rules
// accept is held to Rate (bytes or bits per second), in each direction,
// where it leaves the firewall: an HTB class on each interface of the
// instance, which the packets reach by their mark (render.ShaperMark).
// A rule naming it must be an accept rule with an ID; Per is second, and
// Burst, PerSource and Connections are not set.
type RateLimit struct {
	Name        string `json:"name"`
	Rate        int    `json:"rate"`
	Unit        string `json:"unit,omitempty"` // RateUnit*; "" is packets
	Per         string `json:"per"`            // RatePer*
	Burst       int    `json:"burst,omitempty"`
	PerSource   bool   `json:"per_source,omitempty"`
	Connections bool   `json:"connections,omitempty"`
	Shape       bool   `json:"shape,omitempty"`
}

// Rate limit units besides packets (""): bytes and bits (k and m are
// 1000 and 1000000).
const (
	RateUnitBytes  = "bytes"
	RateUnitKBytes = "kbytes"
	RateUnitMBytes = "mbytes"
	RateUnitKBit   = "kbit"
	RateUnitMBit   = "mbit"
)

// MaxShapers bounds the rate limits of an instance that shape (marks and
// HTB classes).
const MaxShapers = 200

// Marks reports whether the limit needs the connections of the rules
// that name it marked: it polices or shapes them.
func (l RateLimit) Marks() bool { return l.Connections || l.Shape }

// Bits is the rate in bits per second, for a limit in bytes or bits.
func (l RateLimit) Bits() int64 {
	n := int64(l.Rate)
	switch l.Unit {
	case RateUnitBytes:
		return n * 8
	case RateUnitKBytes:
		return n * 8000
	case RateUnitMBytes:
		return n * 8000000
	case RateUnitKBit:
		return n * 1000
	case RateUnitMBit:
		return n * 1000000
	}
	return 0
}

// Shapers returns the rate limits that shape, when a rule names one;
// nil otherwise. A shaper's index in it numbers its mark and class.
func (in *Instance) Shapers() []RateLimit {
	used := false
	var out []RateLimit
	for _, l := range in.RateLimits {
		if !l.Shape {
			continue
		}
		out = append(out, l)
		for _, r := range in.Rules {
			used = used || r.RateLimit == l.Name
		}
	}
	if !used {
		return nil
	}
	return out
}

// Rate limit periods.
const (
	RatePerSecond = "second"
	RatePerMinute = "minute"
	RatePerHour   = "hour"
	RatePerDay    = "day"
)

// MaxRate bounds a rate limit's rate and burst.
const MaxRate = 1000000

// ServiceMatch is one protocol match of a rule. portitor-web expands the
// services a rule names into these.
type ServiceMatch struct {
	// Protocol is tcp, udp or sctp (with ports), icmp or icmpv6 (with a
	// type and code), or ip (with a protocol number).
	Protocol string `json:"protocol"`
	// DstPorts and SrcPorts are port lists ("22", "1000-2000"); empty
	// matches any.
	DstPorts string `json:"dst_ports,omitempty"`
	SrcPorts string `json:"src_ports,omitempty"`
	// ICMPType is an ICMP or ICMPv6 type by name (ICMPTypes, ICMPv6Types)
	// and ICMPCode its code; empty or nil matches any. A code needs a type.
	ICMPType string `json:"icmp_type,omitempty"`
	ICMPCode *int   `json:"icmp_code,omitempty"`
	// IPProtocol is an IP protocol number (1-255) with protocol ip; 0
	// matches any.
	IPProtocol int `json:"ip_protocol,omitempty"`
}

// Service match protocols.
const (
	ProtoTCP    = "tcp"
	ProtoUDP    = "udp"
	ProtoSCTP   = "sctp"
	ProtoICMP   = "icmp"
	ProtoICMPv6 = "icmpv6"
	ProtoIP     = "ip"
)

// HasPorts reports whether the match's protocol has ports.
func (s ServiceMatch) HasPorts() bool {
	return s.Protocol == ProtoTCP || s.Protocol == ProtoUDP || s.Protocol == ProtoSCTP
}

// RuleKindComment marks a Rule that is a comment row.
const RuleKindComment = "comment"

// NAT kinds.
const (
	NATMasquerade = "masquerade"
	NATSNAT       = "snat"
	NATDNAT       = "dnat"
)

// NATRule is a NAT rule: masquerade for Internet sharing, port forwards
// (dnat) and fixed source addresses (snat). Interface lists are as in Rule.
// snat/dnat match only addresses of ToAddr's IP version. Masquerade
// applies to the versions in its address lists, IPv4 when they are empty.
type NATRule struct {
	Kind          string   `json:"kind"`
	InInterfaces  []string `json:"in_interfaces,omitempty"`  // dnat
	OutInterfaces []string `json:"out_interfaces,omitempty"` // snat, masquerade
	Protocol      string   `json:"protocol,omitempty"`       // tcp, udp, tcp,udp; required with ports
	SrcAddrs      []string `json:"src_addrs,omitempty"`
	DstAddrs      []string `json:"dst_addrs,omitempty"`
	DstPorts      string   `json:"dst_ports,omitempty"`
	ToAddr        string   `json:"to_addr,omitempty"`
	ToPort        int      `json:"to_port,omitempty"`
	// Hairpin (dnat) also forwards connections from the other interfaces
	// to the firewall's own addresses, masqueraded so replies come back
	// through the firewall.
	Hairpin     bool   `json:"hairpin,omitempty"`
	Description string `json:"description,omitempty"`
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

// DHCPSubnet is served on Interface by Kea DHCPv4 or DHCPv6. The subnets
// of one IP version on the same interface form a Kea shared network, so
// clients get addresses from all of them. Reservations come from DNS
// A/AAAA records that carry a MAC (dnsmgr2 convention). IPv6 subnets have
// no Gateway; clients learn the router from router advertisements.
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

// DNSServer.Upstream values: where BIND sends the queries it can't
// answer from its own zones.
const (
	UpstreamForward = "forward" // the Forwarders ("" too)
	UpstreamRoot    = "root"    // resolve from the root servers
	UpstreamDHCP    = "dhcp"    // the DNS servers of DHCPInterface's lease
)

// DNSServer.ForwardMode values.
const (
	ForwardFirst = "first" // forwarders, falling back to the root servers ("" too)
	ForwardOnly  = "only"  // forwarders only
	// ForwardOff ignores the forwarders: resolve from the root servers.
	// Documents from before Upstream use it; new ones say UpstreamRoot.
	ForwardOff = "off"
)

// DNSServer.DNSSECValidation values, as BIND's dnssec-validation.
const (
	DNSSECValidationAuto = "auto" // validate with the built-in root key ("" too)
	DNSSECValidationNo   = "no"
)

type DNSServer struct {
	Enabled bool `json:"enabled"`
	// Upstream picks the forwarders: Forwarders, the DNS servers of the
	// DHCP lease on DHCPInterface (an IPv4 DHCP client interface), or none.
	// ForwardMode says how they are used; with no forwarders BIND resolves
	// from the root servers (its built-in hints).
	Upstream      string   `json:"upstream,omitempty"`
	Forwarders    []string `json:"forwarders,omitempty"`
	DHCPInterface string   `json:"dhcp_interface,omitempty"`
	ForwardMode   string   `json:"forward_mode,omitempty"`
	// ForwardFromDHCP, in documents from before Upstream, adds the DNS
	// servers of every DHCP lease of the instance to the Forwarders.
	ForwardFromDHCP bool `json:"forward_from_dhcp,omitempty"`
	// ListenInterfaces are the interfaces BIND answers on (their addresses).
	ListenInterfaces []string `json:"listen_interfaces,omitempty"`
	// AllowRecursion lists client CIDRs allowed to recurse. Empty means the
	// prefixes of the listen interfaces.
	AllowRecursion []string `json:"allow_recursion,omitempty"`
	// DNSSECValidation is DNSSECValidationAuto or DNSSECValidationNo.
	DNSSECValidation string `json:"dnssec_validation,omitempty"`
	// QueryLog, when set, logs the queries BIND answers; the agent keeps
	// those that pass its filters for the GUI's log panel.
	QueryLog *DNSQueryLog `json:"query_log,omitempty"`
	Zones    []DNSZone    `json:"zones"`
	// Templates the zones refer to by name. A zone without a template
	// gets a built-in SOA and NS pointing at localhost.
	SOATemplates   []DNSSOATemplate  `json:"soa_templates,omitempty"`
	ZoneTemplates  []DNSZoneTemplate `json:"zone_templates,omitempty"`
	DNSSECPolicies []DNSSECPolicy    `json:"dnssec_policies,omitempty"`
}

// DNSQueryLog filters the logged queries. Each empty list matches any
// query; a query is kept when it matches all three.
type DNSQueryLog struct {
	Clients []string `json:"clients,omitempty"` // client CIDRs
	// Names are domains: a query for one of them or a name below it.
	Names []string `json:"names,omitempty"`
	Types []string `json:"types,omitempty"` // query types: A, AAAA, MX, ...
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
	// ZoneForwardOnly is not served: BIND forwards its queries to the
	// zone's Forwarders (rendered in named.conf, not by dnsmgr2).
	ZoneForwardOnly = "forward-only"
)

type DNSZone struct {
	Name     string      `json:"name"` // domain, or CIDR for reverse zones
	Type     string      `json:"type"`
	Template string      `json:"template,omitempty"` // a ZoneTemplates name
	Records  []DNSRecord `json:"records,omitempty"`  // forward zones only
	// Forwarders are the DNS servers of a forward-only zone.
	Forwarders []string `json:"forwarders,omitempty"`
}

type DNSRecord struct {
	Name  string `json:"name"`
	TTL   int64  `json:"ttl,omitempty"`
	Type  string `json:"type"`
	Value string `json:"value"`
	MAC   string `json:"mac,omitempty"` // A/AAAA: DHCP reservation
}

// DynDNS is a DNS update client: whenever Interface's addresses change
// it updates the records, by RFC 2136 UPDATE to Server (ifnsupdate), sent
// from inside the instance, or through the API of a DNS hosting Provider
// (libdns), called from the host. A and AAAA records without a Value get the interface's first
// global address of that family; records with a Value, and CNAMEs, are
// static and re-verified every VerifyInterval. A TXT record without a
// Value holds the time of the last update.
type DynDNS struct {
	Name      string `json:"name"`
	Interface string `json:"interface"`
	// Provider is a DNSProviders name; empty is RFC 2136.
	Provider string `json:"provider,omitempty"`
	// ProviderSettings are the provider's fields (DNSProvider.Fields), by
	// key, secrets included.
	ProviderSettings map[string]string `json:"provider_settings,omitempty"`
	// Server is the zone's primary nameserver (RFC 2136 only): an IP
	// address, with an optional port (192.0.2.53, [2001:db8::53]:5353).
	Server string `json:"server,omitempty"`
	Zone   string `json:"zone"`
	TSIG   *TSIG  `json:"tsig,omitempty"`
	// RetryInterval (after a failed update) and VerifyInterval (of the
	// static records) are in seconds; 0 means 300 and 3600.
	RetryInterval  int            `json:"retry_interval,omitempty"`
	VerifyInterval int            `json:"verify_interval,omitempty"`
	Records        []DynDNSRecord `json:"records"`
}

// TSIG authenticates dynamic updates. Secret is base64.
type TSIG struct {
	Name      string `json:"name"`
	Algorithm string `json:"algorithm"`
	Secret    string `json:"secret"`
}

// TSIGAlgorithms are the algorithms a TSIG key may use.
var TSIGAlgorithms = []string{"hmac-sha256", "hmac-sha512", "hmac-sha384", "hmac-sha224", "hmac-sha1", "hmac-md5"}

// DynDNS record types.
var DynDNSRecordTypes = []string{"A", "AAAA", "CNAME", "TXT"}

// DynDNSRecord is a record the client maintains. Name is relative to the
// zone, "@" for the apex, or a name in the zone ending with a dot.
type DynDNSRecord struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	TTL   int    `json:"ttl,omitempty"` // 0 means 300
	Value string `json:"value,omitempty"`
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

// WireGuardRoutes are the routes to the networks behind the site peers of
// the instance's enabled WireGuard interfaces, through the interface with
// metric 0. The agent installs them with the static routes.
func (in *Instance) WireGuardRoutes() []Route {
	var out []Route
	for _, ifc := range in.Interfaces {
		if ifc.Kind != KindWireGuard || !ifc.Enabled || ifc.WireGuard == nil {
			continue
		}
		for _, p := range ifc.WireGuard.Peers {
			for _, n := range p.Networks {
				out = append(out, Route{Destination: n, Interface: ifc.Name})
			}
		}
	}
	return out
}

// InterfaceZone returns the named interface zone, or nil.
func (in *Instance) InterfaceZone(name string) *InterfaceZone {
	for i := range in.InterfaceZones {
		if in.InterfaceZones[i].Name == name {
			return &in.InterfaceZones[i]
		}
	}
	return nil
}

// MatchInterfaces resolves a rule's interface list (interface and zone
// names) to the enabled interfaces it matches, sorted and without
// duplicates. Call it on an expanded document so link ends are included.
// A non-empty list can resolve to none (empty zones, disabled interfaces);
// the rule must then be left out, not rendered without the match.
func (in *Instance) MatchInterfaces(list []string) []string {
	var out []string
	add := func(name string) {
		if ifc := in.Interface(name); ifc != nil && ifc.Enabled && !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	for _, name := range list {
		if z := in.InterfaceZone(name); z != nil {
			for _, m := range z.Interfaces {
				add(m)
			}
		} else {
			add(name)
		}
	}
	slices.Sort(out)
	return out
}
