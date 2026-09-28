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

import "slices"

// Version of the document format. Bump when a field changes meaning.
const Version = 2

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
	NAT            []NATRule       `json:"nat"`
	Routes         []Route         `json:"routes"`
	DHCP           DHCPServer      `json:"dhcp"`
	DNS            DNSServer       `json:"dns"`
	// RA lists the interfaces that send IPv6 router advertisements.
	RA []RAInterface `json:"ra,omitempty"`
	// DynDNS clients keep records on a nameserver in step with the
	// addresses of this instance's interfaces.
	DynDNS []DynDNS `json:"dyndns,omitempty"`
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
	IPv4Mode    string   `json:"ipv4_mode"`
	// DHCPNoDefaultRoute makes the DHCP client ignore the lease's router
	// (a LAN on DHCP: the default route belongs to the WAN).
	DHCPNoDefaultRoute bool `json:"dhcp_no_default_route,omitempty"`
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
	Family        string   `json:"family,omitempty"`   // "", ipv4, ipv6
	Protocol      string   `json:"protocol,omitempty"` // "", tcp, udp, tcp,udp, icmp, icmpv6
	SrcAddrs      []string `json:"src_addrs,omitempty"`
	DstAddrs      []string `json:"dst_addrs,omitempty"`
	DstPorts      string   `json:"dst_ports,omitempty"` // "22", "80,443", "1000-2000"
	Action        string   `json:"action"`
	Log           bool     `json:"log,omitempty"`
	Description   string   `json:"description,omitempty"`
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
	Description   string   `json:"description,omitempty"`
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

// DNSServer.ForwardMode values.
const (
	ForwardFirst = "first" // forwarders, falling back to the root servers ("" too)
	ForwardOnly  = "only"  // forwarders only
	ForwardOff   = "off"   // ignore forwarders: resolve from the root servers
)

type DNSServer struct {
	Enabled bool `json:"enabled"`
	// Forwarders are upstream resolvers. ForwardFromDHCP adds the servers
	// learned by the DHCP client on this instance's WAN interfaces.
	// ForwardMode says how they are used; with no forwarders, or with
	// ForwardOff, BIND resolves from the root servers (its built-in hints).
	Forwarders      []string `json:"forwarders,omitempty"`
	ForwardFromDHCP bool     `json:"forward_from_dhcp,omitempty"`
	ForwardMode     string   `json:"forward_mode,omitempty"`
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

// DynDNS is a dynamic DNS client (ifnsupdate): it sends RFC 2136 UPDATEs
// to Server, from inside the instance, whenever Interface's addresses
// change. A and AAAA records without a Value get the interface's first
// global address of that family; records with a Value, and CNAMEs, are
// static and re-verified every VerifyInterval. A TXT record without a
// Value holds the time of the last update.
type DynDNS struct {
	Name      string `json:"name"`
	Interface string `json:"interface"`
	// Server is the zone's primary nameserver: an IP address, with an
	// optional port (192.0.2.53, [2001:db8::53]:5353).
	Server string `json:"server"`
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
