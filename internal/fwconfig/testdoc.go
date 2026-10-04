// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package fwconfig

// SampleDocument is a typical home setup: a default instance with a DHCP
// WAN, a LAN with DHCP/DNS, a WireGuard interface with a road warrior and a
// site, and a port forward, plus a "guest" instance linked to the default
// one. The LAN is dual-stack: SLAAC and DHCPv6 on fd00:1::/64. Used by
// tests in several packages and by `portitor-agent render --sample`.
func SampleDocument() Document {
	return Document{
		Version:    Version,
		Generation: 7,
		Instances: []Instance{
			{
				Name:    "main",
				Default: true,
				Interfaces: []Interface{
					{Name: "eth0", Kind: KindPhysical, Enabled: true, IPv4Mode: ModeDHCP, IPv6AcceptRA: true, ShapeEgress: 40, ShapeIngress: 400},
					{Name: "eth1", Kind: KindPhysical, Enabled: true, IPv4Mode: ModeStatic, Addresses: []string{"192.168.1.1/24", "fd00:1::1/64"}},
					{Name: "eth1.20", Kind: KindVLAN, Parent: "eth1", VLANID: 20, Enabled: true, IPv4Mode: ModeStatic, Addresses: []string{"192.168.20.1/24"}},
					{
						Name: "wg0", Kind: KindWireGuard, Enabled: true, IPv4Mode: ModeStatic,
						Addresses: []string{"10.99.0.1/24"},
						WireGuard: &WireGuard{
							PrivateKey: "YEocP0e2o1WT5GlvBvQzVF7EeR6z9aCk8ZdZ5oPr1Wk=",
							ListenPort: 51820,
							Peers: []WGPeer{{
								Name:       "phone",
								PublicKey:  "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
								AllowedIPs: []string{"10.99.0.2/32"},
							}, {
								Name:       "office",
								PublicKey:  "SIKnAouqB3jjF6shpAaGd0Ylc68P5jM4bPVMyg5qWCg=",
								Endpoint:   "office.example.org:51820",
								AllowedIPs: []string{"10.99.0.3/32"},
								Networks:   []string{"192.168.50.0/24"},
								Keepalive:  25,
							}},
						},
					},
				},
				InterfaceZones: []InterfaceZone{
					{Name: "wan", Interfaces: []string{"eth0"}},
					{Name: "lan", Interfaces: []string{"eth1"}},
					{Name: "iot", Interfaces: []string{"eth1.20"}},
					{Name: "vpn", Interfaces: []string{"wg0"}},
					{Name: "guest", Interfaces: []string{"lk-guest"}},
					{Name: "dmz", Interfaces: []string{}},
				},
				LogDrops:   []string{ChainForward},
				LogInvalid: []string{ChainInput},
				LogAuto:    []string{"dns server", "no such service"},
				Rules: []Rule{
					{Chain: ChainForward, InInterfaces: []string{"lan"}, OutInterfaces: []string{"wan"}, Action: ActionAccept, Description: "LAN to Internet"},
					{Chain: ChainForward, InInterfaces: []string{"vpn"}, Action: ActionAccept, Description: "VPN anywhere"},
					{Chain: ChainForward, InInterfaces: []string{"iot"}, OutInterfaces: []string{"wan"}, Services: []ServiceMatch{{Protocol: ProtoTCP, DstPorts: "http,https,8883"}}, Action: ActionAccept, Description: "IoT cloud"},
					{Chain: ChainForward, InInterfaces: []string{"guest"}, OutInterfaces: []string{"eth0"}, Action: ActionAccept},
					{Chain: ChainForward, InInterfaces: []string{"dmz"}, Action: ActionAccept, Description: "DMZ (no interfaces yet)"},
					{Chain: ChainInput, InInterfaces: []string{"wan"}, Services: []ServiceMatch{{Protocol: ProtoICMP, ICMPType: "echo-request"}, {Protocol: ProtoICMPv6, ICMPType: "destination-unreachable", ICMPCode: ptr(4)}}, Action: ActionAccept, Description: "ping"},
					{Chain: ChainInput, InInterfaces: []string{"iot"}, Services: []ServiceMatch{{Protocol: ProtoUDP, DstPorts: "53,67"}, {Protocol: ProtoSCTP, DstPorts: "5060,5000-5100", SrcPorts: "1024-65535"}, {Protocol: ProtoIP, IPProtocol: 47}}, Action: ActionAccept},
					{Chain: ChainForward, InInterfaces: []string{"wan"}, DstAddrs: []string{"192.168.1.0/24"}, Action: ActionDrop, Log: true, Description: `no "direct" access`},
					{Chain: ChainForward, InInterfaces: []string{"vpn"}, DstAddrs: []string{"192.168.1.10", "fd00:1::10"}, Services: []ServiceMatch{{Protocol: ProtoTCP, DstPorts: "22"}}, Action: ActionAccept, Description: "NAS ssh"},
					{Chain: ChainInput, InInterfaces: []string{"lan", "vpn"}, Action: ActionAccept, Description: "trusted"},
					{Chain: ChainInput, InInterfaces: []string{"iot"}, Action: ActionReject},
					{Chain: ChainOutput, Kind: RuleKindComment, Description: `"Outbound" is open`},
					{Chain: ChainInput, InInterfaces: []string{"wan"}, SrcAddrs: []string{"@crowdsec", "@drop", "198.51.100.0/24"}, Action: ActionDrop, Description: "blocklists"},
					{Chain: ChainForward, OutInterfaces: []string{"wan"}, Family: "ipv4", DstAddrs: []string{"@drop"}, Action: ActionReject},
					{Chain: ChainOutput, Action: ActionAccept, Description: "allow all output"},
					{Chain: ChainOutput, Kind: RuleKindComment, Description: "group: admin"},
					{Chain: ChainInput, InInterfaces: []string{"wan"}, Services: []ServiceMatch{{Protocol: ProtoTCP, DstPorts: "22"}}, Action: ActionAccept, RateLimit: "ssh", Description: "ssh, limited"},
					{Chain: ChainForward, InInterfaces: []string{"wan"}, DstAddrs: []string{"192.168.1.10"}, Services: []ServiceMatch{{Protocol: ProtoICMP, ICMPType: "echo-request"}}, Action: ActionAccept, RateLimit: "ping flood"},
					{ID: 2000, Chain: ChainForward, InInterfaces: []string{"guest"}, OutInterfaces: []string{"wan"}, Action: ActionAccept, RateLimit: "guest host", Description: "guests, policed"},
					{ID: 2002, Chain: ChainInput, InInterfaces: []string{"lan"}, Services: []ServiceMatch{{Protocol: ProtoTCP, DstPorts: "445"}}, Action: ActionAccept, RateLimit: "shared", Description: "file share"},
					{ID: 2001, Chain: ChainOutput, Services: []ServiceMatch{{Protocol: ProtoTCP, DstPorts: "443"}}, Action: ActionAccept, RateLimit: "updates"},
					{Chain: ChainForward, InInterfaces: []string{"lan"}, SrcAddrs: []string{"$admins", "192.168.1.99"}, DstAddrs: []string{"$servers"}, Action: ActionAccept, Description: "admins to servers"},
				},
				AddressSets: []AddressSet{
					{Name: "admins", Addresses: []string{"192.168.1.20", "192.168.1.21", "fd00:1::20"}},
					{Name: "servers", Addresses: []string{"192.168.1.10", "192.168.2.0/24"}},
				},
				RateLimits: []RateLimit{
					{Name: "ssh", Rate: 4, Per: RatePerMinute, Burst: 2, PerSource: true},
					{Name: "ping flood", Rate: 10, Per: RatePerSecond},
					{Name: "guest host", Rate: 2, Unit: RateUnitMBytes, Per: RatePerSecond, Burst: 1, PerSource: true, Connections: true},
					{Name: "updates", Rate: 500, Unit: RateUnitKBytes, Per: RatePerSecond, Connections: true},
					{Name: "bulk", Rate: 100, Unit: RateUnitMBit, Per: RatePerSecond, Shape: true},
					{Name: "shared", Rate: 2, Unit: RateUnitMBytes, Per: RatePerSecond, Shape: true},
					{Name: "cap", Rate: 10, Unit: RateUnitMBit, Per: RatePerSecond, Burst: 1, Connections: true},
				},
				NAT: []NATRule{
					{Kind: NATDNAT, InInterfaces: []string{"wan"}, Protocol: "tcp", DstPorts: "8443", ToAddr: "192.168.1.10", ToPort: 443, Hairpin: true, Description: "NAS"},
					{Kind: NATMasquerade, OutInterfaces: []string{"wan"}, Description: "Internet sharing"},
				},
				Routes: []Route{
					{Destination: "10.50.0.0/16", Gateway: "192.168.1.254"},
				},
				DHCP: DHCPServer{
					Enabled:    true,
					DomainName: "home.arpa",
					LeaseTime:  43200,
					Subnets: []DHCPSubnet{
						{Prefix: "192.168.1.0/24", Interface: "eth1", RangeStart: "192.168.1.100", RangeEnd: "192.168.1.199", Gateway: "192.168.1.1", DNSServers: []string{"192.168.1.1"}, IPv6OnlyPreferred: IPv6OnlyWait},
						{Prefix: "192.168.20.0/24", Interface: "eth1.20", RangeStart: "192.168.20.100", RangeEnd: "192.168.20.199", Gateway: "192.168.20.1", DNSServers: []string{"192.168.20.1"}},
						{Prefix: "fd00:1::/64", Interface: "eth1", RangeStart: "fd00:1::1000", RangeEnd: "fd00:1::1fff", DNSServers: []string{"fd00:1::1"}},
					},
				},
				RA: []RAInterface{{
					Interface:   "eth1",
					Prefixes:    []RAPrefix{{Prefix: "fd00:1::/64", Autonomous: true}},
					Managed:     true,
					Other:       true,
					RDNSS:       []string{"fd00:1::1"},
					DNSSL:       []string{"home.arpa"},
					NAT64Prefix: NAT64WellKnownPrefix,
				}},
				NAT64: &NAT64{Prefix: NAT64WellKnownPrefix, Interfaces: []string{"eth1"}},
				NTP: &NTP{
					Servers:    []NTPServer{{Address: "time.cloudflare.com", IBurst: true, NTS: true}, {Address: "2.debian.pool.ntp.org", Pool: true, IBurst: true}},
					Interfaces: []string{"eth1"},
					Allow:      []string{"192.168.1.0/24", "fd00:1::/64"},
				},
				SNMP: &SNMP{
					Location: "Server room 1", Contact: "noc@example.com",
					Interfaces: []string{"eth1"},
					Allow:      []string{"192.168.1.0/24", "fd00:1::/64"},
					Community:  "s3cret",
					Users: []SNMPUser{
						{Name: "monitor", AuthProtocol: "SHA-256", AuthPassword: "authpass1", PrivProtocol: "AES", PrivPassword: "privpass1"},
						{Name: "ro", AuthProtocol: "SHA", AuthPassword: "authpass2"},
					},
				},
				Certificates: []Certificate{{
					Name: "www", Domains: []string{"www.example.com", "example.com"}, Email: "admin@example.com",
					CA: "letsencrypt", KeyType: "ec256", Challenge: ChallengeHTTP01, Interface: "eth0",
				}},
				DynDNS: []DynDNS{{
					Name:      "home",
					Interface: "eth0",
					Server:    "192.0.2.53",
					Zone:      "example.com",
					TSIG:      &TSIG{Name: "ddns-key.example.com", Algorithm: "hmac-sha256", Secret: "c2VjcmV0c2VjcmV0c2VjcmV0"},
					Records: []DynDNSRecord{
						{Name: "home", Type: "A", TTL: 60},
						{Name: "home", Type: "AAAA", TTL: 60},
						{Name: "home", Type: "TXT"},
						{Name: "www", Type: "CNAME", Value: "home"},
					},
				}},
				DNS: DNSServer{
					Enabled:          true,
					Upstream:         UpstreamForward,
					Forwarders:       []string{"9.9.9.9"},
					ListenInterfaces: []string{"eth1", "eth1.20", "wg0"},
					DNS64:            NAT64WellKnownPrefix,
					Zones: []DNSZone{
						{Name: "home.arpa", Type: ZoneForward, Template: "home", Records: []DNSRecord{
							{Name: "gw", Type: "A", Value: "192.168.1.1"},
							{Name: "nas", Type: "A", Value: "192.168.1.10", MAC: "02:00:00:00:00:10"},
							{Name: "nas", Type: "AAAA", Value: "fd00:1::10", MAC: "02:00:00:00:00:10"},
						}},
						{Name: "192.168.1.0/24", Type: ZoneReverse4},
					},
					SOATemplates: []DNSSOATemplate{
						{Name: "home", MName: "gw.home.arpa", RName: "hostmaster.home.arpa", Refresh: 86400, Retry: 7200, Expire: 3600000, Minimum: 3600},
					},
					ZoneTemplates: []DNSZoneTemplate{
						{Name: "home", SOA: "home", DefaultTTL: 3600, Nameservers: []string{"gw.home.arpa"}, DNSSECPolicy: "signed"},
					},
					DNSSECPolicies: []DNSSECPolicy{
						{Name: "signed", KSKLifetime: "unlimited", KSKAlgorithm: "ecdsap256sha256", ZSKLifetime: "P90D", ZSKAlgorithm: "ecdsap256sha256", SignaturesValidity: "14d"},
					},
				},
			},
			{
				Name: "guest",
				Interfaces: []Interface{
					{Name: "eth2", Kind: KindPhysical, Enabled: true, IPv4Mode: ModeStatic, Addresses: []string{"192.168.50.1/24"}},
				},
				VRRP: []VRRP{
					{Interface: "eth2", VRID: 50, Priority: 200, AdvertisementInterval: 500, IPv4: []string{"192.168.50.254"}, IPv6: []string{"fe80::50"}},
				},
				Rules: []Rule{
					{Chain: ChainForward, InInterfaces: []string{"eth2"}, OutInterfaces: []string{"lk-main"}, DstAddrs: []string{"192.168.0.0/16"}, Action: ActionReject, Description: "no home access"},
					{Chain: ChainForward, InInterfaces: []string{"eth2"}, OutInterfaces: []string{"lk-main"}, Action: ActionAccept},
					{Chain: ChainInput, InInterfaces: []string{"eth2"}, Action: ActionAccept},
				},
				NAT: []NATRule{
					{Kind: NATMasquerade, OutInterfaces: []string{"lk-main"}},
				},
				Routes: []Route{{Destination: "default", Gateway: "10.255.0.1"}},
				DHCP: DHCPServer{Enabled: true, Subnets: []DHCPSubnet{
					{Prefix: "192.168.50.0/24", Interface: "eth2", RangeStart: "192.168.50.100", RangeEnd: "192.168.50.200", DNSServers: []string{"9.9.9.9"}},
				}},
				BGP: &BGP{
					Enabled: true, ASN: 65010, RouterID: "10.255.0.2", LogNeighborChanges: true,
					Networks:     []BGPNetwork{{Prefix: "192.168.50.0/24"}},
					Aggregates:   []BGPAggregate{{Prefix: "192.168.0.0/16", SummaryOnly: true}},
					Redistribute: []BGPRedistribute{{Family: "ipv4", Source: RedistConnected, RouteMap: "connected"}, {Family: "ipv4", Source: RedistOSPF}},
					PeerGroups: []BGPPeer{{
						Name: "upstream", RemoteAS: "65000", Password: "s3cret",
						IPv4: BGPAddressFamily{Activate: true, RouteMapIn: "from-upstream", PrefixListOut: "ours", SoftReconfiguration: true},
					}},
					Neighbors: []BGPPeer{
						{Address: "10.255.0.1", PeerGroup: "upstream", Description: "main"},
						{Address: "2001:db8::1", RemoteAS: "65001", EBGPMultihop: 2, UpdateSource: "eth2",
							IPv6: BGPAddressFamily{Activate: true, NextHopSelf: true, RemovePrivateAS: true}},
					},
				},
				OSPF: &OSPF{
					Enabled: true, RouterID: "10.255.0.2", LogAdjacencyChanges: true, ReferenceBandwidth: 10000,
					DefaultOriginate: true,
					Areas:            []OSPFArea{{ID: "0.0.0.1", Type: AreaStub, NoSummary: true}},
					Ranges:           []OSPFRange{{Area: "0.0.0.1", Prefix: "192.168.50.0/23", Cost: 10}},
					Summaries:        []OSPFSummary{{Prefix: "172.16.0.0/12"}},
					Interfaces: []OSPFInterface{
						{Name: "lk-main", Area: "0.0.0.0", NetworkType: OSPFPointToPoint, HelloInterval: 5, DeadInterval: 20, AuthKeyID: 1, AuthKey: "k3y"},
						{Name: "eth2", Area: "0.0.0.1", Passive: true, Cost: 100, Priority: ptr(0)},
					},
					Redistribute: []OSPFRedistribute{{Source: RedistStatic, MetricType: 1, Metric: 50, RouteMap: "connected"}, {Source: RedistBGP}},
				},
				OSPF6: &OSPF{
					Enabled: true, RouterID: "10.255.0.2",
					Interfaces:   []OSPFInterface{{Name: "lk-main", Area: "0.0.0.0"}},
					Redistribute: []OSPFRedistribute{{Source: RedistConnected}},
				},
				RoutingPolicy: RoutingPolicy{
					PrefixLists: []PrefixList{
						{Name: "ours", Family: "ipv4", Entries: []PrefixListEntry{{Seq: 5, Action: Permit, Prefix: "192.168.0.0/16", LE: 24}}},
					},
					ASPathLists: []ASPathList{{Name: "short", Entries: []ASPathEntry{{Action: Permit, Regex: "^65000_[0-9]+$"}}}},
					CommunityLists: []CommunityList{
						{Name: "noexport", Kind: CommunityStandard, Entries: []CommunityEntry{{Action: Permit, Value: "65000:666 no-export"}}},
					},
					RouteMaps: []RouteMap{
						{Name: "from-upstream", Entries: []RouteMapEntry{
							{Seq: 10, Action: Deny, MatchCommunity: "noexport"},
							{Seq: 20, Action: Permit, MatchASPath: "short", SetLocalPreference: ptr(int64(200)), SetCommunity: "65010:1", SetCommunityAdditive: true},
						}},
						{Name: "connected", Entries: []RouteMapEntry{{Seq: 10, Action: Permit, MatchPrefixList: "ours"}}},
					},
				},
			},
		},
		Links: []Link{{
			Name: "guestup",
			A:    LinkEnd{Instance: "main", Interface: "lk-guest", Addresses: []string{"10.255.0.1/30"}},
			B:    LinkEnd{Instance: "guest", Interface: "lk-main", Addresses: []string{"10.255.0.2/30"}},
		}},
		IPLists: []IPList{
			{Name: "crowdsec", Source: IPListCrowdSec, URL: "http://127.0.0.1:8080", APIKey: "0123456789abcdef"},
			{Name: "drop", Source: IPListURL, URL: "https://www.spamhaus.org/drop/drop.txt"},
		},
		Tasks: []Task{
			{Name: "crowdsec", Schedule: "*/5 * * * *", Kind: TaskIPList, IPList: "crowdsec"},
			{Name: "drop", Schedule: "@daily", Kind: TaskIPList, IPList: "drop"},
			{Name: "backup", Schedule: "30 3 * * *", Kind: TaskCommand, Command: "tar czf /tmp/etc.tgz /etc/portitor", Timeout: 600},
		},
	}
}

func ptr[T any](v T) *T { return &v }
