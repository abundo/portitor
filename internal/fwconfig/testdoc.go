// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package fwconfig

// SampleDocument is a typical home setup: a default instance with a DHCP
// WAN, a LAN with DHCP/DNS, a WireGuard road-warrior interface and a port
// forward, plus a "guest" instance linked to the default one. The LAN is
// dual-stack: SLAAC and DHCPv6 on fd00:1::/64. Used by tests
// in several packages and by `portitor-agent render --sample`.
func SampleDocument() Document {
	return Document{
		Version:    Version,
		Generation: 7,
		Instances: []Instance{
			{
				Name:    "main",
				Default: true,
				Interfaces: []Interface{
					{Name: "eth0", Kind: KindPhysical, Enabled: true, IPv4Mode: ModeDHCP, IPv6AcceptRA: true},
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
				Rules: []Rule{
					{Chain: ChainForward, InInterfaces: []string{"lan"}, OutInterfaces: []string{"wan"}, Action: ActionAccept, Description: "LAN to Internet"},
					{Chain: ChainForward, InInterfaces: []string{"vpn"}, Action: ActionAccept, Description: "VPN anywhere"},
					{Chain: ChainForward, InInterfaces: []string{"iot"}, OutInterfaces: []string{"wan"}, Protocol: "tcp", DstPorts: "80,443,8883", Action: ActionAccept, Description: "IoT cloud"},
					{Chain: ChainForward, InInterfaces: []string{"guest"}, OutInterfaces: []string{"eth0"}, Action: ActionAccept},
					{Chain: ChainForward, InInterfaces: []string{"dmz"}, Action: ActionAccept, Description: "DMZ (no interfaces yet)"},
					{Chain: ChainInput, InInterfaces: []string{"wan"}, Protocol: "icmp", Action: ActionAccept, Description: "ping"},
					{Chain: ChainInput, InInterfaces: []string{"iot"}, Protocol: "udp", DstPorts: "53,67", Action: ActionAccept},
					{Chain: ChainForward, InInterfaces: []string{"wan"}, DstAddrs: []string{"192.168.1.0/24"}, Action: ActionDrop, Log: true, Description: `no "direct" access`},
					{Chain: ChainForward, InInterfaces: []string{"vpn"}, DstAddrs: []string{"192.168.1.10", "fd00:1::10"}, Protocol: "tcp", DstPorts: "22", Action: ActionAccept, Description: "NAS ssh"},
					{Chain: ChainInput, InInterfaces: []string{"lan", "vpn"}, Action: ActionAccept, Description: "trusted"},
					{Chain: ChainInput, InInterfaces: []string{"iot"}, Action: ActionReject},
					{Chain: ChainOutput, Kind: RuleKindComment, Description: `"Outbound" is open`},
				},
				NAT: []NATRule{
					{Kind: NATDNAT, InInterfaces: []string{"wan"}, Protocol: "tcp", DstPorts: "8443", ToAddr: "192.168.1.10", ToPort: 443, Description: "NAS"},
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
						{Prefix: "192.168.1.0/24", Interface: "eth1", RangeStart: "192.168.1.100", RangeEnd: "192.168.1.199", Gateway: "192.168.1.1", DNSServers: []string{"192.168.1.1"}},
						{Prefix: "192.168.20.0/24", Interface: "eth1.20", RangeStart: "192.168.20.100", RangeEnd: "192.168.20.199", Gateway: "192.168.20.1", DNSServers: []string{"192.168.20.1"}},
						{Prefix: "fd00:1::/64", Interface: "eth1", RangeStart: "fd00:1::1000", RangeEnd: "fd00:1::1fff", DNSServers: []string{"fd00:1::1"}},
					},
				},
				RA: []RAInterface{{
					Interface: "eth1",
					Prefixes:  []RAPrefix{{Prefix: "fd00:1::/64", Autonomous: true}},
					Managed:   true,
					Other:     true,
					RDNSS:     []string{"fd00:1::1"},
					DNSSL:     []string{"home.arpa"},
				}},
				DNS: DNSServer{
					Enabled:          true,
					Forwarders:       []string{"9.9.9.9"},
					ForwardFromDHCP:  true,
					ListenInterfaces: []string{"eth1", "eth1.20", "wg0"},
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
			},
		},
		Links: []Link{{
			Name: "guestup",
			A:    LinkEnd{Instance: "main", Interface: "lk-guest", Addresses: []string{"10.255.0.1/30"}},
			B:    LinkEnd{Instance: "guest", Interface: "lk-main", Addresses: []string{"10.255.0.2/30"}},
		}},
	}
}
