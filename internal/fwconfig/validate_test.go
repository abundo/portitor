// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package fwconfig

import (
	"strings"
	"testing"
)

func TestSampleIsValid(t *testing.T) {
	doc := SampleDocument()
	if err := doc.Validate(); err != nil {
		t.Fatal(err)
	}
}

// Every address of a /31 or /32 (/127, /128) is a host address.
func TestValidatePointToPointAddresses(t *testing.T) {
	doc := SampleDocument()
	doc.Instances[0].Interfaces[1].Addresses = append(doc.Instances[0].Interfaces[1].Addresses, "10.0.0.0/31", "10.0.1.0/32", "fd00:9::/127")
	if err := doc.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateTCPUDPPorts(t *testing.T) {
	doc := SampleDocument()
	doc.Instances[0].NAT[0].Protocol = "tcp,udp" // with a target port
	if err := doc.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateCatchesProblems(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(d *Document)
		want   string
	}{
		{"log drops bad chain", func(d *Document) { d.Instances[0].LogDrops = []string{"nat"} }, `log drops: invalid chain "nat"`},
		{"log drops twice", func(d *Document) { d.Instances[0].LogDrops = []string{"input", "input"} }, "input listed twice"},
		{"log invalid bad chain", func(d *Document) { d.Instances[0].LogInvalid = []string{"prerouting"} }, `log invalid: invalid chain "prerouting"`},
		{"log auto bad service", func(d *Document) { d.Instances[0].LogAuto = []string{`dns" server`} }, `log auto: invalid service`},
		{"log auto double space", func(d *Document) { d.Instances[0].LogAuto = []string{"dns  server"} }, `log auto: invalid service`},
		{"two defaults", func(d *Document) { d.Instances[1].Default = true }, "exactly one instance"},
		{"bad instance name", func(d *Document) { d.Instances[1].Name = "Guest-Net" }, "name must match"},
		{"unknown interface", func(d *Document) { d.Instances[0].Rules[0].InInterfaces = []string{"eth9"} }, `unknown interface or interface zone "eth9"`},
		{"nat unknown interface", func(d *Document) { d.Instances[0].NAT[1].OutInterfaces = []string{"up"} }, `unknown interface or interface zone "up"`},
		{"interface of other instance", func(d *Document) { d.Instances[1].Rules[0].InInterfaces = []string{"eth1"} }, `unknown interface or interface zone "eth1"`},
		{"input with out interface", func(d *Document) { d.Instances[0].Rules[5].OutInterfaces = []string{"lan"} }, "input rules have no outgoing"},
		{"dnat with out interface", func(d *Document) { d.Instances[0].NAT[0].OutInterfaces = []string{"lan"} }, "dnat matches the incoming"},
		{"zone unknown member", func(d *Document) { d.Instances[0].InterfaceZones[0].Interfaces = []string{"eth9"} }, `member "eth9" is not an interface`},
		{"zone named like interface", func(d *Document) { d.Instances[0].InterfaceZones[0].Name = "eth1" }, "an interface has the same name"},
		{"zone duplicate", func(d *Document) { d.Instances[0].InterfaceZones[1].Name = "wan" }, "duplicate"},
		{"unknown rate limit", func(d *Document) { d.Instances[0].Rules[0].RateLimit = "nope" }, `unknown rate limit "nope"`},
		{"rate limit zero", func(d *Document) { d.Instances[0].RateLimits[0].Rate = 0 }, "rate must be 1-"},
		{"rate limit period", func(d *Document) { d.Instances[0].RateLimits[0].Per = "week" }, `invalid period "week"`},
		{"rate limit burst", func(d *Document) { d.Instances[0].RateLimits[0].Burst = -1 }, "burst must be 0-"},
		{"rate limit duplicate", func(d *Document) { d.Instances[0].RateLimits[1].Name = "ssh" }, "duplicate"},
		{"rate limit name newline", func(d *Document) { d.Instances[0].RateLimits[0].Name = "a\nb" }, "invalid name"},
		{"rate limit unit", func(d *Document) { d.Instances[0].RateLimits[0].Unit = "bits" }, `invalid unit "bits"`},
		{"bytes without connections", func(d *Document) { d.Instances[0].RateLimits[1].Unit = RateUnitBytes }, "needs connections"},
		{"connection limit on drop", func(d *Document) { d.Instances[0].Rules[18].Action = ActionDrop }, "limits or shapes connections"},
		{"connection limit without id", func(d *Document) { d.Instances[0].Rules[18].ID = 0 }, "limits or shapes connections"},
		{"interface named ifb-", func(d *Document) { d.Instances[0].Interfaces[1].Name = "ifb-x" }, "names are for shaping"},
		{"shaping range", func(d *Document) { d.Instances[0].Interfaces[0].ShapeIngress = -1 }, "shaping must be"},
		{"shaping on drop", func(d *Document) { d.Instances[0].Rules[19].Action = ActionDrop }, "limits or shapes connections"},
		{"shaping in packets", func(d *Document) { d.Instances[0].RateLimits[4].Unit = "" }, "shaping needs a rate in bytes or bits"},
		{"shaping per minute", func(d *Document) { d.Instances[0].RateLimits[4].Per = RatePerMinute }, "a rate per second only"},
		{"shaping per source", func(d *Document) { d.Instances[0].RateLimits[4].PerSource = true }, "a rate per second only"},
		{"bits without connections", func(d *Document) { d.Instances[0].RateLimits[1].Unit = RateUnitMBit }, "needs connections"},
		{"comment with rate limit", func(d *Document) { d.Instances[0].Rules[11].RateLimit = "ssh" }, "a comment has only"},
		{"zone name newline", func(d *Document) { d.Instances[0].InterfaceZones[0].Name = "wan\naccept" }, "invalid name"},
		{"ports with icmp", func(d *Document) { d.Instances[0].Rules[5].Services[0].DstPorts = "22" }, "ports need protocol"},
		{"src ports with ip", func(d *Document) { d.Instances[0].Rules[6].Services[2].SrcPorts = "22" }, "ports need protocol"},
		{"icmp type without icmp", func(d *Document) { d.Instances[0].Rules[6].Services[0].ICMPType = "echo-request" }, "needs protocol icmp or icmpv6"},
		{"icmpv6 type with icmp", func(d *Document) { d.Instances[0].Rules[5].Services[0].ICMPType = "nd-neighbor-solicit" }, `invalid icmp type "nd-neighbor-solicit"`},
		{"icmp type injection", func(d *Document) { d.Instances[0].Rules[5].Services[0].ICMPType = "echo-request accept" }, "invalid icmp type"},
		{"icmp code without type", func(d *Document) {
			d.Instances[0].Rules[5].Services[0].ICMPType, d.Instances[0].Rules[5].Services[0].ICMPCode = "", ptr(3)
		}, "code needs a type"},
		{"icmp code range", func(d *Document) { d.Instances[0].Rules[5].Services[0].ICMPCode = ptr(256) }, "invalid icmp code 256"},
		{"ip number without ip", func(d *Document) { d.Instances[0].Rules[6].Services[0].IPProtocol = 6 }, "needs protocol ip"},
		{"ip number range", func(d *Document) { d.Instances[0].Rules[6].Services[2].IPProtocol = 300 }, "invalid protocol number 300"},
		{"sctp bad src ports", func(d *Document) { d.Instances[0].Rules[6].Services[1].SrcPorts = "9-1" }, "invalid port range"},
		{"network address on interface", func(d *Document) { d.Instances[0].Interfaces[1].Addresses[0] = "192.168.1.0/24" }, "is the network address"},
		{"ipv6 subnet-router address", func(d *Document) { d.Instances[0].Interfaces[1].Addresses[1] = "fd00:1::/64" }, "is the network address"},
		{"address on two interfaces", func(d *Document) { d.Instances[0].Interfaces[2].Addresses = []string{"192.168.1.1/25"} }, "192.168.1.1 is also on eth1"},
		{"delegated without pd", func(d *Document) {
			d.Instances[0].Interfaces[1].Addresses = append(d.Instances[0].Interfaces[1].Addresses, "<eth0>:1::1/64")
		}, "eth0 does not get a delegated prefix"},
		{"delegated bad form", func(d *Document) {
			d.Instances[0].Interfaces[1].Addresses = append(d.Instances[0].Interfaces[1].Addresses, "<eth0>2000::1/64")
		}, "expected <interface>:subnet::host/length"},
		{"delegated network address", func(d *Document) {
			d.Instances[0].Interfaces[0].DHCPv6, d.Instances[0].Interfaces[0].DHCPv6PD = true, true
			d.Instances[0].Interfaces[1].Addresses = append(d.Instances[0].Interfaces[1].Addresses, "<eth0>:1::/64")
		}, "is the network address"},
		{"delegated twice", func(d *Document) {
			d.Instances[0].Interfaces[0].DHCPv6, d.Instances[0].Interfaces[0].DHCPv6PD = true, true
			d.Instances[0].Interfaces[1].Addresses = append(d.Instances[0].Interfaces[1].Addresses, "<eth0>:1::1/64")
			d.Instances[0].Interfaces[2].Addresses = []string{"<eth0>:01::1/64"}
		}, "<eth0>:1::1/64 is also on eth1"},
		{"lldp on wireguard", func(d *Document) { d.Instances[0].Interfaces[3].LLDP = true }, "lldp is not supported on wireguard interfaces"},
		{"pd without dhcpv6", func(d *Document) { d.Instances[0].Interfaces[0].DHCPv6PD = true }, "prefix delegation needs the dhcpv6 client"},
		{"dhcpv6 without ra", func(d *Document) {
			d.Instances[0].Interfaces[1].DHCPv6 = true
		}, "needs router advertisements accepted"},
		{"pd length", func(d *Document) {
			d.Instances[0].Interfaces[0].DHCPv6, d.Instances[0].Interfaces[0].DHCPv6PD, d.Instances[0].Interfaces[0].DHCPv6PDLength = true, true, 80
		}, "delegated prefix length 80 out of range"},
		{"dhcp subnet twice", func(d *Document) {
			d.Instances[0].DHCP.Subnets = append(d.Instances[0].DHCP.Subnets, DHCPSubnet{Prefix: "192.168.1.0/24", Interface: "eth1"})
		}, "dhcp subnet 192.168.1.0/24: duplicate"},
		{"reservation address twice", func(d *Document) {
			z := &d.Instances[0].DNS.Zones[0]
			z.Records = append(z.Records, DNSRecord{Name: "tv", Type: "A", Value: "192.168.1.10", MAC: "02:00:00:00:00:11"})
		}, "192.168.1.10 is reserved for both"},
		{"reservation mac twice", func(d *Document) {
			z := &d.Instances[0].DNS.Zones[0]
			z.Records = append(z.Records, DNSRecord{Name: "nas2", Type: "A", Value: "192.168.1.11", MAC: "02:00:00:00:00:10"})
		}, "02:00:00:00:00:10 has reservations for both"},
		{"target port without proto", func(d *Document) { d.Instances[0].NAT[0].Protocol, d.Instances[0].NAT[0].DstPorts = "", "" }, "a target port needs protocol"},
		{"bad protocol", func(d *Document) { d.Instances[0].Rules[2].Services[0].Protocol = "tcp,udp" }, `invalid protocol "tcp,udp"`},
		{"bad port range", func(d *Document) { d.Instances[0].Rules[2].Services[0].DstPorts = "90-80" }, "invalid port range"},
		{"ifname injection", func(d *Document) { d.Instances[0].Interfaces[1].Name = `eth1" accept` }, "name must match"},
		{"comment with match", func(d *Document) { d.Instances[0].Rules[11].Services = []ServiceMatch{{Protocol: ProtoTCP}} }, "a comment has only"},
		{"duplicate rule id", func(d *Document) { d.Instances[0].Rules[0].ID, d.Instances[1].Rules[0].ID = 7, 7 }, "duplicate id 7"},
		{"comment with id", func(d *Document) { d.Instances[0].Rules[11].ID = 7 }, "a comment has only"},
		{"bad rule kind", func(d *Document) { d.Instances[0].Rules[0].Kind = "note" }, `invalid kind "note"`},
		{"comment newline", func(d *Document) { d.Instances[0].Rules[0].Description = "a\nflush ruleset" }, "control characters"},
		{"no common family", func(d *Document) {
			d.Instances[0].Rules[0].SrcAddrs = []string{"10.0.0.0/8"}
			d.Instances[0].Rules[0].DstAddrs = []string{"fd00::/8"}
		}, "no IP version fits"},
		{"icmp with only v6 addresses", func(d *Document) {
			d.Instances[0].Rules[5].Services = d.Instances[0].Rules[5].Services[:1]
			d.Instances[0].Rules[5].SrcAddrs = []string{"2001:db8::/32"}
		}, "no service fits"},
		{"family against protocol", func(d *Document) {
			d.Instances[0].Rules[5].Services = d.Instances[0].Rules[5].Services[:1]
			d.Instances[0].Rules[5].Family = "ipv6"
		}, "no service fits"},
		{"slaac needs /64", func(d *Document) { d.Instances[0].RA[0].Prefixes[0].Prefix = "fd00:1::/56" }, "needs a /64"},
		{"ra unknown interface", func(d *Document) { d.Instances[0].RA[0].Interface = "eth9" }, "unknown interface"},
		{"ra v4 dns", func(d *Document) { d.Instances[0].RA[0].RDNSS = []string{"192.168.1.1"} }, "invalid IPv6 dns server"},
		{"dhcpv6 without ra", func(d *Document) { d.Instances[0].RA = nil }, "DHCPv6 needs router advertisements"},
		{"dhcpv6 gateway", func(d *Document) { d.Instances[0].DHCP.Subnets[2].Gateway = "fd00:1::1" }, "learn the gateway"},
		{"dhcp dns family", func(d *Document) { d.Instances[0].DHCP.Subnets[2].DNSServers = []string{"192.168.1.1"} }, "IP version"},
		{"route gateway family", func(d *Document) { d.Instances[0].Routes[0].Gateway = "fd00:1::fe" }, "differ in family"},
		{"dhcp range outside", func(d *Document) { d.Instances[0].DHCP.Subnets[0].RangeEnd = "10.0.0.1" }, "not inside the prefix"},
		{"bad wg key", func(d *Document) { d.Instances[0].Interfaces[3].WireGuard.PrivateKey = "nope" }, "invalid private key"},
		{"bad wg network", func(d *Document) { d.Instances[0].Interfaces[3].WireGuard.Peers[1].Networks = []string{"192.168.50.1"} }, `invalid network "192.168.50.1"`},
		{"wg network default", func(d *Document) { d.Instances[0].Interfaces[3].WireGuard.Peers[1].Networks = []string{"0.0.0.0/0"} }, "a default route through a peer"},
		{"wg network in two peers", func(d *Document) {
			d.Instances[0].Interfaces[3].WireGuard.Peers[0].Networks = []string{"192.168.50.0/24"}
		}, `wg0 peer "office": network 192.168.50.0/24: wg0 peer "phone" already routes it`},
		{"wg network as static route", func(d *Document) { d.Instances[0].Routes[0].Destination = "192.168.50.0/24" }, "route 1 already routes it"},
		{"link same instance", func(d *Document) { d.Links[0].B.Instance = "main" }, "both ends"},
		{"physical in two instances", func(d *Document) { d.Instances[1].Interfaces[0].Name = "eth0" }, "already used by instance"},
		{"dns record injection", func(d *Document) {
			d.Instances[0].DNS.Zones[0].Records[0].Value = "1.2.3.4\n@ NS evil."
		}, "newline"},
		{"dns forward mode", func(d *Document) { d.Instances[0].DNS.ForwardMode = "last" }, `invalid forward mode "last"`},
		{"dns dnssec validation", func(d *Document) { d.Instances[0].DNS.DNSSECValidation = "yes" }, `invalid dnssec validation "yes"`},
		{"dns query log client", func(d *Document) { d.Instances[0].DNS.QueryLog = &DNSQueryLog{Clients: []string{"10.0.0.1"}} }, `invalid client prefix "10.0.0.1"`},
		{"dns query log name", func(d *Document) { d.Instances[0].DNS.QueryLog = &DNSQueryLog{Names: []string{"a b"}} }, `invalid name "a b"`},
		{"dns query log type", func(d *Document) { d.Instances[0].DNS.QueryLog = &DNSQueryLog{Types: []string{"a;"}} }, `invalid query type "a;"`},
		{"dns upstream", func(d *Document) { d.Instances[0].DNS.Upstream = "peer" }, `invalid upstream "peer"`},
		{"dns upstream dhcp no interface", func(d *Document) { d.Instances[0].DNS.Upstream = UpstreamDHCP }, "needs the interface"},
		{"dns upstream dhcp static", func(d *Document) {
			d.Instances[0].DNS.Upstream, d.Instances[0].DNS.DHCPInterface = UpstreamDHCP, "eth1"
		}, "eth1 is not a DHCP client"},
		{"dns dhcp interface not dhcp upstream", func(d *Document) { d.Instances[0].DNS.DHCPInterface = "eth0" }, "only for upstream dhcp"},
		{"dns unknown template", func(d *Document) { d.Instances[0].DNS.Zones[0].Template = "work" }, `unknown template "work"`},
		{"dns forward-only no forwarders", func(d *Document) {
			d.Instances[0].DNS.Zones = append(d.Instances[0].DNS.Zones, DNSZone{Name: "int.example.com", Type: ZoneForwardOnly})
		}, "needs forwarders"},
		{"dns forward-only bad forwarder", func(d *Document) {
			d.Instances[0].DNS.Zones = append(d.Instances[0].DNS.Zones, DNSZone{Name: "int.example.com", Type: ZoneForwardOnly, Forwarders: []string{"1.2.3.4; }; evil"}})
		}, "invalid forwarder"},
		{"dns forwarders on a forward zone", func(d *Document) { d.Instances[0].DNS.Zones[0].Forwarders = []string{"1.2.3.4"} }, "only forward-only zones"},
		{"dns template unknown soa", func(d *Document) { d.Instances[0].DNS.ZoneTemplates[0].SOA = "x" }, `unknown soa template "x"`},
		{"dns template no ns", func(d *Document) { d.Instances[0].DNS.ZoneTemplates[0].Nameservers = nil }, "at least one nameserver"},
		{"dns template ns injection", func(d *Document) {
			d.Instances[0].DNS.ZoneTemplates[0].Nameservers = []string{"ns1.\n@ A 1.2.3.4"}
		}, "invalid nameserver"},
		{"dns template name injection", func(d *Document) { d.Instances[0].DNS.ZoneTemplates[0].Name = `a"; };` }, "invalid name"},
		{"soa bad mailbox", func(d *Document) { d.Instances[0].DNS.SOATemplates[0].RName = "admin@home.arpa" }, "invalid mailbox"},
		{"soa zero retry", func(d *Document) { d.Instances[0].DNS.SOATemplates[0].Retry = 0 }, "retry must be"},
		{"dnssec builtin name", func(d *Document) {
			d.Instances[0].DNS.DNSSECPolicies[0].Name = "default"
			d.Instances[0].DNS.ZoneTemplates[0].DNSSECPolicy = "default"
		}, "built-in BIND policy"},
		{"dnssec bad algorithm", func(d *Document) { d.Instances[0].DNS.DNSSECPolicies[0].KSKAlgorithm = "rsamd5" }, "ksk algorithm must be"},
		{"dnssec bad duration", func(d *Document) { d.Instances[0].DNS.DNSSECPolicies[0].SignaturesValidity = "14d; };" }, "invalid signatures-validity"},
		{"dnssec unknown policy", func(d *Document) { d.Instances[0].DNS.ZoneTemplates[0].DNSSECPolicy = "x" }, `unknown dnssec policy "x"`},
		{"dnat family mismatch", func(d *Document) { d.Instances[0].NAT[0].DstAddrs = []string{"2001:db8::1"} }, "differ in family"},
		{"dyndns unknown interface", func(d *Document) { d.Instances[0].DynDNS[0].Interface = "eth2" }, `unknown interface "eth2"`},
		{"dyndns server bad name", func(d *Document) { d.Instances[0].DynDNS[0].Server = "ns1" }, "not an IP address or DNS name"},
		{"dyndns server bad port", func(d *Document) { d.Instances[0].DynDNS[0].Server = "ns1.example.com:99999" }, "not an IP address or DNS name"},
		{"dyndns bad secret", func(d *Document) { d.Instances[0].DynDNS[0].TSIG.Secret = "not base64!" }, "TSIG secret must be base64"},
		{"dyndns bad algorithm", func(d *Document) { d.Instances[0].DynDNS[0].TSIG.Algorithm = "gss-tsig" }, "TSIG algorithm must be"},
		{"dyndns unknown provider", func(d *Document) { d.Instances[0].DynDNS[0].Provider = "nope" }, `unknown provider "nope"`},
		{"dyndns provider with server", func(d *Document) {
			d.Instances[0].DynDNS[0].Provider = "desec"
			d.Instances[0].DynDNS[0].ProviderSettings = map[string]string{"token": "t"}
		}, "for RFC 2136 only"},
		{"dyndns provider setting missing", func(d *Document) {
			dd := &d.Instances[0].DynDNS[0]
			dd.Provider, dd.Server, dd.TSIG = "porkbun", "", nil
			dd.ProviderSettings = map[string]string{"api_key": "k"}
		}, "Porkbun needs Secret API key"},
		{"dyndns provider unknown setting", func(d *Document) {
			dd := &d.Instances[0].DynDNS[0]
			dd.Provider, dd.Server, dd.TSIG = "desec", "", nil
			dd.ProviderSettings = map[string]string{"token": "t", "x": "y"}
		}, `has no setting "x"`},
		{"dyndns provider setting newline", func(d *Document) {
			dd := &d.Instances[0].DynDNS[0]
			dd.Provider, dd.Server, dd.TSIG = "desec", "", nil
			dd.ProviderSettings = map[string]string{"token": "a\nb"}
		}, "control characters"},
		{"cert unknown interface", func(d *Document) { d.Instances[0].Certificates[0].Interface = "eth9" }, `certificate "www": unknown interface "eth9"`},
		{"cert wildcard", func(d *Document) { d.Instances[0].Certificates[0].Domains[0] = "*.example.com" }, "cannot validate a wildcard"},
		{"cert upper case", func(d *Document) { d.Instances[0].Certificates[0].Domains[0] = "WWW.example.com" }, "is not a DNS name"},
		{"cert single label", func(d *Document) { d.Instances[0].Certificates[0].Domains[0] = "localhost" }, "is not a DNS name"},
		{"cert address", func(d *Document) { d.Instances[0].Certificates[0].Domains[0] = "192.0.2.1" }, "an IP address"},
		{"cert duplicate domain", func(d *Document) { d.Instances[0].Certificates[0].Domains[1] = "www.example.com" }, "twice"},
		{"cert common name not a domain", func(d *Document) { d.Instances[0].Certificates[0].CommonName = "mail.example.com" }, "not one of the domains"},
		{"cert no domains", func(d *Document) { d.Instances[0].Certificates[0].Domains = nil }, "needs 1-100 domains"},
		{"cert http ca", func(d *Document) { d.Instances[0].Certificates[0].CA = "http://ca.example.com/dir" }, "https URL"},
		{"cert key type", func(d *Document) { d.Instances[0].Certificates[0].KeyType = "dsa" }, "key type must be"},
		{"cert challenge", func(d *Document) { d.Instances[0].Certificates[0].Challenge = "dns-01" }, "challenge must be http-01"},
		{"cert email", func(d *Document) { d.Instances[0].Certificates[0].Email = "a b@example.com" }, "invalid email"},
		{"cert duplicate", func(d *Document) {
			d.Instances[0].Certificates = append(d.Instances[0].Certificates, d.Instances[0].Certificates[0])
		}, `certificate "www": duplicate`},
		{"dyndns no records", func(d *Document) { d.Instances[0].DynDNS[0].Records = nil }, "at least one record"},
		{"dyndns name outside zone", func(d *Document) { d.Instances[0].DynDNS[0].Records[0].Name = "home.example.org." }, "not in zone"},
		{"dyndns duplicate record", func(d *Document) { d.Instances[0].DynDNS[0].Records[1].Type = "A" }, "duplicate (one record per name and type)"},
		{"dyndns cname and other", func(d *Document) { d.Instances[0].DynDNS[0].Records[3].Name = "home" }, "has a CNAME and other records"},
		{"dyndns A with v6", func(d *Document) { d.Instances[0].DynDNS[0].Records[0].Value = "2001:db8::1" }, "invalid IPv4 address"},
		{"dyndns txt newline", func(d *Document) { d.Instances[0].DynDNS[0].Records[2].Value = "a\nb" }, "control characters"},
		{"unknown ip list", func(d *Document) { d.Instances[0].Rules[12].SrcAddrs = []string{"@nope"} }, `unknown ip list "nope"`},
		{"ip list in nat", func(d *Document) { d.Instances[0].NAT[1].SrcAddrs = []string{"@drop"} }, "only filter rules can use ip lists"},
		{"unknown address list", func(d *Document) { d.Instances[0].Rules[12].SrcAddrs = []string{"$nope"} }, `unknown address list "nope"`},
		{"address list of other instance", func(d *Document) { d.Instances[1].Rules[0].SrcAddrs = []string{"$admins"} }, `unknown address list "admins"`},
		{"address list in nat", func(d *Document) { d.Instances[0].NAT[1].SrcAddrs = []string{"$admins"} }, "only filter rules can use address lists"},
		{"address list bad address", func(d *Document) { d.Instances[0].AddressSets[0].Addresses[0] = "10.0.0.1; drop" }, `invalid address "10.0.0.1; drop"`},
		{"address list name newline", func(d *Document) { d.Instances[0].AddressSets[0].Name = "a\nb" }, "invalid name"},
		{"address list duplicate", func(d *Document) { d.Instances[0].AddressSets[1].Name = "admins" }, "duplicate"},
		{"ip list name newline", func(d *Document) { d.IPLists[1].Name = "drop\n}" }, "invalid name"},
		{"ip list duplicate", func(d *Document) { d.IPLists[1].Name = "crowdsec" }, "duplicate"},
		{"ip list bad source", func(d *Document) { d.IPLists[1].Source = "file" }, `invalid source "file"`},
		{"ip list file url", func(d *Document) { d.IPLists[1].URL = "file:///etc/shadow" }, "must start with http"},
		{"ip list url credentials", func(d *Document) { d.IPLists[1].URL = "https://u:p@example.com/x" }, "own fields"},
		{"ip list url newline", func(d *Document) { d.IPLists[1].URL = "https://example.com/\nx" }, "control characters"},
		{"crowdsec without key", func(d *Document) { d.IPLists[0].APIKey = "" }, "needs a bouncer api key"},
		{"crowdsec with password", func(d *Document) { d.IPLists[0].Username, d.IPLists[0].Password = "u", "p" }, "not a username and password"},
		{"password without user", func(d *Document) { d.IPLists[1].Password = "p" }, "needs a username"},
		{"username with colon", func(d *Document) { d.IPLists[1].Username = "a:b" }, "cannot contain ':'"},
		{"task bad schedule", func(d *Document) { d.Tasks[0].Schedule = "every 5 minutes" }, "schedule: want 5 fields"},
		{"task unknown list", func(d *Document) { d.Tasks[0].IPList = "nope" }, `unknown ip list "nope"`},
		{"task bad kind", func(d *Document) { d.Tasks[0].Kind = "reboot" }, `invalid kind "reboot"`},
		{"task empty command", func(d *Document) { d.Tasks[2].Command = " " }, "command is empty"},
		{"task command nul", func(d *Document) { d.Tasks[2].Command = "ls\x00" }, "NUL"},
		{"task timeout", func(d *Document) { d.Tasks[2].Timeout = -1 }, "timeout must be"},
		{"dns64 length", func(d *Document) { d.Instances[0].DNS.DNS64 = "64:ff9b::/80" }, "the length must be"},
		{"dns64 ipv4", func(d *Document) { d.Instances[0].DNS.DNS64 = "10.0.0.0/8" }, "invalid NAT64 prefix"},
		{"dns64 u octet", func(d *Document) { d.Instances[0].DNS.DNS64 = "2001:db8:0:0:100::/96" }, "bits 64 to 71"},
		{"pref64 host bits", func(d *Document) { d.Instances[0].RA[0].NAT64Prefix = "64:ff9b::1/96" }, "invalid NAT64 prefix"},
		{"pref64 injection", func(d *Document) { d.Instances[0].RA[0].NAT64Prefix = "64:ff9b::/96 { }; interface x" }, "invalid NAT64 prefix"},
		{"ipv6-only short", func(d *Document) { d.Instances[0].DHCP.Subnets[0].IPv6OnlyPreferred = 60 }, "IPv6-only preferred needs"},
		{"ipv6-only on ipv6", func(d *Document) { d.Instances[0].DHCP.Subnets[2].IPv6OnlyPreferred = 1800 }, "IPv6-only preferred needs"},
		{"nat64 prefix", func(d *Document) { d.Instances[0].NAT64.Prefix = "64:ff9b::/80" }, "nat64: NAT64 prefix"},
		{"nat64 pool", func(d *Document) { d.Instances[0].NAT64.Pool4 = []string{"2001:db8::/64"} }, "invalid IPv4 pool prefix"},
		{"nat64 pool host bits", func(d *Document) { d.Instances[0].NAT64.Pool4 = []string{"192.0.2.1/24"} }, "invalid IPv4 pool prefix"},
		{"nat64 interface", func(d *Document) { d.Instances[0].NAT64.Interfaces = []string{"eth9"} }, `nat64: unknown interface "eth9"`},
		{"ntp no servers", func(d *Document) { d.Instances[0].NTP.Servers = nil }, "ntp: no servers"},
		{"ntp server injection", func(d *Document) { d.Instances[0].NTP.Servers[0].Address = "x\nallow all" }, "ntp: invalid server"},
		{"ntp duplicate", func(d *Document) { d.Instances[0].NTP.Servers[1].Address = "time.cloudflare.com" }, "ntp: duplicate server"},
		{"ntp interface", func(d *Document) { d.Instances[0].NTP.Interfaces = []string{"eth9"} }, `ntp: unknown interface "eth9"`},
		{"ntp allow", func(d *Document) { d.Instances[0].NTP.Allow = []string{"all"} }, "ntp: invalid allow prefix"},
		{"snmp nothing", func(d *Document) { d.Instances[0].SNMP.Community, d.Instances[0].SNMP.Users = "", nil }, "snmp: no community and no users"},
		{"snmp community injection", func(d *Document) { d.Instances[0].SNMP.Community = "x\nrwcommunity y" }, "snmp: the community"},
		{"snmp community space", func(d *Document) { d.Instances[0].SNMP.Community = "a b" }, "snmp: the community"},
		{"snmp location", func(d *Document) { d.Instances[0].SNMP.Location = "a\nrwcommunity x" }, "location and contact"},
		{"snmp short password", func(d *Document) { d.Instances[0].SNMP.Users[0].AuthPassword = "short" }, "authentication password"},
		{"snmp priv password", func(d *Document) { d.Instances[0].SNMP.Users[0].PrivPassword = "a\"quote1" }, "privacy password"},
		{"snmp md5", func(d *Document) { d.Instances[0].SNMP.Users[0].AuthProtocol = "MD5" }, "authentication protocol"},
		{"snmp des", func(d *Document) { d.Instances[0].SNMP.Users[0].PrivProtocol = "DES" }, "privacy protocol"},
		{"snmp user name", func(d *Document) { d.Instances[0].SNMP.Users[0].Name = "a b" }, "user name"},
		{"snmp duplicate user", func(d *Document) { d.Instances[0].SNMP.Users[1].Name = "monitor" }, "duplicate user"},
		{"snmp interface", func(d *Document) { d.Instances[0].SNMP.Interfaces = []string{"eth9"} }, `snmp: unknown interface "eth9"`},
		{"snmp allow", func(d *Document) { d.Instances[0].SNMP.Allow = []string{"default"} }, "snmp: invalid allow prefix"},
		{"task duplicate", func(d *Document) { d.Tasks[1].Name = "crowdsec" }, "duplicate"},
		{"dyndns short retry", func(d *Document) { d.Instances[0].DynDNS[0].RetryInterval = 1 }, "retry interval must be"},
		// A zone may hold quotes and newlines: never an address.
		{"zone in nat target", func(d *Document) { d.Instances[0].NAT[0].ToAddr = "fe80::1%x\nchain evil {" }, "invalid target address"},
		{"zone in dns forwarder", func(d *Document) { d.Instances[0].DNS.Forwarders = []string{`fe80::1%x"; };`} }, "invalid forwarder"},
		{"zone in rule address", func(d *Document) { d.Instances[0].Rules[0].SrcAddrs = []string{"fe80::1%x accept"} }, "invalid address"},
		{"zone in dyndns server", func(d *Document) { d.Instances[0].DynDNS[0].Server = "[fe80::1%x]:53" }, "server"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := SampleDocument()
			tc.mutate(&doc)
			err := doc.Validate()
			if err == nil {
				t.Fatalf("expected error containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}

func TestExpandAddsLinkInterfaces(t *testing.T) {
	doc := SampleDocument().Expand()
	ifc := doc.Instance("guest").Interface("lk-main")
	if ifc == nil || ifc.Kind != KindLink || !ifc.Enabled {
		t.Fatalf("link end not expanded: %+v", ifc)
	}
	// Expand must not modify the original.
	orig := SampleDocument()
	if orig.Instance("guest").Interface("lk-main") != nil {
		t.Fatal("original modified")
	}
}

func TestMatchInterfaces(t *testing.T) {
	doc := SampleDocument().Expand()
	in := doc.Instance("main")
	in.Interface("eth1.20").Enabled = false
	cases := []struct {
		list []string
		want string
	}{
		{nil, ""},
		{[]string{"wan"}, "eth0"},
		{[]string{"lan", "vpn", "eth1"}, "eth1 wg0"},
		{[]string{"guest"}, "lk-guest"},
		{[]string{"dmz"}, ""},
		{[]string{"iot"}, ""}, // disabled member
	}
	for _, tc := range cases {
		if got := strings.Join(in.MatchInterfaces(tc.list), " "); got != tc.want {
			t.Errorf("%v: got %q, want %q", tc.list, got, tc.want)
		}
	}
}

func TestDynDNSOwner(t *testing.T) {
	cases := []struct{ name, want string }{
		{"@", "example.com."},
		{"home", "home.example.com."},
		{"Home.Example.com", "home.example.com."},
		{"home.example.com.", "home.example.com."},
		{"a.b", "a.b.example.com."},
		{"x.example.org.", ""},
	}
	for _, tc := range cases {
		got, err := DynDNSOwner(tc.name, "example.com")
		if tc.want == "" {
			if err == nil {
				t.Errorf("%q: expected error, got %q", tc.name, got)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("%q: got %q %v, want %q", tc.name, got, err, tc.want)
		}
	}
	for s, want := range map[string]string{
		"192.0.2.53": "192.0.2.53:53", "192.0.2.53:5353": "192.0.2.53:5353",
		"2001:db8::53": "[2001:db8::53]:53", "[2001:db8::53]:54": "[2001:db8::53]:54",
		"NS1.Example.com.": "ns1.example.com:53", "ns1.example.com:5353": "ns1.example.com:5353",
		"ns1": "", "ns1.example.com:0": "", "a b.example.com": "", "[fe80::1%x]:53": "", "ns1.example.com\n": "",
	} {
		if got, err := DynDNSServer(s); got != want || (err == nil) != (want != "") {
			t.Errorf("server %q: got %q %v, want %q", s, got, err, want)
		}
	}
}

func TestParsePorts(t *testing.T) {
	got, err := ParsePorts("22, 80-90,443")
	if err != nil || len(got) != 3 || got[1] != (PortRange{80, 90}) {
		t.Fatalf("got %v %v", got, err)
	}
	got, err = ParsePorts("ssh, SNMP,netbios-ns,8000-8080")
	if err != nil || len(got) != 4 || got[0] != (PortRange{22, 22}) || got[1] != (PortRange{161, 161}) ||
		got[2] != (PortRange{137, 137}) || got[3] != (PortRange{8000, 8080}) {
		t.Fatalf("names: got %v %v", got, err)
	}
	for _, bad := range []string{"", "0", "65536", "a", "5-", "1,,2", "nosuchservice", "ssh-https"} {
		if _, err := ParsePorts(bad); err == nil {
			t.Errorf("%q: expected error", bad)
		}
	}
}

func TestServices(t *testing.T) {
	seen := map[string]bool{}
	for i, s := range Services {
		if seen[s.Name] {
			t.Errorf("duplicate service %q", s.Name)
		}
		seen[s.Name] = true
		if s.Port < 1 || s.Port > 65535 || (i > 0 && s.Port < Services[i-1].Port) {
			t.Errorf("service %q: port %d out of range or order", s.Name, s.Port)
		}
	}
}

func TestMatchFamilies(t *testing.T) {
	dual := []string{"192.168.1.10", "fd00::10"}
	cases := []struct {
		name          string
		family, proto string
		src, dst      []string
		want          []string // family: src|dst
	}{
		{"no addresses", "", "tcp", nil, nil, []string{":|"}},
		{"no addresses, v6 only", "ipv6", "", nil, nil, []string{"ipv6:|"}},
		{"dual destination", "", "tcp", nil, dual, []string{"ipv4:|192.168.1.10", "ipv6:|fd00::10"}},
		{"family narrows", "ipv6", "", nil, dual, []string{"ipv6:|fd00::10"}},
		{"icmp narrows", "", "icmp", nil, dual, []string{"ipv4:|192.168.1.10"}},
		{"v4 source leaves out v6", "", "", []string{"10.0.0.0/8"}, dual, []string{"ipv4:10.0.0.0/8|192.168.1.10"}},
		{"nothing in common", "", "", []string{"10.0.0.0/8"}, []string{"fd00::/8"}, nil},
		{"ip list in both", "", "", []string{"@bl"}, nil, []string{"ipv4:@bl|", "ipv6:@bl|"}},
		{"ip list with v4 literal", "", "", []string{"@bl", "10.0.0.0/8"}, nil, []string{"ipv4:@bl,10.0.0.0/8|", "ipv6:@bl|"}},
		{"ip list against v6 destination", "", "", []string{"@bl"}, []string{"fd00::/8"}, []string{"ipv6:@bl|fd00::/8"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			for _, m := range MatchFamilies(tc.family, tc.proto, tc.src, tc.dst) {
				got = append(got, m.Family+":"+strings.Join(m.Src, ",")+"|"+strings.Join(m.Dst, ","))
			}
			if strings.Join(got, " ") != strings.Join(tc.want, " ") {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestWireGuardRoutes(t *testing.T) {
	doc := SampleDocument()
	in := &doc.Instances[0]
	got := in.WireGuardRoutes()
	if len(got) != 1 || got[0] != (Route{Destination: "192.168.50.0/24", Interface: "wg0"}) {
		t.Errorf("routes %+v", got)
	}
	peer := &in.Interfaces[3].WireGuard.Peers[1]
	if ips := peer.AllAllowedIPs(); strings.Join(ips, ",") != "10.99.0.3/32,192.168.50.0/24" {
		t.Errorf("allowed ips %v", ips)
	}
	in.Interfaces[3].Enabled = false
	if got := in.WireGuardRoutes(); len(got) != 0 {
		t.Errorf("disabled interface routed: %+v", got)
	}
}

func TestItemNames(t *testing.T) {
	for name, ok := range map[string]bool{
		"www.example.com": true, "mail-2026": true, "a_b": true, "1st": true,
		".hidden": true, "-x": true, "WWW": true, "a b": true, "Kontor Göteborg": true,
		".": false, "..": false, "a/b": false, "": false, " a": false, "a\nb": false,
	} {
		if ValidFileName(name) != ok {
			t.Errorf("%q: want %v", name, ok)
		}
		d := SampleDocument()
		d.Instances[0].Certificates[0].Name = name
		d.Instances[0].DynDNS[0].Name = name
		if err := d.Validate(); (err == nil) != ok {
			t.Errorf("%q: validate %v", name, err)
		}
	}
}
