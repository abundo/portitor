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

func TestValidateCatchesProblems(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(d *Document)
		want   string
	}{
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
		{"zone name injection", func(d *Document) { d.Instances[0].InterfaceZones[0].Name = `wan" accept` }, "name must match"},
		{"ports without proto", func(d *Document) { d.Instances[0].Rules[0].DstPorts = "22" }, "ports need protocol"},
		{"bad port range", func(d *Document) { d.Instances[0].Rules[2].DstPorts = "90-80" }, "invalid port range"},
		{"ifname injection", func(d *Document) { d.Instances[0].Interfaces[1].Name = `eth1" accept` }, "name must match"},
		{"comment with match", func(d *Document) { d.Instances[0].Rules[11].Protocol = "tcp" }, "a comment has only"},
		{"bad rule kind", func(d *Document) { d.Instances[0].Rules[0].Kind = "note" }, `invalid kind "note"`},
		{"comment newline", func(d *Document) { d.Instances[0].Rules[0].Description = "a\nflush ruleset" }, "control characters"},
		{"no common family", func(d *Document) {
			d.Instances[0].Rules[0].SrcAddrs = []string{"10.0.0.0/8"}
			d.Instances[0].Rules[0].DstAddrs = []string{"fd00::/8"}
		}, "no IP version fits"},
		{"icmp with only v6 addresses", func(d *Document) {
			d.Instances[0].Rules[5].SrcAddrs = []string{"2001:db8::/32"}
		}, "no IP version fits"},
		{"family against protocol", func(d *Document) { d.Instances[0].Rules[5].Family = "ipv6" }, "does not match family"},
		{"slaac needs /64", func(d *Document) { d.Instances[0].RA[0].Prefixes[0].Prefix = "fd00:1::/56" }, "needs a /64"},
		{"ra unknown interface", func(d *Document) { d.Instances[0].RA[0].Interface = "eth9" }, "unknown interface"},
		{"ra v4 dns", func(d *Document) { d.Instances[0].RA[0].RDNSS = []string{"192.168.1.1"} }, "invalid IPv6 dns server"},
		{"dhcpv6 without ra", func(d *Document) { d.Instances[0].RA = nil }, "DHCPv6 needs router advertisements"},
		{"dhcpv6 gateway", func(d *Document) { d.Instances[0].DHCP.Subnets[2].Gateway = "fd00:1::1" }, "learn the gateway"},
		{"dhcp dns family", func(d *Document) { d.Instances[0].DHCP.Subnets[2].DNSServers = []string{"192.168.1.1"} }, "IP version"},
		{"route gateway family", func(d *Document) { d.Instances[0].Routes[0].Gateway = "fd00:1::fe" }, "differ in family"},
		{"dhcp range outside", func(d *Document) { d.Instances[0].DHCP.Subnets[0].RangeEnd = "10.0.0.1" }, "not inside the prefix"},
		{"bad wg key", func(d *Document) { d.Instances[0].Interfaces[3].WireGuard.PrivateKey = "nope" }, "invalid private key"},
		{"link same instance", func(d *Document) { d.Links[0].B.Instance = "main" }, "both ends"},
		{"physical in two instances", func(d *Document) { d.Instances[1].Interfaces[0].Name = "eth0" }, "already used by instance"},
		{"dns record injection", func(d *Document) {
			d.Instances[0].DNS.Zones[0].Records[0].Value = "1.2.3.4\n@ NS evil."
		}, "newline"},
		{"dns forward mode", func(d *Document) { d.Instances[0].DNS.ForwardMode = "last" }, `invalid forward mode "last"`},
		{"dns unknown template", func(d *Document) { d.Instances[0].DNS.Zones[0].Template = "work" }, `unknown template "work"`},
		{"dns template unknown soa", func(d *Document) { d.Instances[0].DNS.ZoneTemplates[0].SOA = "x" }, `unknown soa template "x"`},
		{"dns template no ns", func(d *Document) { d.Instances[0].DNS.ZoneTemplates[0].Nameservers = nil }, "at least one nameserver"},
		{"dns template ns injection", func(d *Document) {
			d.Instances[0].DNS.ZoneTemplates[0].Nameservers = []string{"ns1.\n@ A 1.2.3.4"}
		}, "invalid nameserver"},
		{"dns template name injection", func(d *Document) { d.Instances[0].DNS.ZoneTemplates[0].Name = `a"; };` }, "name must match"},
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
		{"dyndns server name", func(d *Document) { d.Instances[0].DynDNS[0].Server = "ns1.example.com:53" }, "not an IP address"},
		{"dyndns bad secret", func(d *Document) { d.Instances[0].DynDNS[0].TSIG.Secret = "not base64!" }, "TSIG secret must be base64"},
		{"dyndns bad algorithm", func(d *Document) { d.Instances[0].DynDNS[0].TSIG.Algorithm = "gss-tsig" }, "TSIG algorithm must be"},
		{"dyndns no records", func(d *Document) { d.Instances[0].DynDNS[0].Records = nil }, "at least one record"},
		{"dyndns name outside zone", func(d *Document) { d.Instances[0].DynDNS[0].Records[0].Name = "home.example.org." }, "not in zone"},
		{"dyndns duplicate record", func(d *Document) { d.Instances[0].DynDNS[0].Records[1].Type = "A" }, "duplicate (one record per name and type)"},
		{"dyndns cname and other", func(d *Document) { d.Instances[0].DynDNS[0].Records[3].Name = "home" }, "has a CNAME and other records"},
		{"dyndns A with v6", func(d *Document) { d.Instances[0].DynDNS[0].Records[0].Value = "2001:db8::1" }, "invalid IPv4 address"},
		{"dyndns txt newline", func(d *Document) { d.Instances[0].DynDNS[0].Records[2].Value = "a\nb" }, "control characters"},
		{"dyndns short retry", func(d *Document) { d.Instances[0].DynDNS[0].RetryInterval = 1 }, "retry interval must be"},
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
	for s, want := range map[string]string{"192.0.2.53": "192.0.2.53:53", "192.0.2.53:5353": "192.0.2.53:5353", "2001:db8::53": "[2001:db8::53]:53", "[2001:db8::53]:54": "[2001:db8::53]:54"} {
		if got, err := DynDNSServerAddr(s); err != nil || got.String() != want {
			t.Errorf("server %q: got %v %v, want %s", s, got, err, want)
		}
	}
}

func TestParsePorts(t *testing.T) {
	got, err := ParsePorts("22, 80-90,443")
	if err != nil || len(got) != 3 || got[1] != (PortRange{80, 90}) {
		t.Fatalf("got %v %v", got, err)
	}
	for _, bad := range []string{"", "0", "65536", "a", "5-", "1,,2"} {
		if _, err := ParsePorts(bad); err == nil {
			t.Errorf("%q: expected error", bad)
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
