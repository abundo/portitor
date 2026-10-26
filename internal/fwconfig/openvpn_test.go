// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package fwconfig

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func TestOpenVPNExpand(t *testing.T) {
	d := SampleDocument()
	exp := d.Expand()
	in := &exp.Instances[0]
	udp, tcp := in.Interface("ovpn0"), in.Interface("ovt-ovpn0")
	if udp == nil || tcp == nil {
		t.Fatalf("devices: %v %v", udp, tcp)
	}
	if udp.OpenVPN.Proto != OpenVPNUDP || tcp.OpenVPN.Proto != OpenVPNTCP || tcp.Parent != "ovpn0" {
		t.Errorf("protocols %q %q, parent %q", udp.OpenVPN.Proto, tcp.OpenVPN.Proto, tcp.Parent)
	}
	if got := strings.Join(udp.OpenVPN.Pools, " "); got != "10.8.0.0/25 fd00:8::/65" {
		t.Errorf("udp pools %s", got)
	}
	if got := strings.Join(tcp.OpenVPN.Pools, " "); got != "10.8.0.128/25 fd00:8:0:0:8000::/65" {
		t.Errorf("tcp pools %s", got)
	}
	if got := strings.Join(tcp.Addresses, " "); got != "10.8.0.129/25 fd00:8::8000:0:0:1/65" {
		t.Errorf("tcp addresses %s", got)
	}
	if got := strings.Join(tcp.OpenVPN.Prefixes, " "); got != "10.8.0.0/24 fd00:8::/64" {
		t.Errorf("tcp prefixes %s", got)
	}
	// The document itself is left alone.
	if d.Instances[0].Interfaces[5].OpenVPN.Proto != "" || len(d.Instances[0].Interfaces) != 6 {
		t.Errorf("Expand changed the document")
	}
	// A rule naming the interface, or a zone holding it, matches both.
	if got := in.MatchInterfaces([]string{"ovpn0"}); !slices.Equal(got, []string{"ovpn0", "ovt-ovpn0"}) {
		t.Errorf("match %v", got)
	}

	d.Instances[0].Interfaces[5].OpenVPN.Mode = OpenVPNTCP
	exp = d.Expand()
	if in := &exp.Instances[0]; in.Interface("ovt-ovpn0") != nil || in.Interface("ovpn0").OpenVPN.Proto != OpenVPNTCP ||
		strings.Join(in.Interface("ovpn0").OpenVPN.Pools, " ") != "10.8.0.0/24 fd00:8::/64" {
		t.Errorf("tcp only: %+v", in.Interface("ovpn0").OpenVPN)
	}
	if err := d.Validate(); err != nil {
		t.Errorf("tcp only: %v", err)
	}
}

func TestOpenVPNPool(t *testing.T) {
	for _, c := range []struct {
		pool, server, first, last string
	}{
		{"10.8.0.0/24", "10.8.0.1", "10.8.0.2", "10.8.0.254"},
		{"10.8.0.0/24", "10.8.0.254", "10.8.0.1", "10.8.0.253"},
		{"10.8.0.0/24", "10.8.0.100", "10.8.0.101", "10.8.0.254"},
		{"10.8.0.0/25", "10.8.0.1", "10.8.0.2", "10.8.0.126"},
		{"10.8.0.128/25", "10.8.0.129", "10.8.0.130", "10.8.0.254"},
		{"10.8.0.128/25", "10.8.0.1", "10.8.0.129", "10.8.0.254"},
		{"fd00:8::/64", "fd00:8::1", "fd00:8::2", "fd00:8::ffff:ffff:ffff:ffff"},
	} {
		first, last, ok := OpenVPNPool(netip.MustParsePrefix(c.pool), netip.MustParseAddr(c.server))
		if !ok || first.String() != c.first || last.String() != c.last {
			t.Errorf("%s %s: %v %v %v", c.pool, c.server, first, last, ok)
		}
	}
	if _, _, ok := OpenVPNPool(netip.MustParsePrefix("10.8.0.0/31"), netip.MustParseAddr("10.8.0.1")); ok {
		t.Error("/31 has room")
	}
}

func TestOpenVPNKey(t *testing.T) {
	k, err := GenerateOpenVPNKey()
	if err != nil || !tlsCryptRe.MatchString(k) || !tlsCryptRe.MatchString(SampleTLSCrypt) {
		t.Fatalf("key %v:\n%s", err, k)
	}
}

func TestValidateOpenVPN(t *testing.T) {
	ovpn := func(d *Document) *Interface { return &d.Instances[0].Interfaces[5] }
	for _, c := range []struct {
		name   string
		mutate func(*Document)
		want   string
	}{
		{"mode", func(d *Document) { ovpn(d).OpenVPN.Mode = "both" }, "mode must be one of"},
		{"port", func(d *Document) { ovpn(d).OpenVPN.Port = 0 }, "port must be 1-65535"},
		{"listen", func(d *Document) { ovpn(d).OpenVPN.Listen = "eth9" }, `unknown listen interface "eth9"`},
		{"certificate", func(d *Document) { ovpn(d).OpenVPN.Certificate = "nope" }, `unknown certificate "nope"`},
		{"key", func(d *Document) { ovpn(d).OpenVPN.TLSCrypt = "x" }, "invalid tls-crypt key"},
		{"user", func(d *Document) { ovpn(d).OpenVPN.Users[0].Name = "a b" }, "invalid user name"},
		{"hash", func(d *Document) { ovpn(d).OpenVPN.Users[0].Hash = "plain" }, "invalid password hash"},
		{"duplicate user", func(d *Document) { o := ovpn(d).OpenVPN; o.Users = append(o.Users, o.Users[0]) }, "duplicate user"},
		{"hash of a directory user", func(d *Document) { ovpn(d).OpenVPN.Users[1].Hash = ovpn(d).OpenVPN.Users[0].Hash }, "invalid password hash"},
		{"role group", func(d *Document) { ovpn(d).OpenVPN.RoleGroups = []string{"CN=a\nx"} }, "invalid role group"},
		{"route", func(d *Document) { ovpn(d).OpenVPN.Routes = []string{"10.0.0.1\npush x"} }, "invalid route"},
		{"dns", func(d *Document) { ovpn(d).OpenVPN.DNS = []string{"dns.example"} }, "invalid DNS server"},
		{"domain", func(d *Document) { ovpn(d).OpenVPN.DNSDomain = `a" b` }, "invalid DNS domain"},
		{"dhcp", func(d *Document) { ovpn(d).IPv4Mode = ModeDHCP }, "dhcp client is not supported on openvpn"},
		{"no address", func(d *Document) { ovpn(d).Addresses = nil }, "needs an IPv4 or IPv6 address"},
		{"two v4", func(d *Document) { ovpn(d).Addresses = []string{"10.8.0.1/24", "10.9.0.1/24"} }, "one address per IP version"},
		{"small v4", func(d *Document) { ovpn(d).Addresses = []string{"10.8.0.1/30"} }, "the IPv4 prefix must be /16 to /29"},
		{"small v6", func(d *Document) { ovpn(d).Addresses = []string{"fd00:8::1/120"} }, "the IPv6 prefix must be /111 or shorter"},
		{"delegated", func(d *Document) { ovpn(d).Addresses = []string{"<eth0>:8::1/64"} }, "no delegated address"},
		{"two servers", func(d *Document) {
			o := *ovpn(d)
			o.Name, o.Addresses = "ovpn1", []string{"10.9.0.1/24"}
			d.Instances[0].Interfaces = append(d.Instances[0].Interfaces, o)
		}, "at most one OpenVPN interface"},
		{"reserved name", func(d *Document) { d.Instances[0].Interfaces[1].Name = "ovt-x" }, "names are for OpenVPN TCP devices"},
		{"ldap host", func(d *Document) { d.Directory.Servers[0].Host = "dc 1" }, "host must be"},
		{"ldap filter", func(d *Document) { d.Directory.Servers[0].UserFilter = "(uid=bob)" }, "hold %s once"},
		{"ldap filter verb", func(d *Document) { d.Directory.Servers[0].UserFilter = "(uid=%s%d)" }, "hold %s once"},
		{"ldap newline", func(d *Document) { d.Directory.Servers[0].BaseDN = "DC=a\nDC=b" }, "base DN must be one line"},
		{"ldap tls", func(d *Document) { d.Directory.Servers[0].TLSMode = "ssl" }, "TLS must be"},
		{"ldap ca", func(d *Document) { d.Directory.Servers[0].CACert = "not pem" }, "CA certificate must be PEM"},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := SampleDocument()
			c.mutate(&d)
			err := d.Validate()
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("want %q, got %v", c.want, err)
			}
		})
	}
}

func TestCheckOpenVPNAddresses(t *testing.T) {
	for _, c := range []struct {
		mode  string
		addrs []string
		ok    bool
	}{
		{OpenVPNAdaptive, []string{"10.8.0.1/24", "fd00:8::1/64"}, true},
		{OpenVPNUDP, []string{"10.8.0.1/30"}, true},
		{OpenVPNAdaptive, []string{"10.8.0.1/30"}, false},
		// Dual stack: as many IPv6 addresses as IPv4 clients will do.
		{OpenVPNUDP, []string{"10.8.0.1/24", "fd00:8::1/112"}, true},
		{OpenVPNAdaptive, []string{"10.8.0.1/24", "fd00:8::1/111"}, true},
		// IPv6 alone: OpenVPN's whole pool.
		{OpenVPNUDP, []string{"fd00:8::1/112"}, false},
		{OpenVPNUDP, []string{"fd00:8::1/111"}, true},
		{OpenVPNUDP, []string{"fd00:8::1/64"}, true},
		{OpenVPNUDP, nil, false},
	} {
		if got := CheckOpenVPNAddresses(c.mode, c.addrs); (len(got) == 0) != c.ok {
			t.Errorf("%s %v: %v", c.mode, c.addrs, got)
		}
	}
}
