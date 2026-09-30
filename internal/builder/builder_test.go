// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package builder

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/abundo/portitor/internal/dbmigrate"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/wgkeys"
	"github.com/abundo/portitor/models"
)

func testDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := dbmigrate.Open(filepath.Join(t.TempDir(), "db.sqlite"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	if err := dbmigrate.Up(db); err != nil {
		t.Fatal(err)
	}
	return db
}

func mustCreate(t *testing.T, db *gorm.DB, v any) {
	t.Helper()
	if err := db.Create(v).Error; err != nil {
		t.Fatal(err)
	}
}

func ptr(v uint) *uint { return &v }

func TestBuildHome(t *testing.T) {
	db := testDB(t)
	main := models.Instance{Name: "main", IsDefault: true, DnsEnabled: true, DnsUpstream: "dhcp",
		DhcpEnabled: true, DhcpDomainName: "home.arpa", DhcpLeaseTime: 3600}
	mustCreate(t, db, &main)
	mustCreate(t, db, &models.InterfaceZone{InstanceID: main.ID, Name: "lan", Interfaces: models.StringList{"eth1", "wg0"}})
	mustCreate(t, db, &models.InterfaceZone{InstanceID: main.ID, Name: "empty"})

	eth0 := models.Interface{InstanceID: main.ID, Name: "eth0", Kind: "physical", Enabled: true, Ipv4Mode: "dhcp", DnsFromDhcp: true}
	eth1 := models.Interface{InstanceID: main.ID, Name: "eth1", Kind: "physical", Enabled: true, Ipv4Mode: "static", DnsListen: true,
		Addresses: models.StringList{"192.168.1.1/24"}}
	priv, _, _ := wgkeys.Generate()
	wg0 := models.Interface{InstanceID: main.ID, Name: "wg0", Kind: "wireguard", Enabled: true, Ipv4Mode: "static", WgPrivateKey: priv, WgListenPort: 51820,
		Addresses: models.StringList{"10.99.0.1/24"}}
	for _, i := range []*models.Interface{&eth0, &eth1, &wg0} {
		mustCreate(t, db, i)
	}
	_, peerPub, _ := wgkeys.Generate()
	mustCreate(t, db, &models.WgPeer{InterfaceID: wg0.ID, Name: "phone", Enabled: true, PublicKey: peerPub, AllowedIPs: models.StringList{"10.99.0.2/32"}})
	_, oldPub, _ := wgkeys.Generate()
	mustCreate(t, db, &models.WgPeer{InterfaceID: wg0.ID, Name: "old", Enabled: false, PublicKey: oldPub})

	mustCreate(t, db, &models.IpamPrefix{InstanceID: main.ID, Prefix: "192.168.0.0/16"})
	mustCreate(t, db, &models.IpamPrefix{InstanceID: main.ID, Prefix: "192.168.1.0/24", DhcpEnabled: true, DhcpRangeStart: "192.168.1.100", DhcpRangeEnd: "192.168.1.199"})
	mustCreate(t, db, &models.IpamPrefix{InstanceID: main.ID, Prefix: "10.99.0.0/24"})
	mustCreate(t, db, &models.IpamAddress{InstanceID: main.ID, Address: "192.168.1.1", DnsName: "gw.home.arpa"})
	mustCreate(t, db, &models.IpamAddress{InstanceID: main.ID, Address: "192.168.1.10", DnsName: "nas.home.arpa", Mac: "02:00:00:00:00:10"})

	soa := models.DnsSoaTemplate{Name: "home", Mname: "gw.home.arpa", Rname: "hostmaster.home.arpa", Refresh: 86400, Retry: 7200, Expire: 3600000, Minimum: 3600}
	mustCreate(t, db, &soa)
	policy := models.DnsDnssecPolicy{Name: "signed", KskAlgorithm: "ed25519", ZskAlgorithm: "ed25519"}
	mustCreate(t, db, &policy)
	tmpl := models.DnsTemplate{Name: "home", SoaTemplateID: soa.ID, DefaultTtl: 600, DnssecPolicyID: &policy.ID,
		// gw's A record comes from IPAM already; ns.example.com is in no zone here.
		Nameservers: models.DnsNameserverList{{Name: "gw.home.arpa", Address: "192.168.1.1"}, {Name: "gw.home.arpa", Address: "fd00::1"},
			{Name: "ns1.home.arpa", Address: "192.168.1.2"}, {Name: "ns.example.com", Address: "192.0.2.53"}}}
	mustCreate(t, db, &tmpl)
	// Not used by any zone: stays out of the document.
	mustCreate(t, db, &models.DnsTemplate{Name: "unused", SoaTemplateID: soa.ID, DefaultTtl: 600, Nameservers: models.DnsNameserverList{{Name: "ns.example.com"}}})

	zone := models.DnsZone{InstanceID: main.ID, Name: "home.arpa", Type: "forward", DnsTemplateID: &tmpl.ID}
	mustCreate(t, db, &zone)
	mustCreate(t, db, &models.DnsZone{InstanceID: main.ID, Name: "192.168.1.0/24", Type: "reverse4", DnsTemplateID: &tmpl.ID})
	mustCreate(t, db, &models.DnsRecord{ZoneID: zone.ID, Name: "www", Type: "CNAME", Value: "nas"})

	mustCreate(t, db, &models.Service{Name: "app", Type: models.ServiceTypePorts, Ports: models.ServicePortList{{Protocol: "udp", DstLo: 9000, DstHi: 9010}}})
	mustCreate(t, db, &models.Rule{InstanceID: main.ID, Position: 2, Chain: "forward", InInterfaces: models.StringList{"lan"}, OutInterfaces: models.StringList{"eth0"}, Action: "accept", Enabled: true, Description: "second"})
	mustCreate(t, db, &models.Rule{InstanceID: main.ID, Position: 1, Chain: "input", InInterfaces: models.StringList{"eth0"}, Services: models.StringList{"ping", "app"}, Action: "accept", Enabled: true, Description: "first"})
	mustCreate(t, db, &models.Rule{InstanceID: main.ID, Position: 3, Chain: "forward", Action: "accept", Enabled: false})
	mustCreate(t, db, &models.Rule{InstanceID: main.ID, Position: 4, Chain: "forward", Kind: models.RuleKindComment, Enabled: true, Description: "a comment"})
	mustCreate(t, db, &models.Rule{InstanceID: main.ID, Position: 5, Chain: "forward", Kind: models.RuleKindGroup, Enabled: true, Description: "LAN"})
	mustCreate(t, db, &models.NatRule{InstanceID: main.ID, Kind: "dnat", InInterfaces: models.StringList{"eth0"}, Protocol: "tcp", DstPorts: "443", ToAddr: "192.168.1.10", Enabled: true})

	doc, err := Build(db, 42)
	if err != nil {
		t.Fatal(err)
	}
	in := doc.Instance("main")
	if doc.Generation != 42 || in == nil {
		t.Fatalf("%+v", doc)
	}
	if got := in.Interface("eth1").Addresses; len(got) != 1 || got[0] != "192.168.1.1/24" {
		t.Errorf("eth1 addresses %v", got)
	}
	if len(in.InterfaceZones) != 2 || in.InterfaceZones[1].Name != "lan" || strings.Join(in.InterfaceZones[1].Interfaces, " ") != "eth1 wg0" ||
		in.InterfaceZones[0].Interfaces == nil {
		t.Errorf("interface zones %+v", in.InterfaceZones)
	}
	if r := in.Rules[1]; strings.Join(r.InInterfaces, " ") != "lan" || strings.Join(r.OutInterfaces, " ") != "eth0" {
		t.Errorf("rule interfaces %+v", r)
	}
	if wg := in.Interface("wg0").WireGuard; wg == nil || len(wg.Peers) != 1 {
		t.Errorf("wireguard peers: %+v (disabled peers must be left out)", wg)
	}
	if len(in.Rules) != 4 || in.Rules[0].Description != "first" || in.Rules[2].Kind != fwconfig.RuleKindComment || in.Rules[2].Description != "a comment" ||
		in.Rules[3].Kind != fwconfig.RuleKindComment || in.Rules[3].Description != "group: LAN" {
		t.Errorf("rules not ordered by position / disabled not skipped / comment or group not kept: %+v", in.Rules)
	}
	if got, want := in.Rules[0].Services, []fwconfig.ServiceMatch{{Protocol: "icmp", ICMPType: "echo-request"}, {Protocol: "udp", DstPorts: "9000-9010"}}; !reflect.DeepEqual(got, want) {
		t.Errorf("services %+v, want %+v", got, want)
	}
	if in.Rules[0].ID == 0 || in.Rules[1].ID == 0 || in.Rules[0].ID == in.Rules[1].ID || in.Rules[2].ID != 0 || in.Rules[3].ID != 0 {
		t.Errorf("rule ids must be the database ids, none on comments: %+v", in.Rules)
	}
	if len(in.DHCP.Subnets) != 1 {
		t.Fatalf("dhcp subnets %+v", in.DHCP.Subnets)
	}
	s := in.DHCP.Subnets[0]
	if s.Interface != "eth1" || s.Gateway != "192.168.1.1" || len(s.DNSServers) != 1 || s.DNSServers[0] != "192.168.1.1" {
		t.Errorf("dhcp subnet defaults: %+v", s)
	}
	dns := in.DNS
	if len(dns.ZoneTemplates) != 1 || len(dns.SOATemplates) != 1 || len(dns.DNSSECPolicies) != 1 {
		t.Errorf("dns templates: %+v %+v %+v (want only the used ones, once)", dns.ZoneTemplates, dns.SOATemplates, dns.DNSSECPolicies)
	} else if zt := dns.ZoneTemplates[0]; zt.SOA != "home" || zt.DNSSECPolicy != "signed" || zt.DefaultTTL != 600 {
		t.Errorf("zone template %+v", zt)
	}
	if in.DNS.Upstream != "dhcp" || in.DNS.DHCPInterface != "eth0" || in.DNS.Forwarders != nil {
		t.Errorf("dns upstream %q %q %v", in.DNS.Upstream, in.DNS.DHCPInterface, in.DNS.Forwarders)
	}
	fwd := in.DNS.Zones[1] // zones are ordered by name
	if fwd.Name != "home.arpa" || fwd.Template != "home" {
		t.Fatalf("zone %+v", fwd)
	}
	recs := fwd.Records
	var names []string
	for _, r := range recs {
		names = append(names, r.Name+"/"+r.Type+"/"+r.MAC)
	}
	joined := strings.Join(names, " ")
	for _, want := range []string{"www/CNAME/", "gw/A/", "gw/AAAA/", "ns1/A/", "nas/A/02:00:00:00:00:10"} {
		if !strings.Contains(joined, want) {
			t.Errorf("records %s lack %s", joined, want)
		}
	}
	if strings.Count(joined, "gw/A/") != 1 {
		t.Errorf("records %s: the nameserver's A record repeats the IPAM one", joined)
	}
	if zt := dns.ZoneTemplates[0]; strings.Join(zt.Nameservers, " ") != "gw.home.arpa ns1.home.arpa ns.example.com" {
		t.Errorf("zone template nameservers %v", zt.Nameservers)
	}
}

func TestBuildReportsProblems(t *testing.T) {
	db := testDB(t)
	main := models.Instance{Name: "main", IsDefault: true}
	mustCreate(t, db, &main)
	mustCreate(t, db, &models.Interface{InstanceID: main.ID, Name: "eth1", Kind: "physical", Enabled: true, Ipv4Mode: "static",
		Addresses: models.StringList{"192.168.1.0/24"}})
	mustCreate(t, db, &models.IpamAddress{InstanceID: main.ID, Address: "192.168.1.9", Mac: "02:00:00:00:00:09"})
	mustCreate(t, db, &models.Rule{InstanceID: main.ID, Chain: "input", Services: models.StringList{"ghost"}, Action: "accept", Enabled: true})

	_, err := Build(db, 1)
	ve, ok := err.(*fwconfig.ValidationError)
	if !ok {
		t.Fatalf("want ValidationError, got %v", err)
	}
	joined := strings.Join(ve.Problems, "\n")
	for _, want := range []string{"192.168.1.0 is the network address", "MAC but no DNS name", `unknown service "ghost"`} {
		if !strings.Contains(joined, want) {
			t.Errorf("problems lack %q:\n%s", want, joined)
		}
	}
}

func TestBuildIPv6AndObjects(t *testing.T) {
	db := testDB(t)
	main := models.Instance{Name: "main", IsDefault: true, DnsEnabled: true, DhcpEnabled: true, DhcpDomainName: "home.arpa",
		DnsForwarders: models.StringList{"quad9"}}
	mustCreate(t, db, &main)
	mustCreate(t, db, &models.Interface{InstanceID: main.ID, Name: "eth0", Kind: "physical", Enabled: true, Ipv4Mode: "dhcp", Ipv6AcceptRA: true})
	mustCreate(t, db, &models.Interface{InstanceID: main.ID, Name: "eth1", Kind: "physical", Enabled: true, Ipv4Mode: "static", DnsListen: true,
		Addresses: models.StringList{"192.168.1.1/24", "fd00:1::1/64"}})

	mustCreate(t, db, &models.IpamPrefix{InstanceID: main.ID, Prefix: "192.168.1.0/24", DhcpEnabled: true, DhcpRangeStart: "192.168.1.100", DhcpRangeEnd: "192.168.1.199"})
	mustCreate(t, db, &models.IpamPrefix{InstanceID: main.ID, Prefix: "fd00:1::/64", RaEnabled: true, RaSlaac: true, DhcpEnabled: true, DhcpRangeStart: "fd00:1::1000", DhcpRangeEnd: "fd00:1::1fff"})
	mustCreate(t, db, &models.IpamAddress{InstanceID: main.ID, Address: "fd00:1::10", DnsName: "nas.home.arpa", Mac: "02:00:00:00:00:10"})
	mustCreate(t, db, &models.DnsZone{InstanceID: main.ID, Name: "home.arpa", Type: "forward"})

	for _, o := range []models.AddressObject{
		{Name: "nas", Addresses: models.StringList{"192.168.1.10", "fd00:1::10"}},
		{Name: "remote", Addresses: models.StringList{"10.50.0.0/16", "fd00:50::/48"}},
		{Name: "upstream", Addresses: models.StringList{"192.168.1.254", "fd00:1::fe"}},
		{Name: "quad9", Addresses: models.StringList{"9.9.9.9", "2620:fe::fe"}},
	} {
		mustCreate(t, db, &o)
	}
	mustCreate(t, db, &models.Rule{InstanceID: main.ID, Chain: "forward", DstAddrs: models.StringList{"nas"}, Services: models.StringList{"ssh"}, Action: "accept", Enabled: true})
	mustCreate(t, db, &models.NatRule{InstanceID: main.ID, Kind: "dnat", InInterfaces: models.StringList{"eth0"}, Protocol: "tcp", DstPorts: "443", ToAddr: "nas", Enabled: true})
	mustCreate(t, db, &models.Route{InstanceID: main.ID, Destination: "remote", Gateway: "upstream", Enabled: true})

	doc, err := Build(db, 1)
	if err != nil {
		t.Fatal(err)
	}
	in := doc.Instance("main")

	if got := strings.Join(in.Rules[0].DstAddrs, " "); got != "192.168.1.10 fd00:1::10" {
		t.Errorf("rule destination %q", got)
	}
	if len(in.NAT) != 2 || in.NAT[0].ToAddr != "192.168.1.10" || in.NAT[1].ToAddr != "fd00:1::10" {
		t.Errorf("a dual-stack target makes one NAT rule per version: %+v", in.NAT)
	}
	var routes []string
	for _, r := range in.Routes {
		routes = append(routes, r.Destination+" via "+r.Gateway)
	}
	if got := strings.Join(routes, ", "); got != "10.50.0.0/16 via 192.168.1.254, fd00:50::/48 via fd00:1::fe" {
		t.Errorf("routes: %s", got)
	}
	if got := strings.Join(in.DNS.Forwarders, " "); got != "9.9.9.9 2620:fe::fe" {
		t.Errorf("forwarders %q", got)
	}

	if len(in.DHCP.Subnets) != 2 {
		t.Fatalf("dhcp subnets %+v", in.DHCP.Subnets)
	}
	v6 := in.DHCP.Subnets[1]
	if v6.Prefix != "fd00:1::/64" || v6.Interface != "eth1" || v6.Gateway != "" || strings.Join(v6.DNSServers, " ") != "fd00:1::1" {
		t.Errorf("dhcpv6 subnet: %+v", v6)
	}
	if len(in.RA) != 1 {
		t.Fatalf("ra: %+v", in.RA)
	}
	ra := in.RA[0]
	if ra.Interface != "eth1" || len(ra.Prefixes) != 1 || !ra.Prefixes[0].Autonomous || !ra.Managed || !ra.Other ||
		strings.Join(ra.RDNSS, " ") != "fd00:1::1" || strings.Join(ra.DNSSL, " ") != "home.arpa" {
		t.Errorf("ra: %+v", ra)
	}
}

// Two DHCP prefixes on one interface are both served there, each with the
// interface's address in it as gateway (the renderer makes them a Kea
// shared network). A DHCPv4 reservation no longer needs the DNS server.
func TestBuildTwoPrefixesOnInterface(t *testing.T) {
	db := testDB(t)
	main := models.Instance{Name: "main", IsDefault: true, DhcpEnabled: true}
	mustCreate(t, db, &main)
	mustCreate(t, db, &models.Interface{InstanceID: main.ID, Name: "eth1", Kind: "physical", Enabled: true, Ipv4Mode: "static",
		Addresses: models.StringList{"192.168.1.1/24", "10.1.2.1/24"}})
	mustCreate(t, db, &models.IpamPrefix{InstanceID: main.ID, Prefix: "192.168.1.0/24", DhcpEnabled: true, DhcpRangeStart: "192.168.1.100", DhcpRangeEnd: "192.168.1.199"})
	mustCreate(t, db, &models.IpamPrefix{InstanceID: main.ID, Prefix: "10.1.2.0/24", DhcpEnabled: true, DhcpRangeStart: "10.1.2.100", DhcpRangeEnd: "10.1.2.199"})
	mustCreate(t, db, &models.DnsZone{InstanceID: main.ID, Name: "home.arpa", Type: "forward"})
	mustCreate(t, db, &models.IpamAddress{InstanceID: main.ID, Address: "10.1.2.10", DnsName: "tv.home.arpa", Mac: "02:00:00:00:00:10"})

	doc, err := Build(db, 1)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, s := range doc.Instance("main").DHCP.Subnets {
		got = append(got, s.Prefix+" on "+s.Interface+" via "+s.Gateway)
	}
	if strings.Join(got, ", ") != "10.1.2.0/24 on eth1 via 10.1.2.1, 192.168.1.0/24 on eth1 via 192.168.1.1" {
		t.Errorf("dhcp subnets: %v", got)
	}
}

func TestBuildReportsObjectProblems(t *testing.T) {
	db := testDB(t)
	main := models.Instance{Name: "main", IsDefault: true}
	mustCreate(t, db, &main)
	mustCreate(t, db, &models.AddressObject{Name: "net", Addresses: models.StringList{"10.0.0.0/8"}})
	mustCreate(t, db, &models.AddressObject{Name: "hollow"})
	mustCreate(t, db, &models.Rule{InstanceID: main.ID, Chain: "input", SrcAddrs: models.StringList{"ghost"}, Action: "accept", Enabled: true})
	mustCreate(t, db, &models.Rule{InstanceID: main.ID, Chain: "input", SrcAddrs: models.StringList{"hollow"}, Action: "accept", Enabled: true})
	mustCreate(t, db, &models.NatRule{InstanceID: main.ID, Kind: "dnat", ToAddr: "net", Enabled: true})

	_, err := Build(db, 1)
	ve, ok := err.(*fwconfig.ValidationError)
	if !ok {
		t.Fatalf("want ValidationError, got %v", err)
	}
	joined := strings.Join(ve.Problems, "\n")
	for _, want := range []string{`unknown host/prefix name "ghost"`, "hollow has no addresses", "net is not a host"} {
		if !strings.Contains(joined, want) {
			t.Errorf("problems lack %q:\n%s", want, joined)
		}
	}
}
