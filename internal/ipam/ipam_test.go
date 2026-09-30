// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package ipam

import (
	"fmt"
	"testing"

	"github.com/abundo/portitor/models"
)

func pfx(id uint, s string) models.IpamPrefix {
	return models.IpamPrefix{Base: models.Base{ID: id}, Prefix: s}
}

// Interface addresses show up in the tree with their prefix, which is added
// (Auto) when IPAM lacks it; an IPAM address on an interface gets its id.
func TestTreeInterfaceAddresses(t *testing.T) {
	prefixes := []models.IpamPrefix{pfx(1, "192.168.1.0/24")}
	addrs := []models.IpamAddress{
		{Base: models.Base{ID: 10}, Address: "192.168.1.1", DnsName: "gw.home.arpa"},
		{Base: models.Base{ID: 11}, Address: "192.168.1.10"},
	}
	ifaces := []models.Interface{
		{Base: models.Base{ID: 7}, Name: "eth1", Addresses: models.StringList{"192.168.1.1/24", "192.168.2.1/24", "fd00:1::1/64"}},
		{Base: models.Base{ID: 8}, Name: "wg0", Addresses: models.StringList{"10.99.0.1/32"}},
	}
	roots := Tree(prefixes, addrs, ifaces, nil)
	var got []string
	for _, r := range roots {
		got = append(got, r.CIDR)
	}
	if want := "[10.99.0.1 192.168.1.0/24 192.168.2.0/24 fd00:1::/64]"; fmt.Sprint(got) != want {
		t.Fatalf("roots %v, want %s", got, want)
	}
	if r := roots[0]; r.Kind != "address" || !r.Auto || r.ID != 0 || *r.InterfaceID != 8 {
		t.Errorf("/32 interface address: %+v", r)
	}
	lan := roots[1]
	if lan.Auto || lan.ID != 1 || lan.InterfaceID == nil || *lan.InterfaceID != 7 || len(lan.Children) != 2 {
		t.Fatalf("stored prefix: %+v", lan)
	}
	if gw := lan.Children[0]; gw.ID != 10 || gw.Auto || gw.InterfaceID == nil || *gw.InterfaceID != 7 || gw.DnsName != "gw.home.arpa" {
		t.Errorf("IPAM address on an interface: %+v", gw)
	}
	if nas := lan.Children[1]; nas.InterfaceID != nil {
		t.Errorf("IPAM address on no interface: %+v", nas)
	}
	for _, r := range roots[2:] {
		if r.Kind != "prefix" || !r.Auto || r.ID != 0 || *r.InterfaceID != 7 || len(r.Children) != 1 || !r.Children[0].Auto {
			t.Errorf("interface prefix: %+v", r)
		}
	}
	used := Used(addrs, ifaces)
	if len(used) != 6 {
		t.Errorf("used: %+v", used)
	}
}

func TestTreeNesting(t *testing.T) {
	prefixes := []models.IpamPrefix{
		pfx(1, "192.168.1.0/24"),
		pfx(2, "192.168.0.0/16"),
		pfx(3, "192.168.1.128/25"),
		pfx(4, "10.0.0.0/8"),
		pfx(5, "fd00::/48"),
		pfx(6, "192.168.20.0/24"),
	}
	addrs := []models.IpamAddress{
		{Base: models.Base{ID: 10}, Address: "192.168.1.1"},
		{Base: models.Base{ID: 11}, Address: "192.168.1.200"},
		{Base: models.Base{ID: 12}, Address: "172.16.0.1"},
	}
	roots := Tree(prefixes, addrs, nil, nil)
	var got []string
	for _, r := range roots {
		got = append(got, r.CIDR)
	}
	want := []string{"10.0.0.0/8", "172.16.0.1", "192.168.0.0/16", "fd00::/48"}
	if len(got) != len(want) {
		t.Fatalf("roots %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("roots %v, want %v", got, want)
		}
	}
	p16 := roots[2]
	if len(p16.Children) != 2 || p16.Children[0].CIDR != "192.168.1.0/24" || p16.Children[1].CIDR != "192.168.20.0/24" {
		t.Fatalf("/16 children: %+v", p16.Children)
	}
	p24 := p16.Children[0]
	// .1 directly in the /24, .200 in the /25.
	if len(p24.Children) != 2 || p24.Children[0].CIDR != "192.168.1.1" || p24.Children[1].CIDR != "192.168.1.128/25" {
		t.Fatalf("/24 children: %+v", p24.Children)
	}
	if p24.Children[1].Children[0].CIDR != "192.168.1.200" {
		t.Fatal("address not in deepest prefix")
	}
	if p16.UsedFrac <= 0 || p16.UsedFrac >= 1 {
		t.Errorf("used frac %v", p16.UsedFrac)
	}
}

func TestNextFree(t *testing.T) {
	p := models.IpamPrefix{Prefix: "192.168.1.0/29", DhcpEnabled: true, DhcpRangeStart: "192.168.1.3", DhcpRangeEnd: "192.168.1.4"}
	addrs := []models.IpamAddress{{Address: "192.168.1.1"}}
	ip, err := NextFree(p, nil, addrs)
	if err != nil || ip.String() != "192.168.1.2" {
		t.Fatalf("%v %v", ip, err)
	}
	addrs = append(addrs, models.IpamAddress{Address: "192.168.1.2"}, models.IpamAddress{Address: "192.168.1.5"}, models.IpamAddress{Address: "192.168.1.6"})
	if _, err := NextFree(p, nil, addrs); err == nil {
		t.Fatal("expected full (.7 is broadcast)")
	}
}

func TestNextFreeCommon(t *testing.T) {
	v4 := models.IpamPrefix{Prefix: "10.99.0.0/24"}
	v6 := models.IpamPrefix{Prefix: "fd99::/64"}
	addrs := []models.IpamAddress{{Address: "10.99.0.1"}, {Address: "fd99::1"}}
	ips, err := NextFreeCommon([]models.IpamPrefix{v4, v6}, nil, addrs)
	if err != nil || ips[0].String() != "10.99.0.2" || ips[1].String() != "fd99::2" {
		t.Fatalf("%v %v", ips, err)
	}
	// .2 is taken in IPv4 only, ::3 in IPv6 only: both move to 4.
	addrs = append(addrs, models.IpamAddress{Address: "10.99.0.2"}, models.IpamAddress{Address: "fd99::3"})
	ips, err = NextFreeCommon([]models.IpamPrefix{v4, v6}, nil, addrs)
	if err != nil || ips[0].String() != "10.99.0.4" || ips[1].String() != "fd99::4" {
		t.Fatalf("%v %v", ips, err)
	}
}

// A zone's A/AAAA records show up under the deepest prefix that holds their
// address, merged into the node an address already has; records outside
// every prefix are left out.
func TestTreeRecordAddresses(t *testing.T) {
	prefixes := []models.IpamPrefix{pfx(1, "192.168.0.0/16"), pfx(2, "192.168.1.0/24")}
	addrs := []models.IpamAddress{{Base: models.Base{ID: 10}, Address: "192.168.1.10", DnsName: "nas.home.arpa"}}
	records := []RecordAddress{
		{ZoneID: 5, Name: "printer.home.arpa", Address: "192.168.1.20", Mac: "02:00:00:00:00:20", Description: "hall"},
		{ZoneID: 5, Name: "files.home.arpa", Address: "192.168.1.10"},
		{ZoneID: 6, Name: "lp.lab.arpa", Address: "192.168.1.20"},
		{ZoneID: 5, Name: "cam.home.arpa", Address: "192.168.9.9"},
		{ZoneID: 5, Name: "www.home.arpa", Address: "203.0.113.1"},
		{ZoneID: 5, Name: "bad.home.arpa", Address: "nonsense"},
	}
	roots := Tree(prefixes, addrs, nil, records)
	if len(roots) != 1 || roots[0].CIDR != "192.168.0.0/16" {
		t.Fatalf("roots: %+v", roots)
	}
	top := roots[0].Children
	if len(top) != 2 || top[0].CIDR != "192.168.1.0/24" || top[1].CIDR != "192.168.9.9" {
		t.Fatalf("children of /16: %+v", top)
	}
	if cam := top[1]; !cam.Auto || cam.ZoneID == nil || *cam.ZoneID != 5 || cam.DnsName != "cam.home.arpa" {
		t.Errorf("record in the /16: %+v", cam)
	}
	lan := top[0].Children
	if len(lan) != 2 {
		t.Fatalf("children of /24: %+v", lan)
	}
	if nas := lan[0]; nas.ID != 10 || nas.Auto || nas.DnsName != "nas.home.arpa, files.home.arpa" || *nas.ZoneID != 5 {
		t.Errorf("record for an IPAM address: %+v", nas)
	}
	if p := lan[1]; !p.Auto || p.ID != 0 || *p.ZoneID != 5 || p.DnsName != "printer.home.arpa, lp.lab.arpa" ||
		p.Mac != "02:00:00:00:00:20" || p.Description != "hall" {
		t.Errorf("records for one address: %+v", p)
	}
}
