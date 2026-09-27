// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package ipam

import (
	"testing"

	"github.com/abundo/portitor/models"
)

func pfx(id uint, s string) models.IpamPrefix {
	return models.IpamPrefix{Base: models.Base{ID: id}, Prefix: s}
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
	roots := Tree(prefixes, addrs)
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
