// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package fwconfig

import (
	"maps"
	"slices"
	"testing"
)

func TestPolicyRoutes(t *testing.T) {
	doc := SampleDocument()
	in := doc.Instance("main")
	// The gateway's interface, by its prefix, and the named interface.
	if got := slices.Sorted(maps.Keys(in.PolicyRouteDevices())); !slices.Equal(got, []string{"eth1", "wg0"}) {
		t.Errorf("devices: %v", got)
	}
	// The exception's IPv4 destination, the IPv4 gateway's IPv4 alone,
	// the interface's both.
	for i, want := range [][]string{{"ipv4"}, {"ipv4"}, {"ipv4", "ipv6"}} {
		var got []string
		for _, m := range in.PolicyRoutes[i].Matches() {
			got = append(got, m.Family)
		}
		if !slices.Equal(got, want) {
			t.Errorf("policy route %d: families %v, want %v", i+1, got, want)
		}
	}
	// An IPv4 source alone marks IPv4 alone, though the interface routes
	// both.
	if got := (PolicyRoute{SrcAddrs: []string{"192.168.1.50"}, Interface: "wg0"}).MarkedFamilies(); !slices.Equal(got, []string{"ipv4"}) {
		t.Errorf("marked families: %v", got)
	}
	if got := in.PolicyRoutes[2].MarkedFamilies(); !slices.Equal(got, []string{"ipv4", "ipv6"}) {
		t.Errorf("marked families of an address set of both: %v", got)
	}
	p := PolicyRoute{Gateways: []string{"192.0.2.1", "2001:db8::1"}}
	if p.Gateway("ipv6") != "2001:db8::1" || p.Gateway("ipv4") != "192.0.2.1" || !p.Routed() || (PolicyRoute{}).Routed() {
		t.Errorf("gateways: %+v", p)
	}
	if !IsPolicyRoutePref(PolicyRouteTable(0)) || !IsPolicyRoutePref(PolicyRouteTable(MaxPolicyRoutes-1)) || IsPolicyRoutePref(PolicyRouteTable(MaxPolicyRoutes)) ||
		PolicyRouteTable(0) <= MaxVRFTable || PolicyRouteMark(MaxPolicyRoutes-1) >= 0x5300 {
		t.Error("tables or marks overlap")
	}
}
