// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"net"
	"slices"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/rfc1035label"
)

func TestLeaseDetails(t *testing.T) {
	_, dest, _ := net.ParseCIDR("10.0.0.0/8")
	ack, err := dhcpv4.New(
		dhcpv4.WithOption(dhcpv4.OptDomainName("example.org")),
		dhcpv4.WithOption(dhcpv4.OptDomainSearch(&rfc1035label.Labels{Labels: []string{"a.example", "b.example"}})),
		dhcpv4.WithOption(dhcpv4.OptNTPServers(net.IPv4(192, 0, 2, 5))),
		dhcpv4.WithOption(dhcpv4.OptGeneric(dhcpv4.OptionInterfaceMTU, []byte{0x05, 0xdc})),
		dhcpv4.WithOption(dhcpv4.OptClasslessStaticRoute(&dhcpv4.Route{Dest: dest, Router: net.IPv4(192, 0, 2, 1)})),
	)
	if err != nil {
		t.Fatal(err)
	}
	// Stale values from an earlier lease are replaced.
	l := Lease{NTP: []string{"198.51.100.1"}, MTU: 9000}
	leaseDetails(&l, ack)

	if l.Domain != "example.org" {
		t.Errorf("domain %q", l.Domain)
	}
	if !slices.Equal(l.Search, []string{"a.example", "b.example"}) {
		t.Errorf("search %v", l.Search)
	}
	if !slices.Equal(l.NTP, []string{"192.0.2.5"}) {
		t.Errorf("ntp %v", l.NTP)
	}
	if l.MTU != 1500 {
		t.Errorf("mtu %d", l.MTU)
	}
	if !slices.Equal(l.Routes, []string{"10.0.0.0/8 via 192.0.2.1"}) {
		t.Errorf("routes %v", l.Routes)
	}
	var codes []int
	for _, o := range l.Options {
		codes = append(codes, o.Code)
		if o.Name == "" || o.Value == "" {
			t.Errorf("option %+v not decoded", o)
		}
	}
	if !slices.IsSorted(codes) || !slices.Contains(codes, 15) || !slices.Contains(codes, 26) {
		t.Errorf("option codes %v", codes)
	}
	for _, o := range l.Options {
		if o.Code == 15 && o.Value != "example.org" {
			t.Errorf("domain option %+v", o)
		}
	}
}
