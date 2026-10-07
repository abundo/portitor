// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package fwconfig

import (
	"strings"
	"testing"
)

// The sample's guest instance has VRF blue (table 100) with eth3.
func TestValidateVRF(t *testing.T) {
	// Another instance may have a VRF of the same name and table.
	same := SampleDocument()
	main := same.Instance("main")
	main.Interfaces = append(main.Interfaces, Interface{Name: "blue", Kind: KindVRF, Enabled: true, IPv4Mode: ModeNone, VRFTable: 100})
	main.Routes = append(main.Routes, Route{Destination: "10.9.0.0/16", Interface: "blue"}, Route{Destination: "10.8.0.0/16", Gateway: "192.168.1.9", VRF: "blue"})
	if err := same.Validate(); err != nil {
		t.Fatal(err)
	}

	vrf := func(in *Instance) *Interface { return in.Interface("blue") }
	cases := []struct {
		name   string
		mutate func(in *Instance)
		want   string
	}{
		{"table 0", func(in *Instance) { vrf(in).VRFTable = 0 }, "table 0 out of range"},
		{"main table", func(in *Instance) { vrf(in).VRFTable = 254 }, "table 254 out of range"},
		{"nat64 table", func(in *Instance) { vrf(in).VRFTable = NAT64TableBase }, "out of range"},
		{"duplicate table", func(in *Instance) {
			in.Interfaces = append(in.Interfaces, Interface{Name: "red", Kind: KindVRF, IPv4Mode: ModeNone, VRFTable: 100})
		}, "table 100 is also blue's"},
		{"two masters", func(in *Instance) { vrf(in).Members = append(vrf(in).Members, "vx200") }, "member of both br200 and blue"},
		{"vrf in vrf", func(in *Instance) {
			in.Interfaces = append(in.Interfaces, Interface{Name: "red", Kind: KindVRF, IPv4Mode: ModeNone, VRFTable: 101, Members: []string{"blue"}})
		}, `member "blue" is a vrf`},
		{"own member", func(in *Instance) { vrf(in).Members = []string{"blue"} }, "its own member"},
		{"unknown member", func(in *Instance) { vrf(in).Members = []string{"eth9"} }, `member "eth9" is not in this instance`},
		{"dhcp", func(in *Instance) { vrf(in).IPv4Mode = ModeDHCP }, "no dhcp client"},
		{"route to no vrf", func(in *Instance) { in.Routes = append(in.Routes, Route{Destination: "default", Gateway: "10.0.0.1", VRF: "eth2"}) }, `vrf "eth2" is not a vrf`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := SampleDocument()
			c.mutate(d.Instance("guest"))
			err := d.Validate()
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("got %v, want %q", err, c.want)
			}
		})
	}
}

func TestRouteTable(t *testing.T) {
	d := SampleDocument()
	in := d.Instance("guest")
	for _, c := range []struct {
		r    Route
		want string
	}{
		{Route{Destination: "default", Gateway: "10.255.0.1"}, ""},
		{Route{Destination: "default", Gateway: "172.16.3.254", VRF: "blue"}, "100"},
		{Route{Destination: "10.1.0.0/16", Interface: "eth3"}, "100"},
		{Route{Destination: "10.1.0.0/16", Interface: "eth2"}, ""},
		// A route into the VRF from the main table (route leaking).
		{Route{Destination: "172.16.3.0/24", Interface: "blue"}, ""},
	} {
		if got := in.RouteTable(c.r); got != c.want {
			t.Errorf("%+v: table %q, want %q", c.r, got, c.want)
		}
	}
	if !in.HasVRF() || d.Instance("main").HasVRF() {
		t.Error("HasVRF")
	}
}
