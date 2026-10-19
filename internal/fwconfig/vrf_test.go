// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package fwconfig

import (
	"fmt"
	"strings"
	"testing"
)

// The sample's guest instance has VRF blue (table 100) with eth3 in it.
func TestValidateVRF(t *testing.T) {
	// Another instance may have a VRF of the same name and table.
	same := SampleDocument()
	main := same.Instance("main")
	main.VRFs = []VRF{{Name: "blue", Table: 100}}
	main.Routes = append(main.Routes, Route{Destination: "10.9.0.0/16", Interface: "blue"}, Route{Destination: "10.8.0.0/16", Gateway: "192.168.1.9", VRF: "blue"})
	if err := same.Validate(); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		mutate func(in *Instance)
		want   string
	}{
		{"table 0", func(in *Instance) { in.VRFs[0].Table = 0 }, "table 0 out of range"},
		{"main table", func(in *Instance) { in.VRFs[0].Table = 254 }, "table 254 out of range"},
		{"nat64 table", func(in *Instance) { in.VRFs[0].Table = NAT64TableBase }, "out of range"},
		{"duplicate table", func(in *Instance) { in.VRFs = append(in.VRFs, VRF{Name: "red", Table: 100}) }, "table 100 is also blue's"},
		{"duplicate name", func(in *Instance) { in.VRFs = append(in.VRFs, VRF{Name: "blue", Table: 101}) }, "duplicate"},
		{"interface's name", func(in *Instance) { in.VRFs[0].Name = "eth2"; in.Interface("eth3").VRF = "eth2" }, "an interface has the same name"},
		{"bad name", func(in *Instance) { in.VRFs[0].Name = "a b"; in.Interface("eth3").VRF = "a b" }, "invalid"},
		{"unknown vrf", func(in *Instance) { in.Interface("eth2").VRF = "red" }, `vrf "red" is not a vrf`},
		{"bridge member", func(in *Instance) { in.Interface("vx200").VRF = "blue" }, "member of bridge br200"},
		{"vrf device given", func(in *Instance) {
			in.Interfaces = append(in.Interfaces, Interface{Name: "red", Kind: KindVRF, IPv4Mode: ModeNone, VRFTable: 7})
		}, "a vrf device without a vrf"},
		{"policy route from a vrf", func(in *Instance) {
			in.PolicyRoutes = []PolicyRoute{{InInterfaces: []string{"eth3"}, Gateways: []string{"10.0.0.1"}}}
		}, "policy route 1: interface eth3 is in vrf blue"},
		{"policy route into a vrf", func(in *Instance) {
			in.PolicyRoutes = []PolicyRoute{{Interface: "eth3"}}
		}, "policy route 1: interface eth3 is in a vrf"},
		{"route to no vrf", func(in *Instance) {
			in.Routes = append(in.Routes, Route{Destination: "default", Gateway: "10.0.0.1", VRF: "eth2"})
		}, `vrf "eth2" is not a vrf`},
	}
	vrfCases := []struct {
		name   string
		mutate func(in *Instance)
		want   string
	}{
		{"bfd route out of its vrf", func(in *Instance) { in.Routes[1].VRF = "" }, "route 2: a route with bfd must be in the vrf of its gateway's interface eth3"},
		{"main ospf on a vrf's interface", func(in *Instance) {
			in.OSPF.Interfaces = append(in.OSPF.Interfaces, OSPFInterface{Name: "eth3", Area: "0.0.0.0"})
		}, "ospf: interface eth3 is in vrf blue"},
		{"vrf ospf on a main interface", func(in *Instance) {
			in.VRFs[0].OSPF.Interfaces = append(in.VRFs[0].OSPF.Interfaces, OSPFInterface{Name: "eth2", Area: "0.0.0.0"})
		}, "vrf blue: ospf: interface eth2 is in no vrf"},
		{"vrf bgp update source", func(in *Instance) { in.VRFs[0].BGP.Neighbors[0].UpdateSource = "eth2" }, "vrf blue: bgp 172.16.3.2 update source: interface eth2 is in no vrf"},
		{"vrf evpn", func(in *Instance) { in.VRFs[0].BGP.EVPN = true }, "vrf blue: bgp: evpn is for the main table's bgp only"},
		{"vrf bgp checked", func(in *Instance) { in.VRFs[0].BGP.ASN = 0 }, "vrf blue: bgp: local AS is required"},
		{"464xlat in a vrf", func(in *Instance) {
			in.NAT64 = &NAT64{Prefix: "64:ff9b::/96", Interfaces: []string{"eth3"}}
		}, "464xlat is not supported on an interface in a vrf"},
		{"too many vrfs", func(in *Instance) {
			for i := range MaxVRFs {
				in.VRFs = append(in.VRFs, VRF{Name: fmt.Sprintf("v%d", i), Table: 1000 + i})
			}
		}, "at most 127 vrfs"},
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
	if d := SampleVRFDocument(); d.Validate() != nil {
		err := d.Validate()
		t.Fatal(err)
	}
	for _, c := range vrfCases {
		t.Run(c.name, func(t *testing.T) {
			d := SampleVRFDocument()
			c.mutate(d.Instance("guest"))
			err := d.Validate()
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("got %v, want %q", err, c.want)
			}
		})
	}
}

func TestExpandVRF(t *testing.T) {
	d := SampleVRFDocument().Expand()
	in := d.Instance("guest")
	dev := in.Interface("blue")
	if dev == nil || dev.Kind != KindVRF || dev.VRFTable != 100 || len(dev.Members) != 1 || dev.Members[0] != "eth3" {
		t.Fatalf("vrf device: %+v", dev)
	}
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
	if r := in.Routings(); len(r) != 2 || r[0].VRF != "" || r[1].VRF != "blue" || !r[1].BGPOn() || r[1].OSPFOn(2) == nil || r[1].OSPFOn(3) != nil {
		t.Errorf("routings: %+v", r)
	}
	if in.VRFLabel("blue") != 1 || in.VRFLabel("eth3") != 0 {
		t.Error("VRFLabel")
	}
	for _, dev := range in.VRRPDevices() {
		if want := map[string]string{"eth2": "", "eth3": "blue"}[dev.Parent]; dev.VRF != want {
			t.Errorf("vrrp device %s: vrf %q, want %q", dev.Name, dev.VRF, want)
		}
	}
}
