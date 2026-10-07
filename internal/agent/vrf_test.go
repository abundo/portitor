// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"testing"

	"github.com/abundo/portitor/internal/fwconfig"
)

// Captured from ip -j -d addr show: blue is a VRF with table 100 and eth3
// in it, red has the wrong table, eth4 is in red.
const vrfLinksJSON = `[
 {"ifname":"blue","flags":["UP"],"mtu":65575,"linkinfo":{"info_kind":"vrf","info_data":{"table":100}},"addr_info":[]},
 {"ifname":"red","flags":["UP"],"mtu":65575,"linkinfo":{"info_kind":"vrf","info_data":{"table":7}},"addr_info":[]},
 {"ifname":"eth3","master":"blue","flags":["UP"],"mtu":1500,"linkinfo":{"info_slave_kind":"vrf"},"addr_info":[]},
 {"ifname":"eth4","master":"red","flags":["UP"],"mtu":1500,"linkinfo":{"info_slave_kind":"vrf"},"addr_info":[]}
]`

func TestPlanVRF(t *testing.T) {
	links, err := parseLinks([]byte(vrfLinksJSON))
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]ipLink{}
	for _, l := range links {
		have[l.Ifname] = l
	}
	want := []fwconfig.Interface{
		{Name: "blue", Kind: fwconfig.KindVRF, Enabled: true, VRFTable: 100, Members: []string{"eth4"}},
		{Name: "red", Kind: fwconfig.KindVRF, Enabled: true, VRFTable: 8},
		{Name: "green", Kind: fwconfig.KindVRF, Enabled: true, VRFTable: 9, Members: []string{"eth5"}},
		{Name: "eth3", Kind: fwconfig.KindPhysical, Enabled: true},
		{Name: "eth4", Kind: fwconfig.KindPhysical, Enabled: true},
		{Name: "eth5", Kind: fwconfig.KindPhysical, Enabled: true},
	}
	equal(t, planCreate("", want, have),
		"ip link del dev red",
		"ip link add name red type vrf table 8",
		"ip link add name green type vrf table 9")
	equal(t, planLinkSettings("", want, have),
		"ip link set dev green up",
		"ip link set dev eth3 nomaster",
		"ip link set dev eth4 master blue",
		"ip link set dev eth5 master green",
		"ip link set dev eth5 up")
}

func TestPlanRoutesVRF(t *testing.T) {
	in := &fwconfig.Instance{
		Interfaces: []fwconfig.Interface{{Name: "eth3", Kind: fwconfig.KindPhysical, VRF: "blue"}},
		VRFs:       []fwconfig.VRF{{Name: "blue", Table: 100}},
	}
	have := []ipRoute{
		{Table: "100", Dst: "default", Gateway: "172.16.3.254", Dev: "eth3"},
		{Table: "100", Dst: "10.7.0.0/16", Gateway: "172.16.3.7", Dev: "eth3"},
		// The same route in main is not the VRF's.
		{Dst: "10.9.0.0/16", Dev: "eth3"},
	}
	want := []fwconfig.Route{
		{Destination: "default", Gateway: "172.16.3.254", VRF: "blue"},
		{Destination: "10.9.0.0/16", Interface: "eth3"},
	}
	equal(t, planRoutes("", want, have, in.RouteTable),
		"ip route del 10.7.0.0/16 via 172.16.3.7 dev eth3 metric 0 proto 99 table 100",
		"ip route del 10.9.0.0/16 dev eth3 metric 0 proto 99",
		"ip route replace default via 172.16.3.254 metric 0 proto 99 table 100",
		"ip route replace 10.9.0.0/16 dev eth3 metric 0 proto 99 table 100")
}
