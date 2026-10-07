// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"encoding/json"
	"testing"

	"github.com/abundo/portitor/internal/fwconfig"
)

// Captured from ip -j -d addr show: vx200 learns and is in no bridge,
// vx300 is an EVPN bridge port, vx400 has the wrong VNI.
const vxlanLinksJSON = `[
 {"ifname":"eth2","flags":["UP"],"mtu":1500,"addr_info":[]},
 {"ifname":"vx200","flags":["UP"],"mtu":1450,"linkinfo":{"info_kind":"vxlan","info_data":{"id":200,"local":"192.0.2.1","link":"eth2","port":4789,"learning":true}},"addr_info":[]},
 {"ifname":"vx300","master":"br300","flags":["UP"],"mtu":1450,"linkinfo":{"info_kind":"vxlan","info_data":{"id":300,"local6":"2001:db8::1","port":8472,"learning":false},"info_slave_kind":"bridge","info_slave_data":{"learning":false,"neigh_suppress":true}},"addr_info":[]},
 {"ifname":"vx400","flags":["UP"],"mtu":1450,"linkinfo":{"info_kind":"vxlan","info_data":{"id":401,"local":"192.0.2.1","port":4789,"learning":true}},"addr_info":[]}
]`

func vxlanLinks(t *testing.T) map[string]ipLink {
	links, err := parseLinks([]byte(vxlanLinksJSON))
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]ipLink{}
	for _, l := range links {
		m[l.Ifname] = l
	}
	return m
}

func TestPlanCreateVXLAN(t *testing.T) {
	want := []fwconfig.Interface{
		{Name: "vx500", Kind: fwconfig.KindVXLAN, VXLAN: &fwconfig.VXLAN{VNI: 500, Local: "192.0.2.1", Device: "eth2.9"}},
		{Name: "eth2.9", Kind: fwconfig.KindVLAN, Parent: "eth2", VLANID: 9},
		{Name: "vx200", Kind: fwconfig.KindVXLAN, VXLAN: &fwconfig.VXLAN{VNI: 200, Local: "192.0.2.1", Device: "eth2"}},
		{Name: "vx300", Kind: fwconfig.KindVXLAN, VXLAN: &fwconfig.VXLAN{VNI: 300, Local: "2001:db8::1", Port: 8472}},
		{Name: "vx400", Kind: fwconfig.KindVXLAN, VXLAN: &fwconfig.VXLAN{VNI: 400, Local: "192.0.2.1"}},
	}
	// The VLAN underlay first; matching vxlans stay, a changed one is
	// made again.
	equal(t, planCreate("fw-a", want, vxlanLinks(t)),
		"fw-a ip link add link eth2 name eth2.9 type vlan id 9",
		"fw-a ip link add name vx500 type vxlan id 500 local 192.0.2.1 dstport 4789 dev eth2.9",
		"fw-a ip link del dev vx400",
		"fw-a ip link add name vx400 type vxlan id 400 local 192.0.2.1 dstport 4789")
}

func TestPlanVXLAN(t *testing.T) {
	in := &fwconfig.Instance{Interfaces: []fwconfig.Interface{
		{Name: "vx200", Kind: fwconfig.KindVXLAN, Enabled: true, VXLAN: &fwconfig.VXLAN{VNI: 200, Remotes: []string{"192.0.2.2", "192.0.2.3"}}},
		{Name: "vx300", Kind: fwconfig.KindVXLAN, Enabled: true, VXLAN: &fwconfig.VXLAN{VNI: 300}},
	}}
	var fdb []fdbEntry
	if err := json.Unmarshal([]byte(`[
	 {"mac":"00:00:00:00:00:00","dst":"192.0.2.2","flags":["self"],"state":"permanent"},
	 {"mac":"00:00:00:00:00:00","dst":"192.0.2.9","flags":["self"],"state":"permanent"},
	 {"mac":"00:00:00:00:00:00","dst":"192.0.2.8","flags":["self","extern_learn"]},
	 {"mac":"52:54:00:12:34:56","dst":"192.0.2.7","flags":["self"]}]`), &fdb); err != nil {
		t.Fatal(err)
	}
	fdbs := map[string][]fdbEntry{"vx200": fdb}
	// Without EVPN: both learn, the flood list is the remotes.
	equal(t, planVXLAN("", in, vxlanLinks(t), fdbs),
		"bridge fdb append 00:00:00:00:00:00 dev vx200 dst 192.0.2.3",
		"bridge fdb del 00:00:00:00:00:00 dev vx200 dst 192.0.2.9",
		"ip link set dev vx300 type vxlan learning")
	// With EVPN: neither learns, both are EVPN bridge ports, the
	// forwarding database is zebra's.
	in.BGP = &fwconfig.BGP{Enabled: true, EVPN: true}
	equal(t, planVXLAN("", in, vxlanLinks(t), fdbs),
		"ip link set dev vx200 type vxlan nolearning",
		"bridge link set dev vx200 neigh_suppress on learning off")
}
