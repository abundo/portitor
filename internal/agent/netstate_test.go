// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"strings"
	"testing"

	"github.com/abundo/portitor/internal/fwconfig"
)

func cmdStrings(cmds []command) []string {
	out := make([]string, len(cmds))
	for i, c := range cmds {
		out[i] = strings.TrimSpace(c.Netns + " " + c.Name + " " + strings.Join(c.Args, " "))
	}
	return out
}

func equal(t *testing.T, got []command, want ...string) {
	t.Helper()
	g := cmdStrings(got)
	if strings.Join(g, "\n") != strings.Join(want, "\n") {
		t.Errorf("got:\n  %s\nwant:\n  %s", strings.Join(g, "\n  "), strings.Join(want, "\n  "))
	}
}

const ipAddrJSON = `[
 {"ifname":"lo","flags":["LOOPBACK","UP"],"mtu":65536,"addr_info":[{"family":"inet","local":"127.0.0.1","prefixlen":8,"scope":"host"}]},
 {"ifname":"eth0","flags":["BROADCAST","UP"],"mtu":1500,"addr_info":[
   {"family":"inet","local":"198.51.100.7","prefixlen":24,"scope":"global","dynamic":true},
   {"family":"inet6","local":"2001:db8::5","prefixlen":64,"scope":"global","dynamic":true},
   {"family":"inet6","local":"fe80::1","prefixlen":64,"scope":"link"}]},
 {"ifname":"eth1","flags":["BROADCAST"],"mtu":1500,"addr_info":[
   {"family":"inet","local":"192.168.1.1","prefixlen":24,"scope":"global"},
   {"family":"inet","local":"10.0.0.1","prefixlen":8,"scope":"global"}]},
 {"ifname":"eth1.20","link":"eth1","flags":["UP"],"mtu":1500,"linkinfo":{"info_kind":"vlan","info_data":{"protocol":"802.1Q","id":30}},"addr_info":[]},
 {"ifname":"br0","flags":["UP"],"mtu":1500,"linkinfo":{"info_kind":"bridge"},"addr_info":[]}
]`

func observed(t *testing.T) map[string]ipLink {
	links, err := parseLinks([]byte(ipAddrJSON))
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]ipLink{}
	for _, l := range links {
		m[l.Ifname] = l
	}
	return m
}

func TestPlanAddresses(t *testing.T) {
	have := observed(t)
	// DHCP-owned and dynamic/link-local addresses stay.
	equal(t, planAddresses("", fwconfig.Interface{Name: "eth0", IPv4Mode: fwconfig.ModeDHCP}, have["eth0"]))
	// Static: remove the stray, add the missing.
	equal(t, planAddresses("fw-guest", fwconfig.Interface{Name: "eth1", IPv4Mode: fwconfig.ModeStatic,
		Addresses: []string{"192.168.1.1/24", "fd00::1/64"}}, have["eth1"]),
		"fw-guest ip addr del 10.0.0.1/8 dev eth1",
		"fw-guest ip addr add fd00::1/64 dev eth1")
}

func TestPlanCreateRecreatesWrongVLAN(t *testing.T) {
	want := []fwconfig.Interface{
		{Name: "eth1.20", Kind: fwconfig.KindVLAN, Parent: "br0", VLANID: 20},
		{Name: "br0", Kind: fwconfig.KindBridge},
		{Name: "wg0", Kind: fwconfig.KindWireGuard},
		{Name: "eth1", Kind: fwconfig.KindPhysical},
	}
	equal(t, planCreate("", want, observed(t)),
		"ip link add name wg0 type wireguard",
		"ip link del dev eth1.20",
		"ip link add link br0 name eth1.20 type vlan id 20")
}

func TestPlanLinkSettings(t *testing.T) {
	want := []fwconfig.Interface{
		{Name: "br0", Kind: fwconfig.KindBridge, Members: []string{"eth1"}, Enabled: true},
		{Name: "eth1", Kind: fwconfig.KindPhysical, Enabled: true, MTU: 9000},
		{Name: "eth0", Kind: fwconfig.KindPhysical, Enabled: false},
	}
	equal(t, planLinkSettings("", want, observed(t)),
		"ip link set dev eth1 master br0",
		"ip link set dev eth1 mtu 9000",
		"ip link set dev eth1 up",
		"ip link set dev eth0 down")
}

func TestPlanRoutes(t *testing.T) {
	have, err := parseRoutes([]byte(`[
		{"dst":"10.50.0.0/16","gateway":"192.168.1.254","dev":"eth1","metric":0},
		{"dst":"10.60.0.0/16","gateway":"192.168.1.254","dev":"eth1","metric":0}]`))
	if err != nil {
		t.Fatal(err)
	}
	want := []fwconfig.Route{
		{Destination: "10.50.0.0/16", Gateway: "192.168.1.254"},
		{Destination: "default", Gateway: "10.255.0.1"},
		{Destination: "fd00:2::/64", Gateway: "fd00:1::2"},
	}
	equal(t, planRoutes("", want, have),
		"ip route del 10.60.0.0/16 via 192.168.1.254 dev eth1 metric 0 proto 99",
		"ip route replace 10.50.0.0/16 via 192.168.1.254 metric 0 proto 99",
		"ip route replace default via 10.255.0.1 metric 0 proto 99",
		"ip -6 route replace fd00:2::/64 via fd00:1::2 metric 0 proto 99")
}

func TestParseWGDump(t *testing.T) {
	dump := "wg0\tPRIV\tPUBKEY\t51820\toff\n" +
		"wg0\tPEER1\t(none)\t203.0.113.9:4500\t10.99.0.2/32\t1700000000\t1234\t5678\toff\n" +
		"wg0\tPEER2\t(none)\t(none)\t10.99.0.3/32,fd00:99::3/128\t0\t0\t0\t25\n"
	got := parseWGDump(dump)
	if len(got) != 1 || got[0].ListenPort != 51820 || len(got[0].Peers) != 2 {
		t.Fatalf("%+v", got)
	}
	p1, p2 := got[0].Peers[0], got[0].Peers[1]
	if p1.Endpoint != "203.0.113.9:4500" || p1.LatestHandshake == nil || p1.RxBytes != 1234 {
		t.Errorf("peer1 %+v", p1)
	}
	if p2.LatestHandshake != nil || len(p2.AllowedIPs) != 2 {
		t.Errorf("peer2 %+v", p2)
	}
}

func TestParseKeaLeases(t *testing.T) {
	csv := "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id\n" +
		"192.168.1.100,02:00:00:00:00:01,,3600,4000000000,1,0,0,laptop.,0,,0\n" +
		"192.168.1.101,02:00:00:00:00:02,,3600,4000000000,1,0,0,,0,,0\n" +
		"192.168.1.101,02:00:00:00:00:02,,0,4000000000,1,0,0,,2,,0\n"
	var got []ServerLease
	valid := map[string]bool{}
	parseKeaLeases(strings.NewReader(csv), func(l ServerLease, ok bool) {
		got = append(got, l)
		valid[l.Address] = ok
	})
	if len(got) != 3 || got[0].Hostname != "laptop" || valid["192.168.1.101"] {
		t.Errorf("%+v %v", got, valid)
	}
}
