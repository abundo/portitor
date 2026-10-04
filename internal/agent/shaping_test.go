// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"testing"

	"github.com/abundo/portitor/internal/fwconfig"
)

// From tc -j qdisc show: eth0 sends through cake at 40mbit and redirects
// what it receives to ifb-eth0 (cake, 400mbit); eth1 has an ingress qdisc.
const qdiscJSON = `[
 {"kind":"cake","handle":"8001:","dev":"eth0","root":true,"options":{"bandwidth":5000000,"ingress":false}},
 {"kind":"ingress","handle":"ffff:","dev":"eth0","parent":"ffff:fff1","options":{}},
 {"kind":"cake","handle":"8002:","dev":"ifb-eth0","root":true,"options":{"bandwidth":50000000,"ingress":true}},
 {"kind":"fq_codel","handle":"0:","dev":"eth1","root":true,"options":{}},
 {"kind":"ingress","handle":"ffff:","dev":"eth1","parent":"ffff:fff1","options":{}}
]`

const filterJSON = `[{"parent":"ffff:","protocol":"all","pref":1,"kind":"matchall","chain":0},
 {"parent":"ffff:","protocol":"all","pref":1,"kind":"matchall","chain":0,"options":{"handle":1,"actions":[
  {"order":1,"kind":"mirred","mirred_action":"redirect","direction":"egress","to_dev":"ifb-eth0"}]}}]`

func shapingState(t *testing.T) (map[string]ipLink, map[string][]tcQdisc) {
	t.Helper()
	have := map[string]ipLink{}
	for _, n := range []string{"eth0", "eth1", "eth2", "ifb-eth0"} {
		have[n] = ipLink{Ifname: n, Flags: []string{"UP"}}
	}
	qdiscs, err := parseQdiscs([]byte(qdiscJSON))
	if err != nil {
		t.Fatal(err)
	}
	return have, qdiscs
}

func TestParseRedirect(t *testing.T) {
	to, err := parseRedirect([]byte(filterJSON))
	if err != nil || to != "ifb-eth0" {
		t.Errorf("redirect %q, %v", to, err)
	}
}

func TestPlanShapeUnchanged(t *testing.T) {
	have, qdiscs := shapingState(t)
	want := []fwconfig.Interface{{Name: "eth0", Enabled: true, ShapeEgress: 40, ShapeIngress: 400}}
	equal(t, planUnshape("", want, nil, have, qdiscs))
	equal(t, planShape("", want, nil, have, qdiscs, map[string]string{"eth0": "ifb-eth0"}, map[string]string{}))
}

func TestPlanShape(t *testing.T) {
	have, qdiscs := shapingState(t)
	want := []fwconfig.Interface{
		{Name: "eth0", Enabled: true, ShapeEgress: 50, ShapeIngress: 400},
		{Name: "eth1", Enabled: true, ShapeIngress: 100}, // filter redirects elsewhere
		{Name: "eth2", Enabled: true, ShapeEgress: 10, ShapeIngress: 20},
		{Name: "eth3", Enabled: true, ShapeEgress: 10}, // not there yet
	}
	equal(t, planShape("fw-a", want, nil, have, qdiscs, map[string]string{"eth0": "ifb-eth0", "eth1": "ifb-x"}, map[string]string{}),
		"fw-a tc qdisc replace dev eth0 root cake bandwidth 50mbit",
		"fw-a ip link add ifb-eth1 type ifb",
		"fw-a ip link set dev ifb-eth1 up",
		"fw-a tc qdisc replace dev ifb-eth1 root cake bandwidth 100mbit ingress",
		"fw-a tc filter del dev eth1 parent ffff: pref 1",
		"fw-a tc filter add dev eth1 parent ffff: pref 1 handle 1 matchall action mirred egress redirect dev ifb-eth1",
		"fw-a tc qdisc replace dev eth2 root cake bandwidth 10mbit",
		"fw-a ip link add ifb-eth2 type ifb",
		"fw-a ip link set dev ifb-eth2 up",
		"fw-a tc qdisc replace dev ifb-eth2 root cake bandwidth 20mbit ingress",
		"fw-a tc qdisc add dev eth2 handle ffff: ingress",
		"fw-a tc filter add dev eth2 parent ffff: pref 1 handle 1 matchall action mirred egress redirect dev ifb-eth2")
}

func TestPlanUnshape(t *testing.T) {
	have, qdiscs := shapingState(t)
	want := []fwconfig.Interface{
		{Name: "eth0", Enabled: false, ShapeEgress: 40, ShapeIngress: 400}, // disabled: not shaped
		{Name: "eth1", Enabled: true},                                      // fq_codel is not ours
	}
	equal(t, planUnshape("", want, nil, have, qdiscs),
		"tc qdisc del dev eth0 root",
		"tc qdisc del dev eth0 ingress",
		"tc qdisc del dev eth1 ingress")
}

func TestPlanShapeHTB(t *testing.T) {
	have, qdiscs := shapingState(t)
	shapers := []fwconfig.RateLimit{{Name: "bulk", Rate: 100, Unit: "mbit", Shape: true}, {Name: "guests", Rate: 20, Unit: "mbit", Shape: true}}
	want := []fwconfig.Interface{
		{Name: "eth0", Enabled: true, ShapeEgress: 40}, // cake before
		{Name: "eth1", Enabled: true},                  // not ours before
	}
	built := map[string]string{}
	equal(t, planUnshape("", want, shapers, have, qdiscs),
		"tc qdisc del dev eth0 ingress",
		"tc qdisc del dev eth1 ingress")
	equal(t, planShape("", want, shapers, have, qdiscs, nil, built),
		"tc qdisc del dev eth0 root",
		"tc qdisc replace dev eth0 root handle 1: htb default ffff",
		"tc class add dev eth0 parent 1: classid 1:1 htb rate 40mbit ceil 40mbit quantum 1514",
		"tc class add dev eth0 parent 1:1 classid 1:ffff htb rate 40mbit ceil 40mbit quantum 1514",
		"tc qdisc add dev eth0 parent 1:ffff fq_codel",
		"tc class add dev eth0 parent 1:1 classid 1:10 htb rate 40000000bit ceil 40000000bit quantum 1514",
		"tc qdisc add dev eth0 parent 1:10 fq_codel",
		"tc filter add dev eth0 parent 1: protocol all prio 1 handle 0x5300 fw classid 1:10",
		"tc class add dev eth0 parent 1:1 classid 1:11 htb rate 20000000bit ceil 20000000bit quantum 1514",
		"tc qdisc add dev eth0 parent 1:11 fq_codel",
		"tc filter add dev eth0 parent 1: protocol all prio 1 handle 0x5301 fw classid 1:11",
		"tc qdisc replace dev eth1 root handle 1: htb default ffff",
		"tc class add dev eth1 parent 1: classid 1:1 htb rate 100gbit ceil 100gbit quantum 1514",
		"tc class add dev eth1 parent 1:1 classid 1:ffff htb rate 100gbit ceil 100gbit quantum 1514",
		"tc qdisc add dev eth1 parent 1:ffff fq_codel",
		"tc class add dev eth1 parent 1:1 classid 1:10 htb rate 100000000bit ceil 100000000bit quantum 1514",
		"tc qdisc add dev eth1 parent 1:10 fq_codel",
		"tc filter add dev eth1 parent 1: protocol all prio 1 handle 0x5300 fw classid 1:10",
		"tc class add dev eth1 parent 1:1 classid 1:11 htb rate 20000000bit ceil 20000000bit quantum 1514",
		"tc qdisc add dev eth1 parent 1:11 fq_codel",
		"tc filter add dev eth1 parent 1: protocol all prio 1 handle 0x5301 fw classid 1:11")

	// Built and unchanged: nothing to do. Shapers no longer used: removed.
	for _, dev := range []string{"eth0", "eth1"} {
		qdiscs[dev] = []tcQdisc{{Kind: "htb", Dev: dev, Root: true}}
	}
	equal(t, planShape("", want[1:], shapers, have, qdiscs, nil, built))
	equal(t, planUnshape("", want[1:], nil, have, qdiscs),
		"tc qdisc del dev eth1 root")
}

func TestIFBName(t *testing.T) {
	if got := fwconfig.IFBName("eth0"); got != "ifb-eth0" {
		t.Errorf("short: %s", got)
	}
	if got := fwconfig.IFBName("enp1s0f1.1000"); len(got) != 15 || got[:4] != "ifb-" {
		t.Errorf("long: %s", got)
	}
}
