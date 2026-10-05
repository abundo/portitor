// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"testing"

	"github.com/abundo/portitor/internal/fwconfig"
)

func TestPlanNAT64(t *testing.T) {
	wk := &fwconfig.NAT64{Prefix: fwconfig.NAT64WellKnownPrefix, Interfaces: []string{"eth1"}}
	pool := &fwconfig.NAT64{Prefix: fwconfig.NAT64WellKnownPrefix, Pool4: []string{"192.0.2.0/28"}, Interfaces: []string{"eth2", "eth1"}}

	running := parsePool4([]byte("20480,TCP,192.0.0.0,1,65535,1024,0\n"))
	running = append(running, parsePool4([]byte("20480,UDP,192.0.0.0,1,65535,1024,0\n"))...)
	running = append(running, parsePool4([]byte("20480,ICMP,192.0.0.0,1,65535,1024,0\n"))...)
	// Each interface's loop device has its pool4 address, for the
	// packets with its mark.
	equal(t, planNAT64("fw-guest", wk, nil, false, running),
		"modprobe jool",
		"fw-guest jool instance add portitor --netfilter --pool6 64:ff9b::/96",
		"fw-guest jool -i portitor pool4 add --tcp --mark 20480 192.0.0.0 1-65535",
		"fw-guest jool -i portitor pool4 add --udp --mark 20480 192.0.0.0 1-65535",
		"fw-guest jool -i portitor pool4 add --icmp --mark 20480 192.0.0.0 1-65535",
	)
	// Applied and running: nothing.
	equal(t, planNAT64("fw-guest", wk, wk, true, running))
	// Running without the pool4 entries (an agent from before the loop
	// devices): made again.
	equal(t, planNAT64("", wk, wk, true, nil),
		"jool instance remove portitor",
		"modprobe jool",
		"jool instance add portitor --netfilter --pool6 64:ff9b::/96",
		"jool -i portitor pool4 add --tcp --mark 20480 192.0.0.0 1-65535",
		"jool -i portitor pool4 add --udp --mark 20480 192.0.0.0 1-65535",
		"jool -i portitor pool4 add --icmp --mark 20480 192.0.0.0 1-65535",
	)
	// Another interface changes the pool4 entries.
	equal(t, planNAT64("", wk, &fwconfig.NAT64{Prefix: fwconfig.NAT64WellKnownPrefix}, true, running),
		"jool instance remove portitor",
		"modprobe jool",
		"jool instance add portitor --netfilter --pool6 64:ff9b::/96",
		"jool -i portitor pool4 add --tcp --mark 20480 192.0.0.0 1-65535",
		"jool -i portitor pool4 add --udp --mark 20480 192.0.0.0 1-65535",
		"jool -i portitor pool4 add --icmp --mark 20480 192.0.0.0 1-65535",
	)
	// Running as nobody knows: made again. Addresses follow the names.
	equal(t, planNAT64("", pool, nil, true, running),
		"jool instance remove portitor",
		"modprobe jool",
		"jool instance add portitor --netfilter --pool6 64:ff9b::/96",
		"jool -i portitor pool4 add --tcp --mark 20480 192.0.2.0 1-65535",
		"jool -i portitor pool4 add --udp --mark 20480 192.0.2.0 1-65535",
		"jool -i portitor pool4 add --icmp --mark 20480 192.0.2.0 1-65535",
		"jool -i portitor pool4 add --tcp --mark 20481 192.0.2.1 1-65535",
		"jool -i portitor pool4 add --udp --mark 20481 192.0.2.1 1-65535",
		"jool -i portitor pool4 add --icmp --mark 20481 192.0.2.1 1-65535",
	)
	equal(t, planNAT64("", nil, wk, true, running), "jool instance remove portitor")
	equal(t, planNAT64("", nil, nil, false, running))
}

func TestPlanNAT64Devices(t *testing.T) {
	in := &fwconfig.Instance{NAT64: &fwconfig.NAT64{Prefix: fwconfig.NAT64WellKnownPrefix, Interfaces: []string{"eth1", "eth2"}}}
	devs := in.NAT64Devices()
	links, err := parseLinks([]byte(`[{"ifname":"n64-eth1","flags":["UP"],"linkinfo":{"info_kind":"dummy"}},
		{"ifname":"n64-eth2","linkinfo":{"info_kind":"veth"}}]`))
	if err != nil {
		t.Fatal(err)
	}
	up, veth := links[0], links[1]
	equal(t, planNAT64Devices("fw-a", devs, map[string]ipLink{"n64-eth1": up, "n64-eth2": veth},
		map[string]string{"n64-eth1": "n64-eth1"}),
		// n64-eth1 is as wanted; n64-eth2 is of another kind.
		"fw-a ip link del dev n64-eth2",
		"fw-a ip link add name n64-eth2 type dummy",
		"fw-a sysctl -q -w net.ipv6.conf.n64-eth2.disable_ipv6=1",
		"fw-a tc qdisc replace dev n64-eth2 clsact",
		"fw-a tc filter replace dev n64-eth2 egress pref 1 matchall action mirred ingress redirect dev n64-eth2",
		"fw-a ip link set dev n64-eth2 up",
	)
	// The redirect lost (an apply that failed halfway).
	equal(t, planNAT64Devices("", devs[:1], map[string]ipLink{"n64-eth1": up}, nil),
		"tc qdisc replace dev n64-eth1 clsact",
		"tc filter replace dev n64-eth1 egress pref 1 matchall action mirred ingress redirect dev n64-eth1",
	)
}

func TestPlanNAT64Rules(t *testing.T) {
	in := &fwconfig.Instance{NAT64: &fwconfig.NAT64{Prefix: fwconfig.NAT64WellKnownPrefix, Interfaces: []string{"eth1", "eth2"}}}
	devs := in.NAT64Devices()
	rules, err := parseRules([]byte(`[{"priority":0,"src":"all","table":"255"},
		{"priority":6400,"src":"192.0.0.0","iif":"lo","table":"6400","protocol":"99"},
		{"priority":6402,"src":"192.0.0.2","iif":"lo","table":"6402","protocol":"99"},
		{"priority":100,"src":"10.0.0.0/8","table":"100"},
		{"priority":32766,"src":"all","table":"254"}]`))
	if err != nil {
		t.Fatal(err)
	}
	routes := []ipTableRoute{{Dst: "default", Dev: "n64-eth1", Table: "6400"}}
	// Ours that is stale goes; someone else's stays.
	equal(t, planNAT64Rules("", devs, rules, routes),
		"ip -4 rule del pref 6402 from 192.0.0.2 iif lo lookup 6402 proto 99",
		"ip -4 route replace default dev n64-eth2 table 6401 proto 99",
		"ip -4 rule add pref 6401 from 192.0.0.1 iif lo lookup 6401 proto 99",
	)
	// NAT64 off: ours go.
	equal(t, planNAT64Rules("", nil, rules, nil),
		"ip -4 rule del pref 6400 from 192.0.0.0 iif lo lookup 6400 proto 99",
		"ip -4 rule del pref 6402 from 192.0.0.2 iif lo lookup 6402 proto 99",
	)
}
