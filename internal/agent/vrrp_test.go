// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"slices"
	"testing"

	"github.com/abundo/portitor/internal/fwconfig"
)

func TestPlanVRRP(t *testing.T) {
	doc := fwconfig.SampleDocument()
	devs := doc.Instance("guest").VRRPDevices()
	links, err := parseLinks([]byte(`[
 {"ifname":"eth2","flags":["UP"],"address":"52:54:00:12:34:56","addr_info":[]},
 {"ifname":"vrrp4-50-eth2","link":"eth2","flags":["BROADCAST"],"address":"00:00:5e:00:01:32","linkinfo":{"info_kind":"macvlan"},"addr_info":[
   {"family":"inet","local":"192.168.50.9","prefixlen":32,"scope":"global"}]},
 {"ifname":"vrrp6-50-eth2","link":"eth2","flags":["UP"],"address":"02:00:00:00:00:01","linkinfo":{"info_kind":"macvlan"},"addr_info":[]}
]`))
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]ipLink{}
	for _, l := range links {
		have[l.Ifname] = l
	}
	// The IPv4 device is right; the IPv6 one has the wrong MAC address.
	equal(t, planVRRPCreate("fw-guest", devs, have),
		"fw-guest ip link del dev vrrp6-50-eth2",
		"fw-guest ip link add link eth2 name vrrp6-50-eth2 address 00:00:5e:00:02:32 type macvlan mode bridge",
		"fw-guest ip link set dev vrrp6-50-eth2 addrgenmode random",
		"fw-guest ip link set dev vrrp6-50-eth2 protodown on",
	)
	delete(have, "vrrp6-50-eth2")
	equal(t, planVRRPDevices("fw-guest", devs, have),
		"fw-guest ip addr del 192.168.50.9/32 dev vrrp4-50-eth2",
		"fw-guest ip addr add 192.168.50.254/32 dev vrrp4-50-eth2",
		"fw-guest ip link set dev vrrp4-50-eth2 up",
		"fw-guest ip addr add fe80::50/128 dev vrrp6-50-eth2",
		"fw-guest ip link set dev vrrp6-50-eth2 up",
	)
	if got := vrrpSysctls(devs); !slices.Equal(got, []string{"net.ipv4.conf.eth2.arp_ignore=1", "net.ipv6.conf.vrrp6-50-eth2.accept_dad=0"}) {
		t.Errorf("sysctls: %q", got)
	}
}

func TestParseVRRP(t *testing.T) {
	routers, err := parseVRRP([]byte(`[
 {"vrid":50,"version":3,"autoconfigured":false,"shutdown":false,"preemptMode":true,"acceptMode":true,
  "interface":"eth2","advertisementInterval":500,"priority":200,
  "v4":{"interface":"vrrp4-50-eth2","vmac":"00:00:5e:00:01:32","primaryAddress":"192.168.50.1","status":"Master",
        "effectivePriority":200,"masterAdverInterval":500,"skewTime":110,"masterDownInterval":1610,
        "stats":{"adverTxCnt":42,"adverRxCnt":0,"garpTxCnt":1,"transitionCnt":2},"addresses":["192.168.50.254"]},
  "v6":{"interface":"","vmac":"00:00:5e:00:02:32","primaryAddress":"::","status":"Initialize","addresses":[]}},
 {"vrid":3,"version":2,"shutdown":true,"preemptMode":false,"interface":"eth1","advertisementInterval":1000,"priority":100,
  "v4":{"status":"Backup","addresses":["10.0.0.1"],"stats":{}}}
]`))
	if err != nil {
		t.Fatal(err)
	}
	if len(routers) != 2 || routers[0].Interface != "eth1" || routers[1].VRID != 50 {
		t.Fatalf("routers: %+v", routers)
	}
	r := routers[1]
	if r.Version != 3 || r.Priority != 200 || !r.Preempt || r.AdvertisementInterval != 500 || r.V6 != nil {
		t.Errorf("router: %+v", r)
	}
	if v4 := r.V4; v4 == nil || v4.State != "Master" || v4.Device != "vrrp4-50-eth2" || v4.AdvertisementsSent != 42 ||
		v4.Transitions != 2 || v4.MasterDownInterval != 1610 || !slices.Equal(v4.Addresses, []string{"192.168.50.254"}) {
		t.Errorf("v4: %+v", r.V4)
	}
	if r := routers[0]; !r.Shutdown || r.Preempt || r.V4 == nil || r.V4.State != "Backup" {
		t.Errorf("router: %+v", r)
	}
	if _, err := parseVRRP([]byte(`% vrrpd is not running`)); err == nil {
		t.Error("no error for a non-JSON answer")
	}
}
