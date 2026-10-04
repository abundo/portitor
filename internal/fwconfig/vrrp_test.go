// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package fwconfig

import (
	"slices"
	"strings"
	"testing"
)

func TestValidateVRRP(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(in *Instance)
		want   string
	}{
		{"unknown interface", func(in *Instance) { in.VRRP[0].Interface = "eth9" }, `unknown interface "eth9"`},
		{"vrid 0", func(in *Instance) { in.VRRP[0].VRID = 0 }, "id out of range (1-255)"},
		{"vrid 256", func(in *Instance) { in.VRRP[0].VRID = 256 }, "id out of range (1-255)"},
		{"bad version", func(in *Instance) { in.VRRP[0].Version = 4 }, "version must be 2 or 3"},
		{"ipv6 on v2", func(in *Instance) { in.VRRP[0].Version = 2 }, "IPv6 needs VRRPv3"},
		{"priority 255", func(in *Instance) { in.VRRP[0].Priority = 255 }, "priority out of range"},
		{"interval not a multiple of 10", func(in *Instance) { in.VRRP[0].AdvertisementInterval = 505 }, "a multiple of 10"},
		{"v2 interval in ms", func(in *Instance) { in.VRRP[0].Version, in.VRRP[0].IPv6 = 2, nil }, "VRRPv2 takes whole seconds"},
		{"no addresses", func(in *Instance) { in.VRRP[0].IPv4, in.VRRP[0].IPv6 = nil, nil }, "at least one address"},
		{"v6 in ipv4", func(in *Instance) { in.VRRP[0].IPv4 = []string{"fd00::1"} }, "is not an IPv4 address"},
		{"not canonical", func(in *Instance) { in.VRRP[0].IPv6 = []string{"FE80::50"} }, `"FE80::50" is not an address`},
		{"outside the networks", func(in *Instance) { in.VRRP[0].IPv4 = []string{"10.0.0.1"} }, "is in none of the networks of eth2"},
		{"interface's own address", func(in *Instance) { in.VRRP[0].IPv4 = []string{"192.168.50.1"} }, "is an address of interface eth2"},
		{"listed twice", func(in *Instance) { in.VRRP[0].IPv4 = []string{"192.168.50.254", "192.168.50.254"} }, "listed twice"},
		{"duplicate", func(in *Instance) { in.VRRP = append(in.VRRP, in.VRRP[0]) }, "virtual router 50 on eth2: duplicate"},
		{"address in two", func(in *Instance) {
			r := in.VRRP[0]
			r.VRID = 51
			in.VRRP = append(in.VRRP, r)
		}, "also an address of virtual router eth2/50"},
		{"loopback parent", func(in *Instance) {
			in.Interfaces = append(in.Interfaces, Interface{Name: "lo1", Kind: KindLoopback, Enabled: true, IPv4Mode: ModeStatic, Addresses: []string{"10.1.1.1/24"}})
			in.VRRP = append(in.VRRP, VRRP{Interface: "lo1", VRID: 1, IPv4: []string{"10.1.1.2"}})
		}, "not supported on loopback interfaces"},
		{"reserved interface name", func(in *Instance) { in.Interfaces[0].Name = "vrrp4-1-eth2" }, "names are for VRRP devices"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := SampleDocument()
			c.mutate(doc.Instance("guest"))
			err := doc.Validate()
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want %q, got %v", c.want, err)
			}
		})
	}
}

func TestVRRPDevices(t *testing.T) {
	doc := SampleDocument()
	in := doc.Instance("guest")
	devs := in.VRRPDevices()
	if len(devs) != 2 {
		t.Fatalf("devices: %+v", devs)
	}
	if d := devs[0]; d.Name != "vrrp4-50-eth2" || d.MAC != "00:00:5e:00:01:32" || d.Parent != "eth2" || !slices.Equal(d.Addresses, []string{"192.168.50.254/32"}) {
		t.Errorf("IPv4 device: %+v", d)
	}
	if d := devs[1]; d.Name != "vrrp6-50-eth2" || d.MAC != "00:00:5e:00:02:32" || !slices.Equal(d.Addresses, []string{"fe80::50/128"}) {
		t.Errorf("IPv6 device: %+v", d)
	}
	if got := in.MatchInterfaces([]string{"eth2"}); !slices.Equal(got, []string{"eth2", "vrrp4-50-eth2", "vrrp6-50-eth2"}) {
		t.Errorf("MatchInterfaces: %v", got)
	}
	if n := VRRPDeviceName(4, 255, "enp0s31f6.1000"); len(n) != 15 || !strings.HasPrefix(n, "vrrp4-255-") {
		t.Errorf("long name: %q", n)
	}
	if !in.FRRRunning() {
		t.Error("VRRP runs FRR")
	}
}
