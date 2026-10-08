// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package fwconfig

import (
	"strings"
	"testing"
)

func TestValidateL3VNI(t *testing.T) {
	d := SampleL3VNIDocument()
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mutate func(in *Instance)
		want   string
	}{
		{"no main evpn", func(in *Instance) { in.BGP.EVPN = false }, `vrf "blue": evpn needs bgp with evpn on in the main table`},
		{"vni taken", func(in *Instance) { in.VRFs[0].EVPN.VNI = 200 }, "vni 200 is also vx200's"},
		{"vni range", func(in *Instance) { in.VRFs[0].EVPN.VNI = MaxVNI + 1 }, "out of range"},
		{"no local", func(in *Instance) { in.VRFs[0].EVPN.Local = "" }, "the local VTEP address is needed"},
		{"bad rd", func(in *Instance) { in.VRFs[0].EVPN.RD = "1.2.3.4:70000" }, "route distinguisher"},
		{"bad rt", func(in *Instance) { in.VRFs[0].EVPN.ImportRTs = []string{"x:1"} }, "import route target"},
		{"nothing advertised", func(in *Instance) { in.VRFs[0].EVPN.AdvertiseIPv4, in.VRFs[0].EVPN.AdvertiseIPv6 = false, false }, "advertise IPv4, IPv6 or both"},
		{"underlay in the vrf", func(in *Instance) { in.VRFs[0].EVPN.Device = "eth3" }, `underlay interface "eth3" is in vrf blue`},
		{"underlay missing", func(in *Instance) { in.VRFs[0].EVPN.Device = "eth9" }, `underlay interface "eth9" is not in this instance`},
		{"reserved name", func(in *Instance) {
			in.Interfaces = append(in.Interfaces, Interface{Name: "l3br-1", Kind: KindBridge, Enabled: true, IPv4Mode: ModeNone})
		}, "names are for the devices of the VRFs' L3VNIs"},
		{"other as without rts", func(in *Instance) {
			in.VRFs[0].BGP = &BGP{Enabled: true, ASN: 65099}
			in.VRFs[0].EVPN.ImportRTs = nil
		}, "give the import and export route targets"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := SampleL3VNIDocument()
			c.mutate(d.Instance("guest"))
			err := d.Validate()
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("got %v, want %q", err, c.want)
			}
		})
	}
}

func TestExpandL3VNI(t *testing.T) {
	d := SampleL3VNIDocument().Expand()
	in := d.Instance("guest")
	vx, br, vrf := in.Interface("l3vx-5000"), in.Interface("l3br-5000"), in.Interface("blue")
	if vx == nil || br == nil || vrf == nil {
		t.Fatalf("devices missing: %+v", in.Interfaces)
	}
	if vx.Kind != KindVXLAN || vx.VXLAN.VNI != 5000 || vx.VXLAN.Local != "192.168.50.1" || vx.VXLAN.Device != "eth2" || vx.VRF != "" {
		t.Errorf("vxlan device: %+v %+v", vx, vx.VXLAN)
	}
	if br.Kind != KindBridge || br.VRF != "blue" || len(br.Members) != 1 || br.Members[0] != "l3vx-5000" {
		t.Errorf("bridge: %+v", br)
	}
	if !strings.Contains(strings.Join(vrf.Members, ","), "l3br-5000") {
		t.Errorf("vrf members: %v", vrf.Members)
	}
}

func TestCheckExtCommunity(t *testing.T) {
	for s, ok := range map[string]bool{
		"65000:100": true, "4200000000:100": true, "4200000000:70000": false, "65000:4294967295": true,
		"192.0.2.1:100": true, "192.0.2.1:70000": false, "0:1": false, "2001:db8::1:1": false, "a:1": false, "65000": false,
	} {
		if err := CheckExtCommunity(s); (err == nil) != ok {
			t.Errorf("%s: %v", s, err)
		}
	}
}
