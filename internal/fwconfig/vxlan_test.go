// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package fwconfig

import (
	"strings"
	"testing"
)

// withVXLAN adds a bridge with a VXLAN member to the sample's guest
// instance, which has BGP.
func withVXLAN(d *Document) *Instance {
	in := d.Instance("guest")
	in.Interfaces = append(in.Interfaces,
		Interface{Name: "vx150", Kind: KindVXLAN, Enabled: true, IPv4Mode: ModeNone,
			VXLAN: &VXLAN{VNI: 150, Local: "192.168.50.1", Remotes: []string{"192.0.2.2", "192.0.2.3"}}},
		Interface{Name: "br150", Kind: KindBridge, Enabled: true, IPv4Mode: ModeNone, Members: []string{"vx150"}},
	)
	return in
}

func vx(in *Instance) *VXLAN { return in.Interfaces[len(in.Interfaces)-2].VXLAN }

func TestValidateVXLAN(t *testing.T) {
	ok := SampleDocument()
	withVXLAN(&ok)
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	evpn := SampleDocument()
	in := withVXLAN(&evpn)
	in.BGP.EVPN = true
	in.BGP.Neighbors[0].EVPN.Activate = true
	if err := evpn.Validate(); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		mutate func(in *Instance)
		want   string
	}{
		{"no settings", func(in *Instance) { in.Interfaces[len(in.Interfaces)-2].VXLAN = nil }, "vxlan settings missing"},
		{"vni 0", func(in *Instance) { vx(in).VNI = 0 }, "vni 0 out of range"},
		{"vni too big", func(in *Instance) { vx(in).VNI = MaxVNI + 1 }, "out of range"},
		{"bad port", func(in *Instance) { vx(in).Port = 70000 }, "udp port"},
		{"bad local", func(in *Instance) { vx(in).Local = "224.0.0.1" }, "invalid local address"},
		{"bad remote", func(in *Instance) { vx(in).Remotes[0] = "192.0.2.2/32" }, "invalid remote address"},
		{"mixed versions", func(in *Instance) { vx(in).Remotes[0] = "2001:db8::2" }, "one IP version"},
		{"v6 without local", func(in *Instance) { vx(in).Local = ""; vx(in).Remotes = []string{"2001:db8::2"} }, "IPv6 remotes need the local address"},
		{"remote twice", func(in *Instance) { vx(in).Remotes[1] = "192.0.2.2" }, "listed twice"},
		{"remote is local", func(in *Instance) { vx(in).Remotes[1] = "192.168.50.1" }, "is the local address"},
		{"unknown underlay", func(in *Instance) { vx(in).Device = "eth9" }, `underlay interface "eth9" is not in this instance`},
		{"vni twice", func(in *Instance) {
			in.Interfaces = append(in.Interfaces, Interface{Name: "vx2", Kind: KindVXLAN, IPv4Mode: ModeNone, VXLAN: &VXLAN{VNI: 150}})
		}, "vni 150 is also vx150's"},
		{"evpn without local", func(in *Instance) { in.BGP.EVPN = true; vx(in).Remotes = nil; vx(in).Local = "" }, "evpn needs the vxlan's local address"},
		{"evpn outside a bridge", func(in *Instance) {
			in.BGP.EVPN = true
			vx(in).Remotes = nil
			in.Interfaces[len(in.Interfaces)-1].Members = nil
		}, "must be a member of a bridge"},
		{"evpn without vxlan", func(in *Instance) {
			in.BGP.EVPN = true
			vx(in).Remotes = nil
			for i := range in.Interfaces {
				if in.Interfaces[i].Kind == KindVXLAN {
					in.Interfaces[i].Enabled = false
				}
			}
		}, "evpn needs an enabled vxlan interface"},
		{"evpn rr client ebgp", func(in *Instance) { in.BGP.Neighbors[1].EVPN.RouteReflectorClient = true }, "evpn: a route reflector client must be an iBGP neighbour"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := SampleDocument()
			tc.mutate(withVXLAN(&doc))
			err := doc.Validate()
			if err == nil {
				t.Fatalf("expected error containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}
