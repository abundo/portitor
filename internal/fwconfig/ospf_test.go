// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package fwconfig

import (
	"strings"
	"testing"
)

func TestValidateOSPF(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(in *Instance)
		want   string
	}{
		{"router id v6", func(in *Instance) { in.OSPF.RouterID = "2001:db8::1" }, "router id must be an IPv4 address"},
		{"area not dotted", func(in *Instance) { in.OSPF.Interfaces[0].Area = "0" }, `area "0" must be dotted`},
		{"unknown interface", func(in *Instance) { in.OSPF.Interfaces[0].Name = "eth9" }, "interface eth9: unknown interface"},
		{"interface twice", func(in *Instance) { in.OSPF.Interfaces[1].Name = "lk-main" }, "interface lk-main listed twice"},
		{"backbone stub", func(in *Instance) { in.OSPF.Areas[0].ID = "0.0.0.0" }, "the backbone can't be a stub"},
		{"bad area type", func(in *Instance) { in.OSPF.Areas[0].Type = "totally" }, "type must be normal, stub or nssa"},
		{"no summary on normal", func(in *Instance) { in.OSPF.Areas[0].Type = AreaNormal }, "no summary is for a stub or NSSA"},
		{"range of other family", func(in *Instance) { in.OSPF.Ranges[0].Prefix = "2001:db8::/32" }, "is not an IPv4 prefix"},
		{"range host bits", func(in *Instance) { in.OSPF.Ranges[0].Prefix = "192.168.50.1/23" }, "is not a network prefix"},
		{"range not advertised with cost", func(in *Instance) { in.OSPF.Ranges[0].NotAdvertise = true }, "not advertised has no cost"},
		{"summary of other family", func(in *Instance) { in.OSPF6.Summaries = []OSPFSummary{{Prefix: "10.0.0.0/8"}} }, "is not an IPv6 prefix"},
		{"dead below hello", func(in *Instance) { in.OSPF.Interfaces[0].DeadInterval = 5 }, "dead interval"},
		{"priority out of range", func(in *Instance) { in.OSPF.Interfaces[1].Priority = ptr(256) }, "priority out of range"},
		{"bad network type", func(in *Instance) { in.OSPF.Interfaces[0].NetworkType = "nbma" }, "network type must be"},
		{"key with space", func(in *Instance) { in.OSPF.Interfaces[0].AuthKey = "two words" }, "authentication key: 1-16"},
		{"key too long", func(in *Instance) { in.OSPF.Interfaces[0].AuthKey = strings.Repeat("k", 17) }, "authentication key: 1-16"},
		{"key without id", func(in *Instance) { in.OSPF.Interfaces[0].AuthKeyID = 0 }, "key id out of range"},
		{"md5 on ospfv3", func(in *Instance) { in.OSPF6.Interfaces[0].AuthKey, in.OSPF6.Interfaces[0].AuthKeyID = "k", 1 }, "MD5 authentication is for OSPFv2"},
		{"ospfv3 interface without area", func(in *Instance) { in.OSPF6.Interfaces[0].Area = "" }, "an area is required"},
		{"ospfv3 networks", func(in *Instance) {
			in.OSPF6.Networks = []OSPFNetwork{{Prefix: "2001:db8::/64", Area: "0.0.0.0"}}
		}, "network statements are for OSPFv2"},
		{"networks with interface areas", func(in *Instance) {
			in.OSPF.Networks = []OSPFNetwork{{Prefix: "10.255.0.0/30", Area: "0.0.0.0"}}
		}, "can't be used together"},
		{"bad redistribute source", func(in *Instance) { in.OSPF.Redistribute[1].Source = "rip" }, "source must be connected, static or bgp"},
		{"redistribute twice", func(in *Instance) { in.OSPF.Redistribute[1].Source = RedistStatic }, "listed twice"},
		{"bad metric type", func(in *Instance) { in.OSPF.Redistribute[0].MetricType = 3 }, "metric type must be 1 or 2"},
		{"unknown route map", func(in *Instance) { in.OSPF.Redistribute[0].RouteMap = "nope" }, `unknown route map "nope"`},
		{"always without originate", func(in *Instance) { in.OSPF.DefaultOriginate, in.OSPF.DefaultAlways = false, true }, "only with default originate"},
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

	// Network statements alone, with interfaces for their settings only.
	doc := SampleDocument()
	o := doc.Instance("guest").OSPF
	o.Networks = []OSPFNetwork{{Prefix: "10.255.0.0/30", Area: "0.0.0.0"}}
	for i := range o.Interfaces {
		o.Interfaces[i].Area = ""
	}
	if err := doc.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestParseOSPFArea(t *testing.T) {
	for in, want := range map[string]string{"0": "0.0.0.0", "1": "0.0.0.1", "256": "0.0.1.0", "4294967295": "255.255.255.255", "0.0.0.5": "0.0.0.5"} {
		if got, ok := ParseOSPFArea(in); !ok || got != want {
			t.Errorf("%s: %s %v", in, got, ok)
		}
	}
	for _, in := range []string{"", "-1", "4294967296", "1.2.3", "::1", "backbone"} {
		if _, ok := ParseOSPFArea(in); ok {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestFRRRunning(t *testing.T) {
	doc := SampleDocument()
	in := doc.Instance("guest")
	in.BGP, in.VRRP = nil, nil
	if !in.FRRRunning() || !in.OSPFRunning(2) || !in.OSPFRunning(3) {
		t.Fatal("OSPF alone runs FRR")
	}
	in.OSPF.Enabled, in.OSPF6 = false, nil
	if in.FRRRunning() {
		t.Fatal("FRR runs with nothing enabled")
	}
}
