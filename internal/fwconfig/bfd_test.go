// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package fwconfig

import (
	"strings"
	"testing"
)

// bfdDocument has BFD on the guest instance's link end, used by its
// default route, its upstream peer group and OSPF there.
func bfdDocument() Document {
	doc := SampleDocument()
	in := doc.Instance("guest")
	in.BFD = []BFDInterface{{Name: "lk-main", DetectMultiplier: 5, ReceiveInterval: 100, TransmitInterval: 150}}
	in.Routes[0].BFD = true
	in.BGP.PeerGroups[0].BFD = true
	in.BGP.Neighbors[1].BFD = true // not on an interface with BFD
	in.OSPF.Interfaces[0].BFD = true
	return doc
}

func TestValidateBFD(t *testing.T) {
	if doc := bfdDocument(); doc.Validate() != nil {
		err := doc.Validate()
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mutate func(in *Instance)
		want   string
	}{
		{"unknown interface", func(in *Instance) { in.BFD[0].Name = "eth9" }, `BFD: unknown interface "eth9"`},
		{"duplicate", func(in *Instance) { in.BFD = append(in.BFD, in.BFD[0]) }, "BFD on lk-main: duplicate"},
		{"multiplier", func(in *Instance) { in.BFD[0].DetectMultiplier = 1 }, "detect multiplier out of range"},
		{"interval", func(in *Instance) { in.BFD[0].ReceiveInterval = 5 }, "receive interval out of range"},
		{"route without gateway", func(in *Instance) { in.Routes[0].Gateway, in.Routes[0].Interface = "", "lk-main" }, "BFD needs a gateway"},
		{"route distance", func(in *Instance) { in.Routes[0].Metric = 1000 }, "metric is FRR's distance"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := bfdDocument()
			c.mutate(doc.Instance("guest"))
			err := doc.Validate()
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want %q, got %v", c.want, err)
			}
		})
	}
}

func TestBFDUsers(t *testing.T) {
	doc := bfdDocument().Expand()
	in := doc.Instance("guest")
	if got := in.RouteBFD(in.Routes[0]); got != "lk-main" {
		t.Errorf("route: %q", got)
	}
	if len(in.KernelRoutes()) != 0 || !in.HasBFDRoutes() {
		t.Errorf("kernel routes: %+v", in.KernelRoutes())
	}
	if got := in.NeighborBFD(in.BGP.Neighbors[0]); got != "lk-main" {
		t.Errorf("neighbour in the group: %q", got)
	}
	if got := in.NeighborBFD(in.BGP.Neighbors[1]); got != "" {
		t.Errorf("neighbour off BFD interfaces: %q", got)
	}
	// Without BFD on the interface, the route is the agent's again.
	in.BFD = nil
	if len(in.KernelRoutes()) != 1 || in.HasBFDRoutes() || in.FRRRunning() != (in.BGPRunning() || in.OSPFRunning(2) || in.OSPFRunning(3) || in.VRRPRunning()) {
		t.Errorf("without BFD: %+v", in.KernelRoutes())
	}
}
