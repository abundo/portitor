// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package fwconfig

import (
	"strings"
	"testing"
)

func TestValidateBGP(t *testing.T) {
	guest := func(d *Document) *Instance { return d.Instance("guest") }
	cases := []struct {
		name   string
		mutate func(in *Instance)
		want   string
	}{
		{"no local AS", func(in *Instance) { in.BGP.ASN = 0 }, "local AS is required"},
		{"router id v6", func(in *Instance) { in.BGP.RouterID = "2001:db8::1" }, "router id must be an IPv4 address"},
		{"hold below keepalive", func(in *Instance) { in.BGP.Keepalive, in.BGP.Hold = 30, 10 }, "timers"},
		{"network not a prefix", func(in *Instance) { in.BGP.Networks[0].Prefix = "192.168.50.1/24" }, "is not a network prefix"},
		{"network twice", func(in *Instance) { in.BGP.Networks = append(in.BGP.Networks, in.BGP.Networks[0]) }, "listed twice"},
		{"network unknown route map", func(in *Instance) { in.BGP.Networks[0].RouteMap = "nope" }, `unknown route map "nope"`},
		{"redistribute bad source", func(in *Instance) { in.BGP.Redistribute[0].Source = "rip" }, "source must be connected, static or ospf"},
		{"neighbour bad address", func(in *Instance) { in.BGP.Neighbors[0].Address = "10.255.0.1/30" }, "not an IP address"},
		{"neighbour twice", func(in *Instance) { in.BGP.Neighbors[1].Address = "10.255.0.1" }, "listed twice"},
		{"neighbour unknown group", func(in *Instance) { in.BGP.Neighbors[0].PeerGroup = "nope" }, `unknown peer group "nope"`},
		{"neighbour no remote AS", func(in *Instance) { in.BGP.Neighbors[1].RemoteAS = "" }, "remote AS is required"},
		{"group without remote AS", func(in *Instance) { in.BGP.PeerGroups[0].RemoteAS = "" }, "remote AS is required"},
		{"bad remote AS", func(in *Instance) { in.BGP.Neighbors[1].RemoteAS = "AS65001" }, "remote AS must be"},
		{"password with space", func(in *Instance) { in.BGP.PeerGroups[0].Password = "two words" }, "password"},
		{"description newline", func(in *Instance) { in.BGP.Neighbors[0].Description = "a\nrouter bgp 1" }, "control characters"},
		{"update source unknown interface", func(in *Instance) { in.BGP.Neighbors[1].UpdateSource = "eth9" }, `unknown interface "eth9"`},
		{"filter in twice", func(in *Instance) { in.BGP.PeerGroups[0].IPv4.PrefixListIn = "ours" }, "not both"},
		{"prefix list of other family", func(in *Instance) { in.BGP.Neighbors[1].IPv6.PrefixListIn = "ours" }, "is ipv4, not ipv6"},
		{"unknown route map out", func(in *Instance) { in.BGP.Neighbors[1].IPv6.RouteMapOut = "nope" }, `unknown route map "nope"`},
		{"multihop on ibgp", func(in *Instance) { in.BGP.Neighbors[1].RemoteAS = "65010" }, "ebgp multihop is for eBGP"},
		{"remove private AS on ibgp", func(in *Instance) {
			in.BGP.Neighbors[1].RemoteAS, in.BGP.Neighbors[1].EBGPMultihop = "internal", 0
		}, "remove private AS is for eBGP"},
		{"route reflector client on ebgp", func(in *Instance) { in.BGP.PeerGroups[0].IPv4.RouteReflectorClient = true }, "route reflector client must be an iBGP"},
		{"group in group", func(in *Instance) { in.BGP.PeerGroups[0].PeerGroup = "x" }, "can't be in another"},
		{"prefix list bad name", func(in *Instance) { in.RoutingPolicy.PrefixLists[0].Name = "a b" }, "name must be"},
		{"prefix list wrong family", func(in *Instance) { in.RoutingPolicy.PrefixLists[0].Entries[0].Prefix = "2001:db8::/32" }, "is not an ipv4 prefix"},
		{"prefix list host bits", func(in *Instance) { in.RoutingPolicy.PrefixLists[0].Entries[0].Prefix = "192.168.1.1/16" }, "is not a network prefix"},
		{"prefix list le too short", func(in *Instance) { in.RoutingPolicy.PrefixLists[0].Entries[0].LE = 8 }, "le 8 must be longer"},
		{"prefix list ge over le", func(in *Instance) { in.RoutingPolicy.PrefixLists[0].Entries[0].GE = 28 }, "ge 28 is more than le 24"},
		{"prefix list seq twice", func(in *Instance) {
			pl := &in.RoutingPolicy.PrefixLists[0]
			pl.Entries = append(pl.Entries, PrefixListEntry{Seq: 5, Action: Deny, Prefix: "any"})
		}, "sequence number 5 used twice"},
		{"prefix list bad action", func(in *Instance) { in.RoutingPolicy.PrefixLists[0].Entries[0].Action = "accept" }, "permit or deny"},
		{"as path regex with quote", func(in *Instance) { in.RoutingPolicy.ASPathLists[0].Entries[0].Regex = `^65000"` }, "regular expression"},
		{"as path regex with newline", func(in *Instance) { in.RoutingPolicy.ASPathLists[0].Entries[0].Regex = "^1\nexit" }, "regular expression"},
		{"community out of range", func(in *Instance) { in.RoutingPolicy.CommunityLists[0].Entries[0].Value = "65000:70000" }, "communities are AS:NN"},
		{"community unknown name", func(in *Instance) { in.RoutingPolicy.CommunityLists[0].Entries[0].Value = "no-such" }, "communities are AS:NN"},
		{"community bad kind", func(in *Instance) { in.RoutingPolicy.CommunityLists[0].Kind = "extended" }, `invalid kind "extended"`},
		{"route map unknown community", func(in *Instance) { in.RoutingPolicy.RouteMaps[0].Entries[0].MatchCommunity = "nope" }, `unknown community list "nope"`},
		{"route map unknown as path", func(in *Instance) { in.RoutingPolicy.RouteMaps[0].Entries[1].MatchASPath = "nope" }, `unknown as path list "nope"`},
		{"route map unknown prefix list", func(in *Instance) { in.RoutingPolicy.RouteMaps[1].Entries[0].MatchPrefixList = "nope" }, `unknown prefix list "nope"`},
		{"route map additive without communities", func(in *Instance) { in.RoutingPolicy.RouteMaps[0].Entries[1].SetCommunity = "" }, "additive needs communities"},
		{"route map bad prepend", func(in *Instance) { in.RoutingPolicy.RouteMaps[0].Entries[1].SetASPathPrepend = "65000 x" }, `"x" is not an AS number`},
		{"route map bad next hop", func(in *Instance) { in.RoutingPolicy.RouteMaps[0].Entries[1].SetNextHop = "gw" }, "is not an address"},
		{"route map bad origin", func(in *Instance) { in.RoutingPolicy.RouteMaps[0].Entries[1].SetOrigin = "bgp" }, "set origin"},
		{"route map negative local pref", func(in *Instance) {
			in.RoutingPolicy.RouteMaps[0].Entries[1].SetLocalPreference = ptr(int64(-1))
		}, "out of range"},
		{"route map duplicate name", func(in *Instance) { in.RoutingPolicy.RouteMaps[1].Name = "from-upstream" }, "duplicate name"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := SampleDocument()
			c.mutate(guest(&doc))
			err := doc.Validate()
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want %q, got %v", c.want, err)
			}
		})
	}
}

// What the GUI checks on its own, before the document exists.
func TestCheckBGPObjects(t *testing.T) {
	if p := CheckPrefixList(PrefixList{Name: "ok", Family: "ipv6", Entries: []PrefixListEntry{{Seq: 5, Action: Permit, Prefix: "2001:db8::/32", GE: 48, LE: 64}}}); p != nil {
		t.Errorf("valid prefix list: %v", p)
	}
	if p := CheckCommunityList(CommunityList{Name: "lg", Kind: CommunityLargeStandard, Entries: []CommunityEntry{{Action: Permit, Value: "65000:1:4294967295"}}}); p != nil {
		t.Errorf("valid large community list: %v", p)
	}
	if p := CheckCommunityList(CommunityList{Name: "lg", Kind: CommunityLargeStandard, Entries: []CommunityEntry{{Action: Permit, Value: "65000:1:4294967296"}}}); p == nil {
		t.Error("large community over 32 bits accepted")
	}
	// A reference is not checked on its own.
	if p := CheckRouteMap(RouteMap{Name: "m", Entries: []RouteMapEntry{{Seq: 10, Action: Permit, MatchPrefixList: "elsewhere"}}}); p != nil {
		t.Errorf("route map: %v", p)
	}
	if p := CheckBGPSession(65010, BGPPeer{EBGPMultihop: 2}, "65010"); len(p) != 1 {
		t.Errorf("multihop on iBGP: %v", p)
	}
	if p := CheckBGPSession(0, BGPPeer{EBGPMultihop: 2}, "65010"); p != nil {
		t.Errorf("without a local AS nothing is known: %v", p)
	}
	if p := CheckBGPSession(65010, BGPPeer{IPv4: BGPAddressFamily{RouteReflectorClient: true}}, "internal"); p != nil {
		t.Errorf("route reflector client on iBGP: %v", p)
	}
}

// A disabled BGP is left out of the document by portitor-web; the
// validator still checks one that is there.
func TestBGPRunning(t *testing.T) {
	doc := SampleDocument()
	if !doc.Instance("guest").BGPRunning() || doc.Instance("main").BGPRunning() {
		t.Fatal("BGPRunning")
	}
	doc.Instance("guest").BGP.Enabled = false
	if doc.Instance("guest").BGPRunning() {
		t.Fatal("disabled BGP runs")
	}
}
