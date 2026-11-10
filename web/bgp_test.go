// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"encoding/json"
	"maps"
	"net/http"
	"strings"
	"testing"

	"github.com/abundo/portitor/internal/builder"
)

func TestRoutingObjects(t *testing.T) {
	env := newEnv(t)
	env.host("main")
	env.vf("lab")

	// Prefixes are masked.
	env.put("instance=main/prefix-list=ours", map[string]any{"family": "ipv4", "entry": []map[string]any{{"seq": 20, "action": "deny", "prefix": "any"}, {"seq": 25, "action": "permit", "prefix": "192.168.1.7/24", "le": 32}}})
	if es := env.node("instance=main/prefix-list=ours").Lists["entry"]; len(es) != 2 || es[1].Leaf("prefix") != "192.168.1.0/24" {
		t.Errorf("entries: %v", es)
	}
	for what, body := range map[string]map[string]any{
		"bad family":   {"name": "x", "family": "ipv5"},
		"wrong family": {"name": "x", "family": "ipv6", "entry": []map[string]any{{"seq": 5, "action": "permit", "prefix": "10.0.0.0/8"}}},
		"bad name":     {"name": "a b"},
		"duplicate":    {"name": "ours"},
	} {
		if rec := env.cfg("POST", "instance=main/prefix-list", body); rec.Code < 400 {
			t.Errorf("%s accepted: %d %s", what, rec.Code, rec.Body)
		}
	}
	// The same name in another instance is another list.
	env.put("instance=lab/prefix-list=ours", map[string]any{"family": "ipv4"})
	env.put("instance=main/as-path-list=short", map[string]any{"entry": []map[string]any{{"action": "permit", "regex": "^65000$"}}})
	env.put("instance=main/community-list=blackhole", map[string]any{"kind": "standard", "entry": []map[string]any{{"action": "permit", "value": "  65000:666   blackhole "}}})

	// A route map refers to objects of its own instance only.
	entries := []map[string]any{
		{"seq": 10, "action": "permit", "match-prefix-list": "ours", "match-as-path": "short", "set-local-preference": 200},
		{"seq": 20, "action": "deny", "match-community": "blackhole", "set-metric": 5},
	}
	if rec := env.cfg("PUT", "instance=lab/route-map=in", map[string]any{"entry": entries}); rec.Code != http.StatusBadRequest {
		t.Errorf("objects of another instance: %d %s", rec.Code, rec.Body)
	}
	env.put("instance=main/route-map=in", map[string]any{"entry": entries})
	if e := env.node("instance=main/route-map=in").Lists["entry"][1]; e.Leaf("set-metric") != "" {
		t.Errorf("a deny entry keeps a set: %+v", e.Leaves)
	}

	// BGP refers to the route map and the prefix list.
	env.put("instance=main/bgp=main", map[string]any{"enabled": true, "asn": 65000, "network": []map[string]any{{"prefix": "192.168.1.1/24", "route-map": "in"}}, "redist-connected-v4": true, "redist-connected-v4-map": "in"})
	if rec := env.cfg("POST", "instance=main/bgp", map[string]any{"asn": 65001, "vrf": "main"}); rec.Code != http.StatusBadRequest {
		t.Errorf("second BGP config: %d %s", rec.Code, rec.Body)
	}
	env.post("instance=main/bgp-peer-group", map[string]any{"name": "up", "remote-as": "65001", "v4-activate": true, "v4-prefix-list-out": "ours", "vrf": "main"})
	env.post("instance=main/bgp-neighbor", map[string]any{"address": "192.0.2.1", "enabled": true, "peer-group": "up", "v4-activate": true, "v4-route-map-in": "in", "vrf": "main"})

	// Renames rewrite the references.
	env.mustCfg("POST", "instance=main/prefix-list=ours?action=rename", map[string]any{"keys": []string{"mine"}})
	env.mustCfg("POST", "instance=main/route-map=in?action=rename", map[string]any{"keys": []string{"from-up"}})
	env.mustCfg("POST", "instance=main/bgp-peer-group=up?action=rename", map[string]any{"keys": []string{"upstream"}})
	m := env.node("instance=main/route-map=from-up")
	cfg := env.node("instance=main/bgp=main")
	grp := env.node("instance=main/bgp-peer-group=upstream")
	nb := env.node("instance=main/bgp-neighbor=main,192.0.2.1")
	if m.Lists["entry"][0].Leaf("match-prefix-list") != "mine" || cfg.Lists["network"][0].Leaf("route-map") != "from-up" || cfg.Leaf("redist-connected-v4-map") != "from-up" ||
		grp.Leaf("v4-prefix-list-out") != "mine" || nb.Leaf("v4-route-map-in") != "from-up" || nb.Leaf("peer-group") != "upstream" {
		t.Errorf("not rewritten")
	}
	if env.node("instance=lab/prefix-list=ours") == nil {
		t.Error("another instance's list renamed")
	}

	// Objects in use can't be deleted, nor a prefix list change family.
	for _, path := range []string{"instance=main/prefix-list=mine", "instance=main/route-map=from-up", "instance=main/bgp-peer-group=upstream"} {
		if rec := env.cfg("DELETE", path, nil); rec.Code != http.StatusBadRequest {
			t.Errorf("delete %s: %d %s", path, rec.Code, rec.Body)
		}
	}
	if rec := env.cfg("PUT", "instance=main/prefix-list=mine", map[string]any{"family": "ipv6"}); rec.Code != http.StatusBadRequest {
		t.Errorf("family change of a list in use: %d %s", rec.Code, rec.Body)
	}

	// The document holds BGP and the objects; the builder's result
	// validates.
	doc, err := builder.Build(env.input(), 1)
	if err != nil {
		t.Fatal(err)
	}
	in := doc.Instance("main")
	if in.BGP == nil || in.BGP.ASN != 65000 || len(in.BGP.Neighbors) != 1 || in.BGP.Neighbors[0].PeerGroup != "upstream" ||
		len(in.BGP.Redistribute) != 1 || len(in.RoutingPolicy.RouteMaps) != 1 || in.RoutingPolicy.CommunityLists[0].Entries[0].Value != "65000:666 blackhole" {
		t.Errorf("document: %+v %+v", in.BGP, in.RoutingPolicy)
	}
	if lab := doc.Instance("lab"); lab.BGP != nil || !lab.RoutingPolicy.Empty() {
		t.Errorf("lab has no BGP: %+v %+v", lab.BGP, lab.RoutingPolicy)
	}

	// Turned off, BGP and its objects stay out of the document.
	env.patch("instance=main/bgp=main", map[string]any{"enabled": false})
	doc, _ = builder.Build(env.input(), 2)
	if in := doc.Instance("main"); in.BGP != nil || !in.RoutingPolicy.Empty() {
		t.Errorf("BGP off: %+v", in.BGP)
	}
}

func TestBGPNeighbors(t *testing.T) {
	env := newEnv(t)
	env.host("main")
	env.put("instance=main/interface=lo1", map[string]any{"kind": "bridge", "enabled": true, "ipv4-mode": "static", "addresses": []string{"10.0.0.1/32"}})
	env.put("instance=main/bgp=main", map[string]any{"enabled": true, "asn": 65000})

	const secret = "s3cret-pw"
	n := map[string]any{"address": "2001:DB8::0001", "vrf": "main", "enabled": true, "remote-as": "65001", "password": secret, "v6-activate": true}
	for field, v := range map[string]any{
		"address":       "192.0.2.0/24",
		"remote-as":     "AS1",
		"password":      "has space",
		"update-source": "eth9",
		"peer-group":    "nope",
	} {
		c := maps.Clone(n)
		c[field] = v
		if rec := env.cfg("POST", "instance=main/bgp-neighbor", c); rec.Code != http.StatusBadRequest {
			t.Errorf("bad %s accepted: %d %s", field, rec.Code, rec.Body)
		}
	}
	// What is for eBGP only, on an iBGP neighbour.
	if rec := env.cfg("POST", "instance=main/bgp-neighbor", map[string]any{"address": "192.0.2.9", "remote-as": "65000", "ebgp-multihop": 2, "vrf": "main"}); rec.Code != http.StatusBadRequest {
		t.Errorf("multihop on iBGP: %d %s", rec.Code, rec.Body)
	}
	// Both a prefix list and a route map in.
	env.put("instance=main/prefix-list=p6", map[string]any{"family": "ipv6"})
	env.put("instance=main/route-map=m", map[string]any{})
	if rec := env.cfg("POST", "instance=main/bgp-neighbor", map[string]any{"address": "192.0.2.9", "remote-as": "65009", "v6-activate": true, "v6-prefix-list-in": "p6", "v6-route-map-in": "m", "vrf": "main"}); rec.Code != http.StatusBadRequest {
		t.Errorf("two filters in: %d %s", rec.Code, rec.Body)
	}

	env.post("instance=main/bgp-neighbor", n)
	nb := "instance=main/bgp-neighbor=main,2001:db8::1"
	if env.node(nb) == nil {
		t.Fatal("address not canonical")
	}
	if rec := env.do("GET", "/api/config/candidate/instance=main/bgp-neighbor", nil); strings.Contains(rec.Body.String(), secret) {
		t.Errorf("password leaked: %s", rec.Body)
	}
	env.patch(nb, map[string]any{"description": "transit", "update-source": "lo1"})
	if stored := env.node(nb); stored.Leaf("password") != secret || stored.Leaf("description") != "transit" {
		t.Errorf("stored %+v", stored.Leaves)
	}
	// A filter of a family that is not active is dropped.
	env.patch(nb, map[string]any{"v4-route-map-in": "m"})
	if got := env.node(nb).Leaf("v4-route-map-in"); got != "" {
		t.Errorf("filter of an inactive family kept: %q", got)
	}

	// The deployment history doesn't keep the password.
	doc, err := builder.Build(env.input(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Instance("main").BGP.Neighbors[0].Password != secret {
		t.Error("password not in the document")
	}
	b, _ := json.Marshal(doc.Redacted())
	if strings.Contains(string(b), secret) {
		t.Error("password in the redacted document")
	}

	// The update source follows a renamed interface; deleting one in use
	// is refused.
	env.mustCfg("POST", "instance=main/interface=lo1?action=rename", map[string]any{"keys": []string{"lo2"}})
	if got := env.node(nb).Leaf("update-source"); got != "lo2" {
		t.Errorf("update source %q", got)
	}
	if rec := env.cfg("DELETE", "instance=main/interface=lo2", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("delete interface in use: %d %s", rec.Code, rec.Body)
	}
	env.patch(nb, map[string]any{"password": nil})
	if env.node(nb).Leaf("password") != "" {
		t.Error("password not cleared")
	}

	// A link-local neighbour needs its interface, which follows a rename
	// and can't be deleted; a global address drops one.
	ll := map[string]any{"address": "fe80::1", "vrf": "main", "enabled": true, "remote-as": "external", "v4-activate": true, "v6-activate": true}
	if rec := env.cfg("POST", "instance=main/bgp-neighbor", ll); rec.Code != http.StatusBadRequest {
		t.Errorf("link-local without interface: %d %s", rec.Code, rec.Body)
	}
	ll["interface"] = "lo2"
	env.post("instance=main/bgp-neighbor", ll)
	env.patch(nb, map[string]any{"update-source": nil, "interface": "lo2"})
	if got := env.node(nb).Leaf("interface"); got != "" {
		t.Errorf("interface kept on a global neighbour: %q", got)
	}
	env.mustCfg("POST", "instance=main/interface=lo2?action=rename", map[string]any{"keys": []string{"lo3"}})
	if got := env.node("instance=main/bgp-neighbor=main,fe80::1").Leaf("interface"); got != "lo3" {
		t.Errorf("interface %q", got)
	}
	if rec := env.cfg("DELETE", "instance=main/interface=lo3", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("delete interface of a link-local neighbour: %d %s", rec.Code, rec.Body)
	}
	doc, _ = builder.Build(env.input(), 1)
	if p := doc.Instance("main").BGP.Neighbors[1]; p.Address != "fe80::1" || p.Interface != "lo3" {
		t.Errorf("document neighbour %+v", p)
	}
}
