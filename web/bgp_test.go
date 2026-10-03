// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/abundo/portitor/internal/builder"
	"github.com/abundo/portitor/models"
)

func TestRoutingObjects(t *testing.T) {
	env := newEnv(t)
	inst := env.create("/api/instances", map[string]any{"name": "main"})
	other := env.create("/api/instances", map[string]any{"name": "lab"})

	// Entries are normalised: sequence numbers filled in and sorted,
	// prefixes masked.
	rec := env.do("POST", "/api/routing/prefix-lists", map[string]any{
		"instance_id": inst, "name": "ours", "family": "ipv4",
		"entries": []map[string]any{{"seq": 20, "action": "deny", "prefix": "any"}, {"action": "permit", "prefix": "192.168.1.0/24", "le": 32}},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var pl models.RoutePrefixList
	_ = json.Unmarshal(rec.Body.Bytes(), &pl)
	if len(pl.Entries) != 2 || pl.Entries[0].Seq != 20 || pl.Entries[1].Seq != 25 || pl.Entries[1].Prefix != "192.168.1.0/24" {
		t.Errorf("entries: %+v", pl.Entries)
	}
	for what, body := range map[string]map[string]any{
		"bad family":   {"instance_id": inst, "name": "x", "family": "ipv5"},
		"wrong family": {"instance_id": inst, "name": "x", "family": "ipv6", "entries": []map[string]any{{"action": "permit", "prefix": "10.0.0.0/8"}}},
		"bad name":     {"instance_id": inst, "name": "a b"},
		"duplicate":    {"instance_id": inst, "name": "ours"},
	} {
		if rec := env.do("POST", "/api/routing/prefix-lists", body); rec.Code < 400 {
			t.Errorf("%s accepted: %d %s", what, rec.Code, rec.Body)
		}
	}
	// The same name in another instance is another list.
	env.create("/api/routing/prefix-lists", map[string]any{"instance_id": other, "name": "ours", "family": "ipv4"})
	env.create("/api/routing/as-path-lists", map[string]any{"instance_id": inst, "name": "short", "entries": []map[string]any{{"action": "permit", "regex": "^65000$"}}})
	env.create("/api/routing/community-lists", map[string]any{"instance_id": inst, "name": "blackhole", "kind": "standard", "entries": []map[string]any{{"action": "permit", "value": "  65000:666   blackhole "}}})

	// A route map refers to objects of its own instance only.
	entries := []map[string]any{
		{"seq": 10, "action": "permit", "match_prefix_list": "ours", "match_as_path": "short", "set_local_preference": 200},
		{"seq": 20, "action": "deny", "match_community": "blackhole", "set_metric": 5},
	}
	if rec := env.do("POST", "/api/routing/route-maps", map[string]any{"instance_id": other, "name": "in", "entries": entries}); rec.Code != http.StatusBadRequest {
		t.Errorf("objects of another instance: %d %s", rec.Code, rec.Body)
	}
	rm := env.create("/api/routing/route-maps", map[string]any{"instance_id": inst, "name": "in", "entries": entries})
	var m models.RouteMap
	env.srv.db.First(&m, rm)
	if m.Entries[1].SetMetric != nil {
		t.Errorf("a deny entry keeps a set: %+v", m.Entries[1])
	}

	// BGP refers to the route map and the prefix list.
	env.create("/api/bgp/config", map[string]any{
		"instance_id": inst, "enabled": true, "asn": 65000,
		"networks":            []map[string]any{{"prefix": "192.168.1.1/24", "route_map": "in"}},
		"redist_connected_v4": true, "redist_connected_v4_map": "in",
	})
	if rec := env.do("POST", "/api/bgp/config", map[string]any{"instance_id": inst, "asn": 65001}); rec.Code != http.StatusConflict {
		t.Errorf("second BGP config: %d %s", rec.Code, rec.Body)
	}
	g := env.create("/api/bgp/peer-groups", map[string]any{"instance_id": inst, "name": "up", "remote_as": "65001", "v4_activate": true, "v4_prefix_list_out": "ours"})
	env.create("/api/bgp/neighbors", map[string]any{"instance_id": inst, "address": "192.0.2.1", "enabled": true, "peer_group": "up", "v4_activate": true, "v4_route_map_in": "in"})

	// Renames rewrite the references.
	if rec := env.do("PUT", "/api/routing/prefix-lists/"+itoa(pl.ID), map[string]any{"name": "mine"}); rec.Code != http.StatusOK {
		t.Fatalf("rename: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("PUT", "/api/routing/route-maps/"+itoa(rm), map[string]any{"name": "from-up"}); rec.Code != http.StatusOK {
		t.Fatalf("rename: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("PUT", "/api/bgp/peer-groups/"+itoa(g), map[string]any{"name": "upstream"}); rec.Code != http.StatusOK {
		t.Fatalf("rename: %d %s", rec.Code, rec.Body)
	}
	env.srv.db.First(&m, rm)
	var cfg models.BgpConfig
	env.srv.db.Where("instance_id = ?", inst).First(&cfg)
	var grp models.BgpPeerGroup
	env.srv.db.First(&grp, g)
	var nb models.BgpNeighbor
	env.srv.db.Where("instance_id = ?", inst).First(&nb)
	if m.Entries[0].MatchPrefixList != "mine" || cfg.Networks[0].RouteMap != "from-up" || cfg.RedistConnectedV4Map != "from-up" ||
		grp.V4PrefixListOut != "mine" || nb.V4RouteMapIn != "from-up" || nb.PeerGroup != "upstream" {
		t.Errorf("not rewritten: map %+v cfg %+v group %s neighbour %s %s", m.Entries[0], cfg.Networks, grp.V4PrefixListOut, nb.V4RouteMapIn, nb.PeerGroup)
	}
	var lab models.RoutePrefixList
	env.srv.db.Where("instance_id = ?", other).First(&lab)
	if lab.Name != "ours" {
		t.Errorf("another instance's list renamed: %s", lab.Name)
	}

	// Objects in use can't be deleted, nor a prefix list change family.
	for _, path := range []string{"/api/routing/prefix-lists/" + itoa(pl.ID), "/api/routing/route-maps/" + itoa(rm), "/api/bgp/peer-groups/" + itoa(g)} {
		if rec := env.do("DELETE", path, nil); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "is used by") {
			t.Errorf("delete %s: %d %s", path, rec.Code, rec.Body)
		}
	}
	if rec := env.do("PUT", "/api/routing/prefix-lists/"+itoa(pl.ID), map[string]any{"family": "ipv6", "entries": []any{}}); rec.Code != http.StatusBadRequest {
		t.Errorf("family change of a list in use: %d %s", rec.Code, rec.Body)
	}
	// A row stays in its instance.
	if rec := env.do("PUT", "/api/routing/route-maps/"+itoa(rm), map[string]any{"instance_id": other}); rec.Code != http.StatusOK {
		t.Fatalf("move: %d %s", rec.Code, rec.Body)
	}
	env.srv.db.First(&m, rm)
	if m.InstanceID != inst {
		t.Errorf("route map moved to instance %d", m.InstanceID)
	}

	// The document holds BGP and the objects; the builder's result
	// validates.
	doc, err := builder.Build(env.srv.db, 1)
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
	if rec := env.do("PUT", "/api/bgp/config/"+itoa(cfg.ID), map[string]any{"enabled": false}); rec.Code != http.StatusOK {
		t.Fatal(rec.Body)
	}
	doc, _ = builder.Build(env.srv.db, 2)
	if in := doc.Instance("main"); in.BGP != nil || !in.RoutingPolicy.Empty() {
		t.Errorf("BGP off: %+v", in.BGP)
	}
}

func TestBGPNeighbors(t *testing.T) {
	env := newEnv(t)
	inst := env.create("/api/instances", map[string]any{"name": "main"})
	env.create("/api/interfaces", map[string]any{"instance_id": inst, "name": "lo1", "kind": "bridge", "enabled": true, "ipv4_mode": "static", "addresses": []string{"10.0.0.1/32"}})
	env.create("/api/bgp/config", map[string]any{"instance_id": inst, "enabled": true, "asn": 65000})

	const secret = "s3cret-pw"
	n := map[string]any{"instance_id": inst, "address": "2001:DB8::0001", "enabled": true, "remote_as": "65001", "new_password": secret, "v6_activate": true}
	for field, v := range map[string]any{
		"address":       "192.0.2.0/24",
		"remote_as":     "AS1",
		"new_password":  "has space",
		"update_source": "eth9",
		"peer_group":    "nope",
	} {
		c := map[string]any{}
		for k, x := range n {
			c[k] = x
		}
		c[field] = v
		if rec := env.do("POST", "/api/bgp/neighbors", c); rec.Code != http.StatusBadRequest {
			t.Errorf("bad %s accepted: %d %s", field, rec.Code, rec.Body)
		}
	}
	// What is for eBGP only, on an iBGP neighbour.
	if rec := env.do("POST", "/api/bgp/neighbors", map[string]any{"instance_id": inst, "address": "192.0.2.9", "remote_as": "65000", "ebgp_multihop": 2}); rec.Code != http.StatusBadRequest {
		t.Errorf("multihop on iBGP: %d %s", rec.Code, rec.Body)
	}
	// Both a prefix list and a route map in.
	env.create("/api/routing/prefix-lists", map[string]any{"instance_id": inst, "name": "p6", "family": "ipv6"})
	env.create("/api/routing/route-maps", map[string]any{"instance_id": inst, "name": "m"})
	if rec := env.do("POST", "/api/bgp/neighbors", map[string]any{"instance_id": inst, "address": "192.0.2.9", "remote_as": "65009", "v6_activate": true, "v6_prefix_list_in": "p6", "v6_route_map_in": "m"}); rec.Code != http.StatusBadRequest {
		t.Errorf("two filters in: %d %s", rec.Code, rec.Body)
	}

	rec := env.do("POST", "/api/bgp/neighbors", n)
	if rec.Code != http.StatusCreated || strings.Contains(rec.Body.String(), secret) || !strings.Contains(rec.Body.String(), `"has_password":true`) {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var created models.BgpNeighbor
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	id := itoa(created.ID)
	if created.Address != "2001:db8::1" {
		t.Errorf("address not canonical: %s", created.Address)
	}
	if rec := env.do("GET", "/api/bgp/neighbors?instance_id="+itoa(inst), nil); strings.Contains(rec.Body.String(), secret) {
		t.Errorf("password leaked: %s", rec.Body)
	}
	// Saving without a password keeps it; clear_password removes it.
	if rec := env.do("PUT", "/api/bgp/neighbors/"+id, map[string]any{"description": "transit", "update_source": "lo1"}); rec.Code != http.StatusOK {
		t.Fatalf("update: %d %s", rec.Code, rec.Body)
	}
	var stored models.BgpNeighbor
	env.srv.db.First(&stored, created.ID)
	if stored.Password != secret || stored.Description != "transit" {
		t.Errorf("stored %+v", stored)
	}
	// A filter of a family that is not active is dropped.
	if rec := env.do("PUT", "/api/bgp/neighbors/"+id, map[string]any{"v4_route_map_in": "m"}); rec.Code != http.StatusOK {
		t.Fatal(rec.Body)
	}
	env.srv.db.First(&stored, created.ID)
	if stored.V4RouteMapIn != "" {
		t.Errorf("filter of an inactive family kept: %q", stored.V4RouteMapIn)
	}

	// The deployment history doesn't keep the password.
	doc, err := builder.Build(env.srv.db, 1)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Instance("main").BGP.Neighbors[0].Password != secret {
		t.Error("password not in the document")
	}
	b, _ := json.Marshal(redactDoc(*doc))
	if strings.Contains(string(b), secret) {
		t.Error("password in the redacted document")
	}

	// The update source follows a renamed interface; deleting one in use
	// is refused.
	var lo models.Interface
	env.srv.db.Where("name = ?", "lo1").First(&lo)
	if rec := env.do("PUT", "/api/interfaces/"+itoa(lo.ID), map[string]any{"name": "lo2"}); rec.Code != http.StatusOK {
		t.Fatalf("rename interface: %d %s", rec.Code, rec.Body)
	}
	env.srv.db.First(&stored, created.ID)
	if stored.UpdateSource != "lo2" {
		t.Errorf("update source %q", stored.UpdateSource)
	}
	if rec := env.do("DELETE", "/api/interfaces/"+itoa(lo.ID), nil); rec.Code != http.StatusBadRequest {
		t.Errorf("delete interface in use: %d %s", rec.Code, rec.Body)
	}

	if rec := env.do("PUT", "/api/bgp/neighbors/"+id, map[string]any{"clear_password": true}); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"has_password":false`) {
		t.Fatalf("clear: %d %s", rec.Code, rec.Body)
	}
	env.srv.db.First(&stored, created.ID)
	if stored.Password != "" {
		t.Error("password not cleared")
	}

	// A link-local neighbour needs its interface, which follows a rename
	// and can't be deleted; a global address drops one.
	ll := map[string]any{"instance_id": inst, "address": "fe80::1", "enabled": true, "remote_as": "external", "v4_activate": true, "v6_activate": true}
	if rec := env.do("POST", "/api/bgp/neighbors", ll); rec.Code != http.StatusBadRequest {
		t.Errorf("link-local without interface: %d %s", rec.Code, rec.Body)
	}
	ll["interface"] = "lo2"
	llID := env.create("/api/bgp/neighbors", ll)
	if rec := env.do("PUT", "/api/bgp/neighbors/"+id, map[string]any{"update_source": "", "interface": "lo2"}); rec.Code != http.StatusOK {
		t.Fatalf("update: %d %s", rec.Code, rec.Body)
	}
	env.srv.db.First(&stored, created.ID)
	if stored.Interface != "" {
		t.Errorf("interface kept on a global neighbour: %q", stored.Interface)
	}
	if rec := env.do("PUT", "/api/interfaces/"+itoa(lo.ID), map[string]any{"name": "lo3"}); rec.Code != http.StatusOK {
		t.Fatalf("rename interface: %d %s", rec.Code, rec.Body)
	}
	var llStored models.BgpNeighbor
	env.srv.db.First(&llStored, llID)
	if llStored.Interface != "lo3" {
		t.Errorf("interface %q", llStored.Interface)
	}
	if rec := env.do("DELETE", "/api/interfaces/"+itoa(lo.ID), nil); rec.Code != http.StatusBadRequest {
		t.Errorf("delete interface of a link-local neighbour: %d %s", rec.Code, rec.Body)
	}
	doc, _ = builder.Build(env.srv.db, 1)
	if p := doc.Instance("main").BGP.Neighbors[1]; p.Address != "fe80::1" || p.Interface != "lo3" {
		t.Errorf("document neighbour %+v", p)
	}
}
