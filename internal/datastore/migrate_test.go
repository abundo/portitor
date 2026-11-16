// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package datastore

import (
	"slices"
	"testing"

	"github.com/abundo/portitor/internal/schema"
)

// A 1.0.0 tree: the host is the instance with is-default; its
// configuration becomes the top level's, its DNS templates join the
// firewall's, and a second read changes nothing.
const tree100 = `{
 "portitor:instance": [
  {"name": "main", "is-default": true, "firewall": "fw", "description": "the host",
   "interface": [{"name": "lan", "kind": "physical", "addresses": ["192.168.1.1/24"]}],
   "dns-soa-template": [{"name": "own", "mname": "ns1.example.com", "rname": "h.example.com"}],
   "dns-forwarders": ["192.0.2.53"]},
  {"name": "blue", "firewall": "fw", "interface": [{"name": "eth1", "kind": "physical"}]}],
 "portitor:dns-soa-template": [{"name": "fw", "mname": "ns1.example.com", "rname": "h.example.com"}],
 "portitor:firewall": [{"name": "fw"}],
 "portitor:link": [{"name": "l1", "instance-a": "main", "interface-a": "to-blue", "instance-b": "blue", "interface-b": "to-main"}]
}`

func TestMigrateHostToRoot(t *testing.T) {
	tr := New(schema.MustLoad())
	if err := tr.UnmarshalJSON([]byte(tree100)); err != nil {
		t.Fatal(err)
	}
	if !tr.Migrated {
		t.Error("not marked migrated")
	}
	r := tr.Root
	if r.Leaf("host-name") != "main" || r.Leaf("description") != "the host" || r.Entry("interface", []string{"lan"}) == nil {
		t.Errorf("top level: %v %v", r.Leaves, r.Lists["interface"])
	}
	if got := r.LeafLists["dns-forwarders"]; !slices.Equal(got, []string{"192.0.2.53"}) {
		t.Errorf("dns-forwarders %v", got)
	}
	if r.Entry("dns-soa-template", []string{"own"}) == nil || r.Entry("dns-soa-template", []string{"fw"}) == nil {
		t.Errorf("SOA templates %v", r.Lists["dns-soa-template"])
	}
	if ins := r.Lists["instance"]; len(ins) != 1 || ins[0].Leaf("name") != "blue" {
		t.Errorf("instances %v", ins)
	}
	if errs := tr.Validate(); len(errs) > 0 {
		t.Errorf("not valid: %v", errs)
	}
	// The link's end names the host by host-name.
	l := r.Entry("link", []string{"l1"})
	if tg := tr.Referenced(l, l.S.Child("instance-a"), "main"); tg != r {
		t.Errorf("link end: %v", tg)
	}
	// Written and read again: this release's shape, left alone.
	data, err := tr.JSON(JSONOptions{Secrets: true})
	if err != nil {
		t.Fatal(err)
	}
	again := New(schema.MustLoad())
	if err := again.UnmarshalJSON(data); err != nil {
		t.Fatal(err)
	}
	if again.Migrated || again.Root.Leaf("host-name") != "main" {
		t.Errorf("read again: migrated %v, %v", again.Migrated, again.Root.Leaves)
	}

	// Two hosts are refused.
	two := `{"portitor:instance": [{"name": "a", "is-default": true}, {"name": "b", "is-default": true}]}`
	if err := New(schema.MustLoad()).UnmarshalJSON([]byte(two)); err == nil {
		t.Error("two hosts accepted")
	}
}

func TestMigrateIDPaths(t *testing.T) {
	paths := []string{"/instance[name=main]", "/instance[name=main]/interface[name=lan]", "/instance[name=blue]", "/host[name=web]", "/instance[name=mainx]"}
	got := map[string]string{}
	if !MigrateIDPaths(paths, "main", func(from, to string) { got[from] = to }) {
		t.Fatal("nothing moved")
	}
	want := map[string]string{"/instance[name=main]": "/", "/instance[name=main]/interface[name=lan]": "/interface[name=lan]"}
	if len(got) != len(want) || got["/instance[name=main]"] != "/" || got["/instance[name=main]/interface[name=lan]"] != "/interface[name=lan]" {
		t.Errorf("moved %v", got)
	}
}
