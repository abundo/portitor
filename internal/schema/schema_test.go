// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package schema

import (
	"slices"
	"testing"
)

func TestLoad(t *testing.T) {
	root, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	in := root.Child("instance")
	if in == nil || in.Kind != List || !slices.Equal(in.Keys, []string{"name"}) {
		t.Fatalf("instance: %+v", in)
	}
	if in.Children[0].Name != "name" {
		t.Errorf("first child of instance is %s, want its key", in.Children[0].Name)
	}
	rule := in.Child("rule")
	if rule == nil || !rule.OrderedByUser || rule.Ext["table"] != "rules" || rule.Ext["position"] != "position" {
		t.Fatalf("rule: %+v", rule)
	}
	src := rule.Child("src-addrs")
	if src.Kind != LeafList || src.Type.Kind != "union" || len(src.Type.Leafrefs()) != 2 {
		t.Errorf("src-addrs: %+v", src.Type)
	}
	if !in.Child("interface").Child("wg-private-key").Secret() {
		t.Error("wg-private-key is not secret")
	}
	if d := in.Child("interface").Child("enabled"); !d.HasDefault || d.Default != "true" {
		t.Errorf("interface enabled default %q", d.Default)
	}
	if root.Find("instance/interface/mtu") == nil {
		t.Error("Find")
	}
	// Leaves follow the modules' order: kind before mtu.
	iface := in.Child("interface")
	idx := func(n string) int { return slices.IndexFunc(iface.Children, func(c *Node) bool { return c.Name == n }) }
	if idx("kind") > idx("mtu") {
		t.Error("children out of order")
	}
}

func TestCheck(t *testing.T) {
	root := MustLoad()
	mtu := root.Find("instance/interface/mtu").Type
	if v, err := mtu.Check("01500"); err != nil || v != "1500" {
		t.Errorf("mtu 01500: %q %v", v, err)
	}
	if _, err := mtu.Check("x"); err == nil {
		t.Error("mtu x accepted")
	}
	kind := root.Find("instance/interface/kind").Type
	if _, err := kind.Check("vlan"); err != nil {
		t.Error(err)
	}
	if _, err := kind.Check("token-ring"); err == nil {
		t.Error("kind token-ring accepted")
	}
	if _, err := root.Find("instance/interface/enabled").Type.Check("yes"); err == nil {
		t.Error("boolean yes accepted")
	}
}
