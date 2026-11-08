// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package schema

import (
	"slices"
	"strings"
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

func TestFormats(t *testing.T) {
	root := MustLoad()
	for _, c := range []struct{ path, in, want string }{
		{"/instance/static-neighbour/address", " fd00:0::5 ", "fd00::5"},
		{"/instance/static-neighbour/mac", "02-00-5E-00-01-01", "02:00:5e:00:01:01"},
		{"/instance/static-neighbour/mac", "0200.5e00.0101", "02:00:5e:00:01:01"},
		{"/instance/ipam-prefix/prefix", "192.168.1.7/24", "192.168.1.0/24"},
		{"/instance/route/destination", "default", "default"},
		{"/instance/route/destination", "10.1.2.3/8", "10.0.0.0/8"},
		{"/instance/route/destination", "lan-hosts", "lan-hosts"}, // a host's name
		{"/instance/rule/src-addrs", "@blocklist", "@blocklist"},
		{"/instance/rule/src-addrs", "2001:db8::1", "2001:db8::1"},
		{"/instance/interface/addresses", "<wan0>:2000::1/64", "<wan0>:2000::1/64"},
		{"/instance/interface/addresses", "10.0.0.1/24", "10.0.0.1/24"},
		{"/instance/dhcp-domain-name", "Home.Arpa.", "home.arpa"},
	} {
		n := root.Find(c.path)
		if n == nil {
			t.Fatalf("no %s", c.path)
		}
		got, err := n.Type.Check(c.in)
		if err != nil || got != c.want {
			t.Errorf("%s %q: %q %v, want %q", c.path, c.in, got, err, c.want)
		}
	}
	for _, c := range []struct{ path, in string }{
		{"/instance/static-neighbour/mac", "02:00:00:00:00"},
		{"/instance/static-neighbour/address", "10.0.0.300"},
		{"/instance/interface/addresses", "10.0.0.0/24"}, // the network address
		{"/instance/interface/name", "a name with spaces"},
		{"/instance/interface/label", strings.Repeat("x", 33)},
		{"/instance/description", "two\nlines"},
		{"/instance/interface/wg-public-key", "not a key"},
	} {
		if v, err := root.Find(c.path).Type.Check(c.in); err == nil {
			t.Errorf("%s %q accepted as %q", c.path, c.in, v)
		}
	}
}
