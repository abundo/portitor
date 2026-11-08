// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package confcheck

import (
	"strings"
	"testing"

	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/schema"
)

func tree(t *testing.T, js string) *datastore.Tree {
	t.Helper()
	tr := datastore.New(schema.MustLoad())
	if err := tr.UnmarshalJSON([]byte(js)); err != nil {
		t.Fatal(err)
	}
	return tr
}

const base = `{"portitor:instance": [
	{"name": "host", "is-default": true, "firewall": "fw",
	 "interface": [{"name": "wan0", "kind": "physical", "addresses": ["192.0.2.1/24"]},
	               {"name": "lan0", "kind": "physical", "addresses": ["10.0.0.1/24"]}]},
	{"name": "lab", "firewall": "fw", "interface": [{"name": "eth1", "kind": "physical"}]}
]}`

// edit applies fn to a copy of before, normalizes what changed and checks
// the result as a save does.
func edit(t *testing.T, before *datastore.Tree, fn func(*datastore.Tree) error) error {
	t.Helper()
	work := before.Clone()
	if err := fn(work); err != nil {
		t.Fatal(err)
	}
	changed := datastore.ChangedEntries(before, work)
	if err := Normalize(before, work, changed); err != nil {
		return err
	}
	if errs := CheckEntries(work, changed); len(errs) > 0 {
		return errs[0]
	}
	return nil
}

func path(s string) datastore.Path {
	var p datastore.Path
	for _, step := range strings.Split(s, "/") {
		name, key, ok := strings.Cut(step, "=")
		e := datastore.Elem{Name: name}
		if ok {
			e.Keys = strings.Split(key, ",")
		}
		p = append(p, e)
	}
	return p
}

func TestHooks(t *testing.T) {
	tr := tree(t, base)
	if errs := Check(tr); len(errs) > 0 {
		t.Fatalf("base: %v", errs)
	}
	for what, c := range map[string]struct {
		body string
		at   string
		want string // "" accepted
	}{
		"route without gateway":  {`{"id": 1, "destination": "default"}`, "instance=host/route", "gateway or an interface"},
		"route with gateway":     {`{"id": 2, "destination": "default", "gateway": "192.0.2.254"}`, "instance=host/route", ""},
		"BFD without gateway":    {`{"id": 3, "destination": "10.9.0.0/16", "interface": "lan0", "bfd": true}`, "instance=host/route", "needs one"},
		"SYN proxy on input":     {`{"id": 4, "chain": "input", "action": "accept", "syn-proxy": true, "services": ["ssh"]}`, "instance=host/rule", "only a forward rule"},
		"SYN proxy forward ssh":  {`{"id": 5, "chain": "forward", "action": "accept", "syn-proxy": true, "services": ["ssh"]}`, "instance=host/rule", ""},
		"unknown service":        {`{"id": 6, "chain": "input", "services": ["nosuch"]}`, "instance=host/rule", "no service"},
		"unknown interface":      {`{"id": 7, "chain": "input", "in-interfaces": ["eth9"]}`, "instance=host/rule", "not an interface"},
		"unknown IP list":        {`{"id": 8, "chain": "input", "src-addrs": ["@bad"]}`, "instance=host/rule", "no IP list"},
		"HA role in a VF":        {`{"name": "eth2", "kind": "physical", "ha-role": "ha_link"}`, "instance=lab/interface", "not of a virtual firewall"},
		"HA role on the host":    {`{"name": "eth2", "kind": "physical", "ha-role": "ha_link"}`, "instance=host/interface", ""},
		"address twice":          {`{"name": "lan1", "kind": "physical", "addresses": ["10.0.0.1/24"]}`, "instance=host/interface", "already on lan0"},
		"reservation, no name":   {`{"address": "10.0.0.9", "mac": "02:00:00:00:00:09"}`, "instance=host/ipam-address", "needs a DNS name"},
		"DHCP range outside":     {`{"prefix": "10.0.0.0/24", "dhcp-enabled": true, "dhcp-range-start": "10.0.1.1", "dhcp-range-end": "10.0.1.9"}`, "instance=host/ipam-prefix", "not inside"},
		"link in one VF":         {`{"name": "l1", "instance-a": "lab", "interface-a": "x0", "instance-b": "lab", "interface-b": "x1"}`, "link", "two different"},
		"NAT ports, no protocol": {`{"id": 9, "kind": "dnat", "to-addr": "10.0.0.5", "dst-ports": "80"}`, "instance=host/nat-rule", "need protocol"},
	} {
		err := edit(t, tr, func(w *datastore.Tree) error {
			return w.EditJSON(path(c.at), datastore.EditCreate, []byte(c.body))
		})
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s refused: %v", what, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s: %v, want %q", what, err, c.want)
		}
	}

	// A WireGuard interface gets its keys; its kind can't change after.
	work := tr.Clone()
	if err := work.EditJSON(path("instance=host/interface"), datastore.EditCreate, []byte(`{"name": "wg0", "kind": "wireguard", "addresses": ["10.99.0.1/24"]}`)); err != nil {
		t.Fatal(err)
	}
	if err := Normalize(tr, work, datastore.ChangedEntries(tr, work)); err != nil {
		t.Fatal(err)
	}
	wg := work.Root.Entry("instance", []string{"host"}).Entry("interface", []string{"wg0"})
	if wg.Leaves["wg-private-key"] == "" || wg.Leaves["wg-public-key"] == "" {
		t.Errorf("no keys: %v", wg.Leaves)
	}
	if err := edit(t, work, func(w *datastore.Tree) error {
		return w.Set(path("instance=host/interface=wg0/kind"), "physical")
	}); err == nil || !strings.Contains(err.Error(), "can't change") {
		t.Errorf("kind changed: %v", err)
	}

	// A new virtual firewall resolves from the root servers.
	work = tr.Clone()
	if err := work.EditJSON(path("instance"), datastore.EditCreate, []byte(`{"name": "shop", "firewall": "fw"}`)); err != nil {
		t.Fatal(err)
	}
	if err := Normalize(tr, work, datastore.ChangedEntries(tr, work)); err != nil {
		t.Fatal(err)
	}
	shop := work.Root.Entry("instance", []string{"shop"})
	if got := shop.Leaf("dns-upstream"); got != "root" {
		t.Errorf("dns-upstream %q", got)
	}
	if len(shop.Lists["rate-limit"]) != 3 || shop.Entry("rate-limit", []string{"dns server"}).Leaf("service") != "dns" {
		t.Errorf("rate limits: %v", shop.Lists["rate-limit"])
	}
	if rs := shop.Lists["rule"]; len(rs) != 1 || rs[0].Leaf("chain") != "output" || rs[0].Leaf("description") != "allow all output" {
		t.Errorf("rules: %v", rs)
	}
}

func TestObjectHooks(t *testing.T) {
	tr := tree(t, `{"portitor:host": [{"name": "nas", "addresses": ["10.0.0.5"]}],
		"portitor:address-list": [{"name": "a", "entries": ["b"]}, {"name": "b", "entries": ["nas"]}],
		"portitor:instance": [{"name": "host", "is-default": true, "firewall": "fw"}, {"name": "lab", "firewall": "fw"}]}`)
	if errs := Check(tr); len(errs) > 0 {
		t.Fatalf("base: %v", errs)
	}
	for what, c := range map[string]struct{ at, body, want string }{
		"a loop":               {"address-list=b", `{"entries": ["a"]}`, "contains itself"},
		"a host's name":        {"address-list=nas", `{"entries": ["10.0.0.1"]}`, "a host is named nas"},
		"a predefined name":    {"service=ssh", `{"type": "tcp/udp/sctp", "port": [{"protocol": "tcp", "dst-lo": 2222, "dst-hi": 0, "src-lo": 0, "src-hi": 0}]}`, "predefined"},
		"CrowdSec, no key":     {"ip-list=cs", `{"source": "crowdsec", "url": "https://lapi.example/"}`, "bouncer API key"},
		"a key over http":      {"ip-list=cs", `{"source": "crowdsec", "url": "http://lapi.example/", "api-key": "k"}`, "unencrypted"},
		"syslog in a VF":       {"instance=lab/syslog-server=7", `{"address": "192.0.2.1", "protocol": "udp"}`, "firewall's"},
		"a bad schedule":       {"task=t", `{"kind": "command", "schedule": "every day", "command": "true"}`, "schedule"},
		"shaping with a burst": {"instance=lab/rate-limit=s", `{"rate": 10, "shape": true, "burst": 5, "unit": "pps"}`, "unit"},
	} {
		err := edit(t, tr, func(w *datastore.Tree) error {
			return w.EditJSON(path(c.at), datastore.EditMerge, []byte(c.body))
		})
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", what, err, c.want)
		}
	}
}

func TestRoutingHooks(t *testing.T) {
	tr := tree(t, `{"portitor:instance": [{"name": "host", "is-default": true, "firewall": "fw",
		"vrf": [{"name": "blue", "route-table": 100}],
		"prefix-list": [{"name": "lan", "family": "ipv4", "entry": [{"seq": 10, "action": "permit", "prefix": "10.0.0.0/8"}]}],
		"route-map": [{"name": "out", "entry": [{"seq": 10, "action": "deny", "match-prefix-list": "lan", "set-metric": 5}]}],
		"bgp-peer-group": [{"name": "core", "remote-as": "65001", "vrf": "blue"}]}]}`)
	if err := Normalize(datastore.New(tr.Root.S), tr, datastore.ChangedEntries(datastore.New(tr.Root.S), tr)); err != nil {
		t.Fatal(err)
	}
	e := tr.Root.Entry("instance", []string{"host"}).Entry("route-map", []string{"out"}).Entry("entry", []string{"10"})
	if _, ok := e.Leaves["set-metric"]; ok {
		t.Error("a deny entry kept what it sets")
	}
	// A prefix list renamed: the route map follows.
	if err := tr.Rename(path("instance=host/prefix-list=lan"), []string{"inside"}); err != nil {
		t.Fatal(err)
	}
	if got := e.Leaf("match-prefix-list"); got != "inside" {
		t.Errorf("match-prefix-list %q after the rename", got)
	}
	err := edit(t, tr, func(w *datastore.Tree) error {
		return w.EditJSON(path("instance=host/bgp-neighbor"), datastore.EditCreate, []byte(`{"address": "192.0.2.9", "vrf": "main", "peer-group": "core"}`))
	})
	if err == nil || !strings.Contains(err.Error(), "VRF blue's, not the main table's") {
		t.Errorf("a neighbour in another VRF than its group: %v", err)
	}
}
