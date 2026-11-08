// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package datastore

import (
	"slices"
	"testing"
)

func TestEditJSON(t *testing.T) {
	tr := sample(t)
	host := p("instance", k("host"))
	wan := append(host, p("interface", k("wan0"))...)
	must(t, tr.Set(append(wan, Elem{Name: "wg-private-key"}), "secret"))

	// Merge: leaves set, a leaf-list replaced, null deletes.
	must(t, tr.EditJSON(wan, EditMerge, []byte(`{"mtu": 1400, "addresses": ["198.51.100.1/24"], "kind": null}`)))
	n, _, _ := tr.Find(wan)
	if n.Leaves["mtu"] != "1400" || !slices.Equal(n.LeafLists["addresses"], []string{"198.51.100.1/24"}) {
		t.Errorf("merge: %v %v", n.Leaves, n.LeafLists)
	}
	if _, ok := n.Leaves["kind"]; ok {
		t.Error("null left kind")
	}

	// Replace keeps the secret it can't read back, drops the rest.
	must(t, tr.EditJSON(wan, EditReplace, []byte(`{"name": "wan0", "description": "uplink"}`)))
	n, _, _ = tr.Find(wan)
	if n.Leaves["wg-private-key"] != "secret" || n.Leaves["description"] != "uplink" || n.Leaves["mtu"] != "" || len(n.LeafLists) != 0 {
		t.Errorf("replace: %v %v", n.Leaves, n.LeafLists)
	}

	// Create at a list's path; twice is refused.
	ifaces := append(host, Elem{Name: "interface"})
	must(t, tr.EditJSON(ifaces, EditCreate, []byte(`{"name": "lo1", "kind": "loopback"}`)))
	if err := tr.EditJSON(ifaces, EditCreate, []byte(`{"name": "lo1"}`)); err == nil {
		t.Error("created lo1 twice")
	}

	// Refused: a wrong type, an unknown member, a key changed, state, a
	// missing key.
	for what, c := range map[string]struct {
		p    Path
		body string
	}{
		"type":      {wan, `{"mtu": "big"}`},
		"unknown":   {wan, `{"colour": "red"}`},
		"key":       {wan, `{"name": "wan9"}`},
		"state":     {append(host, Elem{Name: "state"}), `{}`},
		"no key":    {ifaces, `{"kind": "loopback"}`},
		"bad JSON":  {wan, `{`},
		"not array": {ifaces, `{"name": "x"}`},
	} {
		op := EditMerge
		if what == "no key" {
			op = EditCreate
		}
		if err := tr.EditJSON(c.p, op, []byte(c.body)); err == nil {
			t.Errorf("%s accepted", what)
		}
	}

	// A whole list replaced, in the order given.
	rules := append(host, Elem{Name: "rule"})
	must(t, tr.EditJSON(rules, EditReplace, []byte(`[{"id": 9, "chain": "forward"}, {"id": 3, "chain": "input"}]`)))
	var ids []string
	for _, r := range tr.Root.Entry("instance", k("host")).Lists["rule"] {
		ids = append(ids, r.Leaves["id"])
	}
	if !slices.Equal(ids, []string{"9", "3"}) {
		t.Errorf("rules: %v", ids)
	}
}
