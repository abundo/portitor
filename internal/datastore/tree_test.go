// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package datastore

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"github.com/abundo/portitor/internal/schema"
)

func p(words ...any) Path {
	var out Path
	for _, w := range words {
		switch x := w.(type) {
		case string:
			out = append(out, Elem{Name: x})
		case []string:
			out[len(out)-1].Keys = x
		}
	}
	return out
}

func k(keys ...string) []string { return keys }

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func sample(t *testing.T) *Tree {
	t.Helper()
	tr := New(schema.MustLoad())
	host := p("instance", k("host"))
	must(t, tr.Set(append(host, Elem{Name: "is-default"}), "true"))
	must(t, tr.Set(append(host, p("interface", k("wan0"), "kind")...), "physical"))
	must(t, tr.SetList(append(host, p("interface", k("wan0"), "addresses")...), []string{"192.0.2.10/24"}))
	must(t, tr.Set(append(host, p("interface", k("lan0"), "mtu")...), "1500"))
	must(t, tr.SetList(append(host, p("rule", k("7"), "in-interfaces")...), []string{"wan0", "lan0"}))
	must(t, tr.Set(append(host, p("rule", k("7"), "chain")...), "input"))
	must(t, tr.Set(append(host, p("route", k("1"), "destination")...), "default"))
	must(t, tr.Set(append(host, p("route", k("1"), "interface")...), "wan0"))
	return tr
}

func TestSetFindDelete(t *testing.T) {
	tr := sample(t)
	n, leaf, err := tr.Find(p("instance", k("host"), "interface", k("lan0"), "mtu"))
	if err != nil || n == nil || leaf == nil || n.Leaves["mtu"] != "1500" {
		t.Fatalf("find mtu: %v %v %v", n, leaf, err)
	}
	if err := tr.Set(p("instance", k("host"), "interface", k("lan0"), "mtu"), "big"); err == nil {
		t.Error("mtu big accepted")
	}
	if err := tr.Set(p("instance", k("host"), "interface", k("lan0"), "name"), "x"); err == nil {
		t.Error("a key was set")
	}
	must(t, tr.Delete(p("instance", k("host"), "interface", k("lan0"), "mtu")))
	if n.Leaf("mtu") != "" || n.Leaf("enabled") != "true" {
		t.Errorf("after delete: mtu %q, enabled default %q", n.Leaf("mtu"), n.Leaf("enabled"))
	}
	if err := tr.Delete(p("instance", k("host"), "interface", k("lan0"), "mtu")); err == nil {
		t.Error("deleting what isn't set")
	}
	must(t, tr.Delete(p("instance", k("host"), "rule", k("7"), "in-interfaces"), "lan0"))
	r := tr.Root.Entry("instance", k("host")).Entry("rule", k("7"))
	if !slices.Equal(r.LeafLists["in-interfaces"], []string{"wan0"}) {
		t.Errorf("in-interfaces %v", r.LeafLists["in-interfaces"])
	}
}

func TestRenameFollowsReferences(t *testing.T) {
	tr := sample(t)
	must(t, tr.Rename(p("instance", k("host"), "interface", k("wan0")), k("uplink")))
	host := tr.Root.Entry("instance", k("host"))
	if host.Entry("interface", k("uplink")) == nil {
		t.Fatal("no uplink")
	}
	if got := host.Entry("rule", k("7")).LeafLists["in-interfaces"]; !slices.Equal(got, []string{"uplink", "lan0"}) {
		t.Errorf("rule in-interfaces %v", got)
	}
	if got := host.Entry("route", k("1")).Leaves["interface"]; got != "uplink" {
		t.Errorf("route interface %q", got)
	}
	if err := tr.Rename(p("instance", k("host"), "interface", k("lan0")), k("uplink")); err == nil {
		t.Error("renamed onto an existing entry")
	}
}

func TestValidate(t *testing.T) {
	tr := sample(t)
	if errs := tr.Validate(); len(errs) != 0 {
		t.Fatalf("valid tree: %v", errs)
	}
	// A route to an interface that isn't there: the leafref has no
	// fallback type.
	must(t, tr.Set(p("instance", k("host"), "route", k("1"), "interface"), "nope"))
	errs := tr.Validate()
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), `"nope" doesn't name a interface`) {
		t.Errorf("errors: %v", errs)
	}
	// A rule with the destination missing: chain is mandatory.
	must(t, tr.Set(p("instance", k("host"), "rule", k("8"), "log"), "true"))
	if errs := tr.Validate(); len(errs) != 2 {
		t.Errorf("errors: %v", errs)
	}
	host := tr.Root.Entry("instance", k("host"))
	if u := tr.Using(host.Entry("interface", k("wan0"))); !slices.Contains(u, "instance host rule 7 in-interfaces") {
		t.Errorf("using wan0: %v", u)
	}
}

func TestJSONRoundTrip(t *testing.T) {
	tr := sample(t)
	must(t, tr.Set(p("instance", k("host"), "interface", k("wan0"), "wg-private-key"), "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="))
	data, err := tr.JSON(JSONOptions{Secrets: true})
	must(t, err)
	if !bytes.Contains(data, []byte(`"portitor:instance"`)) || !bytes.Contains(data, []byte(`"mtu":1500`)) || !bytes.Contains(data, []byte(`"id":7`)) {
		t.Errorf("json: %s", data)
	}
	back := New(schema.MustLoad())
	must(t, back.UnmarshalJSON(data))
	if d := Diff(tr, back); len(d) != 0 {
		t.Errorf("round trip changed: %+v", d)
	}
	public, err := tr.JSON(JSONOptions{})
	must(t, err)
	if bytes.Contains(public, []byte("MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")) {
		t.Error("secret in public JSON")
	}
	// SecretsSet says it is set, and an edit with that annotation keeps it.
	marked, err := NodeJSON(tr.Root.Entry("instance", k("host")).Entry("interface", k("wan0")), JSONOptions{SecretsSet: true})
	must(t, err)
	if !bytes.Contains(marked, []byte(`"@wg-private-key":{"portitor:set":true}`)) || bytes.Contains(marked, []byte("MDEy")) {
		t.Errorf("marked: %s", marked)
	}
	wan := p("instance", k("host"), "interface", k("wan0"))
	must(t, tr.EditJSON(wan, EditReplace, marked))
	if tr.Root.Entry("instance", k("host")).Entry("interface", k("wan0")).Leaves["wg-private-key"] == "" {
		t.Error("a replace with the annotation lost the secret")
	}
}

func TestDiffApply(t *testing.T) {
	a := sample(t)
	b := a.Clone()
	host := p("instance", k("host"))
	must(t, b.Set(append(host, p("interface", k("lan0"), "mtu")...), "9000"))
	must(t, b.Delete(append(host, p("route", k("1"))...)))
	must(t, b.Set(append(host, p("rule", k("3"), "chain")...), "forward"))
	must(t, b.Move(append(host, p("rule", k("3"))...), "first", nil))
	must(t, b.Set(append(host, p("vrf", k("blue"), "route-table")...), "10"))
	changes := Diff(a, b)
	c := a.Clone()
	must(t, c.Apply(changes))
	if d := Diff(c, b); len(d) != 0 {
		t.Errorf("apply left differences: %+v", d)
	}
	var out bytes.Buffer
	DiffText(&out, a, b, nil)
	for _, want := range []string{"-             mtu 1500", "+             mtu 9000", "-         route 1 {", "+         vrf blue {"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("diff text lacks %q:\n%s", want, out.String())
		}
	}
}

func TestRebaseKeepsBoth(t *testing.T) {
	base := sample(t)
	cand := base.Clone()
	host := p("instance", k("host"))
	must(t, cand.Set(append(host, p("interface", k("lan0"), "mtu")...), "9000"))
	upstream := base.Clone()
	must(t, upstream.Set(append(host, p("interface", k("wan0"), "mtu")...), "1492"))
	must(t, upstream.Delete(append(host, p("route", k("1"))...)))
	must(t, upstream.Apply(Diff(base, cand)))
	h := upstream.Root.Entry("instance", k("host"))
	if h.Entry("interface", k("lan0")).Leaves["mtu"] != "9000" || h.Entry("interface", k("wan0")).Leaves["mtu"] != "1492" || h.Entry("route", k("1")) != nil {
		t.Error("rebase lost a change")
	}
}

func TestTextAndFlat(t *testing.T) {
	tr := sample(t)
	var b bytes.Buffer
	Text(&b, tr.Root, TextOptions{})
	want := "instance host {\n    is-default true\n    interface lan0 {\n        mtu 1500\n    }\n"
	if !strings.HasPrefix(b.String(), want) {
		t.Errorf("text:\n%s", b.String())
	}
	b.Reset()
	Flat(&b, tr.Root)
	if !strings.Contains(b.String(), "set / instance host interface wan0 addresses [ 192.0.2.10/24 ]\n") {
		t.Errorf("flat:\n%s", b.String())
	}
}
