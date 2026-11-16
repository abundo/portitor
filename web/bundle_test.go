// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/abundo/portitor/internal/builder"
	"github.com/abundo/portitor/internal/confview"
	"github.com/abundo/portitor/models"
)

// richInstance makes a virtual firewall with rows at every depth: VRF,
// interfaces, a WireGuard peer, a DNS zone with a record, BGP, a route in
// the VRF, a rule using a host and a custom service, DHCP.
func richInstance(t *testing.T, env *testEnv, name string) uint {
	t.Helper()
	env.do("PUT", "/api/settings", map[string]any{"virtual_firewalls": true})
	if err := env.srv.ensureDefaultInstance(); err != nil {
		t.Fatal(err)
	}
	env.vf(name)
	in := "instance=" + name
	env.patch(in, map[string]any{"dns-upstream": "root", "dhcp-enabled": true, "dhcp-domain-name": "shop.example"})
	env.put(in+"/vrf=blue", map[string]any{"route-table": 10})
	env.put(in+"/interface=eth1", map[string]any{"kind": "physical", "addresses": []string{"192.168.5.1/24"}, "enabled": true, "dns-listen": true})
	env.put(in+"/interface=eth2", map[string]any{"kind": "physical", "addresses": []string{"10.2.0.1/24"}, "enabled": true, "vrf": "blue"})
	env.put(in+"/interface=wg0", map[string]any{"kind": "wireguard", "enabled": true, "ipv4-mode": "static", "addresses": []string{"10.9.0.1/24"}, "wg-listen-port": 51820})
	env.put(in+"/interface=wg0/wireguard-peer=phone", map[string]any{"allowed-ips": []string{"10.9.0.2/32"}, "enabled": true})
	// OpenVPN, by its certificate (a cycle with the certificates'
	// interfaces), with no user in its role: the users differ between
	// installations.
	env.mustCfg("POST", in+"/certificate=vpn?action=generate", map[string]any{"domains": []string{"vpn.shop.example"}, "key-type": "ec256", "days": 30})
	env.create("/api/roles", map[string]any{"name": "vpn-" + name})
	env.put(in+"/interface=ovpn0", map[string]any{"kind": "openvpn", "enabled": true,
		"addresses": []string{"10.8.0.1/24"}, "ovpn-tcp-addresses": []string{"10.7.0.1/24"}, "ovpn-listen": "eth1", "ovpn-certificate": "vpn", "ovpn-role": "vpn-" + name})
	env.put(in+"/dns-zone=shop.example", map[string]any{})
	env.post(in+"/dns-zone=shop.example/record", map[string]any{"name": "nas", "type": "A", "value": "192.168.5.10"})
	env.post(in+"/ipam-prefix", map[string]any{"prefix": "192.168.5.0/24", "dhcp-enabled": true, "dhcp-range-start": "192.168.5.100", "dhcp-range-end": "192.168.5.199"})
	env.post(in+"/route", map[string]any{"destination": "10.50.0.0/16", "gateway": "10.2.0.254", "enabled": true})
	env.put(in+"/bgp=main", map[string]any{"enabled": true, "asn": 65010})
	env.post(in+"/bgp-neighbor", map[string]any{"address": "192.168.5.2", "vrf": "main", "enabled": true, "remote-as": "65011"})
	env.post("host", map[string]any{"name": "nas", "addresses": []string{"192.168.5.10"}})
	env.post("service", map[string]any{"name": "unifi", "type": "tcp/udp/sctp", "port": []any{map[string]any{"protocol": "tcp", "dst-lo": 8443, "dst-hi": 0, "src-lo": 0, "src-hi": 0}}})
	env.post(in+"/rule", map[string]any{"chain": "forward", "action": "accept", "enabled": true, "dst-addrs": []string{"nas"}, "services": []string{"unifi"}})
	return env.rowID("instances", name)
}

// docOf builds one instance as the agent would get it, rule ids aside
// (they are row ids).
func docOf(t *testing.T, env *testEnv, name string) string {
	t.Helper()
	doc, err := builder.BuildInstances(env.input(), 0, map[string]bool{name: true})
	if err != nil {
		t.Fatalf("build %s: %v", name, err)
	}
	in := doc.Instance(name)
	if in == nil {
		t.Fatalf("no instance %s", name)
	}
	in.Name = "x"
	for i := range in.Rules {
		in.Rules[i].ID = 0
	}
	b, _ := json.Marshal(in)
	return string(b)
}

func TestBundleRoundTrip(t *testing.T) {
	src := newEnv(t)
	richInstance(t, src, "shop")
	rec := src.do("GET", "/api/config/candidate/instance=shop?action=bundle", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("export: %d %s", rec.Code, rec.Body)
	}
	var b Bundle
	if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"phone"`, `"nas"`, `"unifi"`} {
		if !strings.Contains(string(b.Config), want) {
			t.Errorf("bundle without %s: %s", want, b.Config)
		}
	}

	// Into another installation, under another name: the same
	// configuration, with its role.
	dst := newEnv(t)
	dst.do("PUT", "/api/settings", map[string]any{"virtual_firewalls": true})
	if err := dst.srv.ensureDefaultInstance(); err != nil {
		t.Fatal(err)
	}
	rec = dst.do("POST", "/api/instances/import", map[string]any{"name": "shop2", "bundle": b})
	if rec.Code != http.StatusCreated {
		t.Fatalf("import: %d %s", rec.Code, rec.Body)
	}
	if got, want := docOf(t, dst, "shop2"), docOf(t, src, "shop"); got != want {
		t.Errorf("imported configuration differs:\n got %s\nwant %s", got, want)
	}
	if roles, _ := dst.srv.rec.Roles(); !slices.ContainsFunc(roles, func(r models.Role) bool { return r.Name == "vf-shop2" }) {
		t.Errorf("no role for the imported instance: %+v", roles)
	}

	// Beside the source it is refused: both would have eth1 and eth2.
	if rec := src.do("POST", "/api/instances/import", map[string]any{"name": "shop3", "bundle": b}); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "already used by instance shop") {
		t.Errorf("import beside the source: %d %s", rec.Code, rec.Body)
	}
	// In its place: the shared objects are reused.
	src.mustCfg("DELETE", "instance=shop", nil)
	if rec := src.do("POST", "/api/instances/import", map[string]any{"name": "shop3", "bundle": b}); rec.Code != http.StatusCreated {
		t.Fatalf("import beside the source: %d %s", rec.Code, rec.Body)
	}
	var n int64
	n = int64(len(rows(src, func(v *confview.View) []models.AddressObject { return v.AddressObjects }, func(o *models.AddressObject) bool { return o.Name == "nas" })))
	if n != 1 {
		t.Errorf("%d hosts named nas", n)
	}
	// A host that differs here is a conflict, and nothing is imported.
	dst.patch("host=nas", map[string]any{"addresses": []string{"192.168.5.11"}})
	rec = dst.do("POST", "/api/instances/import", map[string]any{"name": "shop4", "bundle": b})
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "nas") {
		t.Errorf("conflicting host: %d %s", rec.Code, rec.Body)
	}
	n = int64(len(rows(dst, func(v *confview.View) []models.Instance { return v.Instances }, func(in *models.Instance) bool { return in.Name == "shop4" })))
	if n != 0 {
		t.Error("a refused import left its instance")
	}
	// Another format is refused.
	b.Format--
	if rec := dst.do("POST", "/api/instances/import", map[string]any{"name": "shop5", "bundle": b}); rec.Code != http.StatusBadRequest {
		t.Errorf("other format: %d %s", rec.Code, rec.Body)
	}
}

// A link comes with whichever of its two instances arrives last.
func TestBundleLinks(t *testing.T) {
	src := newEnv(t)
	if err := src.srv.ensureDefaultInstance(); err != nil {
		t.Fatal(err)
	}
	src.vf("left")
	src.vf("right")
	src.put("link=lr", map[string]any{"instance-a": "left", "interface-a": "to-right", "addresses-a": []string{"10.7.0.1/30"},
		"instance-b": "right", "interface-b": "to-left", "addresses-b": []string{"10.7.0.2/30"}})
	dst := newEnv(t)
	if err := dst.srv.ensureDefaultInstance(); err != nil {
		t.Fatal(err)
	}
	links := func() []models.Link {
		return dst.view().Links
	}
	if rec := dst.do("POST", "/api/instances/import", map[string]any{"name": "right", "bundle": bundleOf(t, src, "right")}); rec.Code != http.StatusCreated {
		t.Fatalf("import right: %d %s", rec.Code, rec.Body)
	}
	if len(links()) != 0 {
		t.Fatal("a link to an instance that is not there")
	}
	if rec := dst.do("POST", "/api/instances/import", map[string]any{"name": "left", "bundle": bundleOf(t, src, "left")}); rec.Code != http.StatusCreated {
		t.Fatalf("import left: %d %s", rec.Code, rec.Body)
	}
	ls := links()
	if len(ls) != 1 || ls[0].InterfaceA != "to-right" || ls[0].InstanceAID != instanceID(t, dst, "left") || ls[0].InstanceBID != instanceID(t, dst, "right") {
		t.Errorf("links: %+v", ls)
	}
	if got, want := docOf(t, dst, "left"), docOf(t, src, "left"); got != want {
		t.Errorf("left differs:\n got %s\nwant %s", got, want)
	}
}

func bundleOf(t *testing.T, env *testEnv, name string) Bundle {
	t.Helper()
	rec := env.do("GET", "/api/config/candidate/instance="+name+"?action=bundle", nil)
	var b Bundle
	if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	return b
}

// The host's bundle (the top level's configuration, as an instance entry):
// into an installation without a host it becomes the host, into one with
// one a virtual firewall; the same configuration either way.
func TestBundleOfTheHost(t *testing.T) {
	src := newEnv(t)
	if err := src.srv.ensureDefaultInstance(); err != nil {
		t.Fatal(err)
	}
	src.put("interface=eth4", map[string]any{"kind": "physical", "enabled": true, "ipv4-mode": "static", "addresses": []string{"10.4.0.1/24"}})
	src.post("rule", map[string]any{"chain": "input", "action": "accept", "enabled": true, "in-interfaces": []string{"eth4"}})
	rec := src.do("GET", "/api/config/candidate/?action=bundle", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("export: %d %s", rec.Code, rec.Body)
	}
	var b Bundle
	if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b.Config), `"eth4"`) || strings.Contains(string(b.Config), "host-name") {
		t.Errorf("the host's bundle: %s", b.Config)
	}
	want := docOf(t, src, "main")

	// No host yet: it becomes the host.
	dst := newEnv(t)
	if err := dst.srv.ensureFirewall(); err != nil {
		t.Fatal(err)
	}
	if rec := dst.do("POST", "/api/instances/import", map[string]any{"name": "fw", "bundle": b}); rec.Code != http.StatusCreated {
		t.Fatalf("import as the host: %d %s", rec.Code, rec.Body)
	}
	tr, _ := dst.srv.tree()
	cand, _ := tr.store.Candidate(t.Context())
	if hostName(cand) != "fw" || cand.Root.Entry("interface", []string{"eth4"}) == nil {
		t.Errorf("the imported host: %v", cand.Root.Leaves)
	}
	if got := docOf(t, dst, "fw"); got != want {
		t.Errorf("the imported host differs:\n got %s\nwant %s", got, want)
	}

	// With a host: a virtual firewall.
	vf := newEnv(t)
	vf.do("PUT", "/api/settings", map[string]any{"virtual_firewalls": true})
	if err := vf.srv.ensureDefaultInstance(); err != nil {
		t.Fatal(err)
	}
	if rec := vf.do("POST", "/api/instances/import", map[string]any{"name": "copy", "bundle": b}); rec.Code != http.StatusCreated {
		t.Fatalf("import as a virtual firewall: %d %s", rec.Code, rec.Body)
	}
	if vf.node("instance=copy/interface=eth4") == nil {
		t.Error("the virtual firewall lacks the host's interface")
	}
}

// A bundle 1.0.0 made of its host (the instance with is-default), with the
// DNS templates bootstrap makes (soa-1, dns-1), imported as a virtual
// firewall where the firewall has templates of those names: its own shadow
// them, and its zone is served with them.
func TestA100HostBundleWithTemplates(t *testing.T) {
	cfg := `{"portitor:instance": [{"name": "main", "is-default": true, "firewall": "firewall",
		"interface": [{"name": "eth4", "kind": "physical", "enabled": true, "addresses": ["10.4.0.1/24"]}],
		"dns-soa-template": [{"name": "soa-1", "mname": "ns1.old.example", "rname": "h.old.example"}],
		"dns-template": [{"name": "dns-1", "soa-template": "soa-1", "nameserver": [{"name": "ns1.old.example", "address": ""}]}],
		"dns-zone": [{"name": "old.example", "dns-template": "dns-1"}]}]}`
	b := Bundle{Format: bundleFormat, Instance: "main", Config: json.RawMessage(cfg), Refs: []bundleRef{}, Left: []string{}}
	env := newEnv(t)
	env.do("PUT", "/api/settings", map[string]any{"virtual_firewalls": true})
	if err := env.srv.ensureDefaultInstance(); err != nil {
		t.Fatal(err)
	}
	soa := map[string]any{"mname": "ns1.home.arpa", "rname": "h.home.arpa"}
	env.put("dns-soa-template=soa-1", soa)
	env.put("dns-template=dns-1", map[string]any{"soa-template": "soa-1", "nameserver": []map[string]string{{"name": "ns1.home.arpa", "address": ""}}})
	if rec := env.do("POST", "/api/instances/import", map[string]any{"name": "old", "bundle": b}); rec.Code != http.StatusCreated {
		t.Fatalf("import: %d %s", rec.Code, rec.Body)
	}
	doc, err := builder.Build(env.input(), 1)
	if err != nil {
		t.Fatal(err)
	}
	dns := doc.Instance("old").DNS
	if zt := dns.ZoneTemplate("dns-1"); zt == nil || len(dns.SOATemplates) != 1 || dns.SOATemplates[0].MName != "ns1.old.example." && dns.SOATemplates[0].MName != "ns1.old.example" {
		t.Errorf("the imported VF's DNS: %+v %+v", dns.ZoneTemplates, dns.SOATemplates)
	}
}
