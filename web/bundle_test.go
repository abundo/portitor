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

// richInstance makes a virtual firewall with rows at every depth: VRF,
// interfaces, a WireGuard peer, a DNS zone with a record, BGP, a route in
// the VRF, a rule using a host and a custom service, DHCP.
func richInstance(t *testing.T, env *testEnv, name string) uint {
	t.Helper()
	env.do("PUT", "/api/settings", map[string]any{"virtual_firewalls": true})
	if err := env.srv.ensureDefaultInstance(); err != nil {
		t.Fatal(err)
	}
	inst := env.create("/api/instances", map[string]any{"name": name, "dns_upstream": "root", "dhcp_enabled": true, "dhcp_domain_name": "shop.example"})
	env.create("/api/vrfs", map[string]any{"instance_id": inst, "name": "blue", "route_table": 10})
	env.create("/api/interfaces", map[string]any{"instance_id": inst, "name": "eth1", "kind": "physical", "addresses": []string{"192.168.5.1/24"}, "enabled": true, "dns_listen": true})
	env.create("/api/interfaces", map[string]any{"instance_id": inst, "name": "eth2", "kind": "physical", "addresses": []string{"10.2.0.1/24"}, "enabled": true, "vrf": "blue"})
	wg := env.create("/api/interfaces", map[string]any{"instance_id": inst, "name": "wg0", "kind": "wireguard", "enabled": true, "ipv4_mode": "static", "addresses": []string{"10.9.0.1/24"}, "wg_listen_port": 51820})
	env.create("/api/wg/peers", map[string]any{"interface_id": wg, "name": "phone", "allowed_ips": []string{"10.9.0.2/32"}, "enabled": true})
	// OpenVPN, by its certificate (a cycle with the certificates'
	// interfaces), with no user in its role: the users differ between
	// installations.
	cert := env.create("/api/certificates", map[string]any{"instance_id": inst, "name": "vpn", "enabled": true, "source": "import",
		"generate": map[string]any{"domains": []string{"vpn.shop.example"}, "key_type": "ec256", "days": 30}})
	vpnRole := env.create("/api/roles", map[string]any{"name": "vpn-" + name})
	env.create("/api/interfaces", map[string]any{"instance_id": inst, "name": "ovpn0", "kind": "openvpn", "enabled": true,
		"addresses": []string{"10.8.0.1/24"}, "ovpn_tcp_addresses": []string{"10.7.0.1/24"}, "ovpn_listen": "eth1", "ovpn_certificate_id": cert, "ovpn_role_id": vpnRole})
	zone := env.create("/api/dns/zones", map[string]any{"instance_id": inst, "name": "shop.example"})
	env.create("/api/dns/records", map[string]any{"zone_id": zone, "name": "nas", "type": "A", "value": "192.168.5.10"})
	env.create("/api/ipam/prefixes", map[string]any{"instance_id": inst, "prefix": "192.168.5.0/24", "dhcp_enabled": true, "dhcp_range_start": "192.168.5.100", "dhcp_range_end": "192.168.5.199"})
	env.create("/api/routes", map[string]any{"instance_id": inst, "destination": "10.50.0.0/16", "gateway": "10.2.0.254", "vrf_id": nil, "enabled": true})
	env.create("/api/bgp/config", map[string]any{"instance_id": inst, "enabled": true, "asn": 65010})
	env.create("/api/bgp/neighbors", map[string]any{"instance_id": inst, "address": "192.168.5.2", "enabled": true, "remote_as": "65011"})
	env.create("/api/objects", map[string]any{"name": "nas", "addresses": []string{"192.168.5.10"}})
	env.create("/api/custom-services", map[string]any{"name": "unifi", "type": "tcp/udp/sctp", "ports": []any{map[string]any{"protocol": "tcp", "dst_lo": 8443, "dst_hi": 0}}})
	env.create("/api/rules", map[string]any{"instance_id": inst, "chain": "forward", "action": "accept", "enabled": true,
		"dst_addrs": []string{"nas"}, "services": []string{"unifi"}})
	return inst
}

// docOf builds one instance as the agent would get it, rule ids aside
// (they are row ids).
func docOf(t *testing.T, env *testEnv, name string) string {
	t.Helper()
	doc, err := builder.BuildInstances(env.srv.db, 0, map[string]bool{name: true})
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
	id := richInstance(t, src, "shop")
	rec := src.do("GET", "/api/instances/"+itoa(id)+"/bundle", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("export: %d %s", rec.Code, rec.Body)
	}
	var b Bundle
	if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	if len(b.Tables["wg_peers"]) != 1 || len(b.Tables["dns_records"]) != 1 || len(b.Tables["roles"]) != 0 {
		t.Errorf("bundle tables: %d peers, %d records, %d roles", len(b.Tables["wg_peers"]), len(b.Tables["dns_records"]), len(b.Tables["roles"]))
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
	var role models.Role
	if err := dst.srv.db.Where("name = ?", "vf-shop2").First(&role).Error; err != nil {
		t.Errorf("no role for the imported instance: %v", err)
	}

	// Again into the source: the shared objects are reused.
	if rec := src.do("POST", "/api/instances/import", map[string]any{"name": "shop3", "bundle": b}); rec.Code != http.StatusCreated {
		t.Fatalf("import beside the source: %d %s", rec.Code, rec.Body)
	}
	var n int64
	src.srv.db.Model(&models.AddressObject{}).Where("name = ?", "nas").Count(&n)
	if n != 1 {
		t.Errorf("%d hosts named nas", n)
	}
	// A host that differs here is a conflict, and nothing is imported.
	var nas models.AddressObject
	dst.srv.db.Where("name = ?", "nas").First(&nas)
	dst.do("PUT", "/api/objects/"+itoa(nas.ID), map[string]any{"addresses": []string{"192.168.5.11"}})
	rec = dst.do("POST", "/api/instances/import", map[string]any{"name": "shop4", "bundle": b})
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "nas") {
		t.Errorf("conflicting host: %d %s", rec.Code, rec.Body)
	}
	dst.srv.db.Model(&models.Instance{}).Where("name = ?", "shop4").Count(&n)
	if n != 0 {
		t.Error("a refused import left its instance")
	}
	// Another schema version is refused.
	b.Schema--
	if rec := dst.do("POST", "/api/instances/import", map[string]any{"name": "shop5", "bundle": b}); rec.Code != http.StatusBadRequest {
		t.Errorf("other schema: %d %s", rec.Code, rec.Body)
	}
}

// A link comes with whichever of its two instances arrives last.
func TestBundleLinks(t *testing.T) {
	src := newEnv(t)
	if err := src.srv.ensureDefaultInstance(); err != nil {
		t.Fatal(err)
	}
	a := src.create("/api/instances", map[string]any{"name": "left"})
	b := src.create("/api/instances", map[string]any{"name": "right"})
	src.create("/api/links", map[string]any{"name": "lr", "instance_a_id": a, "interface_a": "to-right", "addresses_a": []string{"10.7.0.1/30"},
		"instance_b_id": b, "interface_b": "to-left", "addresses_b": []string{"10.7.0.2/30"}})
	dst := newEnv(t)
	if err := dst.srv.ensureDefaultInstance(); err != nil {
		t.Fatal(err)
	}
	links := func() []models.Link {
		var ls []models.Link
		dst.srv.db.Find(&ls)
		return ls
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
	var in models.Instance
	if err := env.srv.db.Where("name = ?", name).First(&in).Error; err != nil {
		t.Fatal(err)
	}
	rec := env.do("GET", "/api/instances/"+itoa(in.ID)+"/bundle", nil)
	var b Bundle
	if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	return b
}
