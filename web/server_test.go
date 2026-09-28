// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/labstack/echo/v5"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/abundo/portitor/internal/agent"
	"github.com/abundo/portitor/internal/builder"
	"github.com/abundo/portitor/internal/dbmigrate"
	"github.com/abundo/portitor/internal/render"
	"github.com/abundo/portitor/models"
)

type testEnv struct {
	t      *testing.T
	srv    *Server
	e      *echo.Echo
	cookie *http.Cookie
}

func newEnv(t *testing.T) *testEnv {
	t.Helper()
	db, err := dbmigrate.Open(filepath.Join(t.TempDir(), "db.sqlite"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	if err := dbmigrate.Up(db); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{JWTSecret: strings.Repeat("s", 32), Dev: true}
	srv := NewServer(cfg, db)
	srv.static = os.DirFS(t.TempDir())
	env := &testEnv{t: t, srv: srv, e: srv.Echo()}
	if err := CreateUser(srv, "admin", "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	rec := env.do("POST", "/api/login", map[string]string{"username": "admin", "password": "correct horse battery"})
	if rec.Code != http.StatusOK {
		t.Fatalf("login: %d %s", rec.Code, rec.Body)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == cookieName {
			env.cookie = c
		}
	}
	return env
}

func (env *testEnv) do(method, path string, body any) *httptest.ResponseRecorder {
	env.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	if env.cookie != nil {
		req.AddCookie(env.cookie)
	}
	rec := httptest.NewRecorder()
	env.e.ServeHTTP(rec, req)
	return rec
}

// create POSTs and returns the new id.
func (env *testEnv) create(path string, body any) uint {
	env.t.Helper()
	rec := env.do("POST", path, body)
	if rec.Code != http.StatusCreated {
		env.t.Fatalf("POST %s: %d %s", path, rec.Code, rec.Body)
	}
	var out struct {
		ID uint `json:"id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return out.ID
}

func TestAuthRequired(t *testing.T) {
	env := newEnv(t)
	cookie := env.cookie
	env.cookie = nil
	if rec := env.do("GET", "/api/instances", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated: %d", rec.Code)
	}
	if rec := env.do("POST", "/api/login", map[string]string{"username": "admin", "password": "wrong"}); rec.Code != http.StatusUnauthorized {
		t.Errorf("wrong password: %d", rec.Code)
	}
	env.cookie = cookie

	// CSRF: a form post is refused even with a valid cookie.
	req := httptest.NewRequest("POST", "/api/instances", strings.NewReader("name=x"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	env.e.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("form post: %d", rec.Code)
	}

	// A DELETE has no body, so the browser sends no Content-Type.
	id := env.create("/api/instances", map[string]any{"name": "gone"})
	req = httptest.NewRequest("DELETE", fmt.Sprintf("/api/instances/%d", id), nil)
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	env.e.ServeHTTP(rec, req)
	if rec.Code >= 300 {
		t.Errorf("delete without content type: %d %s", rec.Code, rec.Body)
	}
}

func TestPasswordChangeRevokesSessions(t *testing.T) {
	env := newEnv(t)
	old := env.cookie
	rec := env.do("POST", "/api/me/password", map[string]string{"current": "correct horse battery", "new": "another long password"})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	env.cookie = old
	if rec := env.do("GET", "/api/me", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("old session still valid: %d", rec.Code)
	}
}

func TestUpdateMe(t *testing.T) {
	env := newEnv(t)
	rec := env.do("PUT", "/api/me", map[string]string{"username": "root", "full_name": "Ada Admin", "email": "ada@example.org"})
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	var me models.User
	if err := json.Unmarshal(env.do("GET", "/api/me", nil).Body.Bytes(), &me); err != nil {
		t.Fatal(err)
	}
	if me.Username != "admin" || me.FullName != "Ada Admin" || me.Email != "ada@example.org" {
		t.Errorf("got %+v", me)
	}
	for _, body := range []map[string]string{
		{"email": "not an address"},
		{"full_name": "a\nb"},
	} {
		if rec := env.do("PUT", "/api/me", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%v: %d", body, rec.Code)
		}
	}
}

func TestValidationAndSecrets(t *testing.T) {
	env := newEnv(t)
	if rec := env.do("POST", "/api/instances", map[string]any{"name": "Bad Name"}); rec.Code != http.StatusBadRequest {
		t.Errorf("bad instance name: %d", rec.Code)
	}
	inst := env.create("/api/instances", map[string]any{"name": "main"})
	var got models.Instance
	env.srv.db.First(&got, inst)
	if !got.IsDefault {
		t.Error("first instance should become the default")
	}
	if rec := env.do("POST", "/api/instances", map[string]any{"name": "main"}); rec.Code != http.StatusConflict {
		t.Errorf("duplicate: %d", rec.Code)
	}
	other := env.create("/api/instances", map[string]any{"name": "guest"})
	env.create("/api/interfaces", map[string]any{"instance_id": other, "name": "eth2"})
	if rec := env.do("POST", "/api/interface-zones", map[string]any{"instance_id": inst, "name": "lan", "interfaces": []string{"eth2"}}); rec.Code != http.StatusBadRequest {
		t.Errorf("interface of another instance accepted in a zone: %d", rec.Code)
	}
	if rec := env.do("POST", "/api/rules", map[string]any{"instance_id": inst, "chain": "forward", "action": "accept", "in_interfaces": []string{"eth2"}}); rec.Code != http.StatusBadRequest {
		t.Errorf("interface of another instance accepted in a rule: %d", rec.Code)
	}

	// WireGuard: keys generated, private key never returned.
	wg := env.do("POST", "/api/interfaces", map[string]any{"instance_id": inst, "name": "wg0", "kind": "wireguard", "wg_listen_port": 51820})
	if wg.Code != http.StatusCreated || !strings.Contains(wg.Body.String(), "wg_public_key") {
		t.Fatalf("%d %s", wg.Code, wg.Body)
	}
	var ifc models.Interface
	env.srv.db.Where("name = ?", "wg0").First(&ifc)
	if ifc.WgPrivateKey == "" || strings.Contains(wg.Body.String(), ifc.WgPrivateKey) {
		t.Error("private key missing or leaked")
	}
	// PUT cannot overwrite the private key.
	env.do("PUT", "/api/interfaces/"+itoa(ifc.ID), map[string]any{"wg_private_key": "x", "description": "vpn"})
	var after models.Interface
	env.srv.db.First(&after, ifc.ID)
	if after.WgPrivateKey != ifc.WgPrivateKey || after.Description != "vpn" {
		t.Error("PUT merged wrongly")
	}
	peer := env.do("POST", "/api/wg/peers", map[string]any{"interface_id": ifc.ID, "name": "phone", "allowed_ips": []string{"10.99.0.2/32"}, "enabled": true})
	if peer.Code != http.StatusCreated || !strings.Contains(peer.Body.String(), `"has_client_key":true`) {
		t.Fatalf("peer: %d %s", peer.Code, peer.Body)
	}

	// Free peer addresses follow the interface's addresses, skipping IPAM
	// and existing peers.
	env.create("/api/ipam/prefixes", map[string]any{"instance_id": inst, "prefix": "10.99.0.0/24"})
	env.create("/api/ipam/prefixes", map[string]any{"instance_id": inst, "prefix": "fd99::/64"})
	env.create("/api/ipam/addresses", map[string]any{"instance_id": inst, "address": "10.99.0.1", "interface_id": ifc.ID})
	env.create("/api/ipam/addresses", map[string]any{"instance_id": inst, "address": "fd99::1", "interface_id": ifc.ID})
	env.create("/api/ipam/addresses", map[string]any{"instance_id": inst, "address": "10.99.0.3"})
	env.create("/api/ipam/addresses", map[string]any{"instance_id": inst, "address": "172.25.34.1", "interface_id": ifc.ID})
	free := env.do("GET", "/api/interfaces/"+itoa(ifc.ID)+"/wg-next-free", nil)
	if !strings.Contains(free.Body.String(), "172.25.34.1 on wg0 is not inside any IPAM prefix") {
		t.Errorf("no warning for an address outside IPAM prefixes: %s", free.Body)
	}
	if !strings.Contains(free.Body.String(), `"addresses":["10.99.0.4/32","fd99::4/128"]`) {
		t.Errorf("next free: %d %s", free.Code, free.Body)
	}
	// Client config uses the interface's endpoint and keepalive.
	if rec := env.do("PUT", "/api/interfaces/"+itoa(ifc.ID), map[string]any{"wg_endpoint": "vpn.example.org:4500", "wg_keepalive": 15}); rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	var p models.WgPeer
	env.srv.db.Where("name = ?", "phone").First(&p)
	conf := env.do("GET", "/api/wg/peers/"+itoa(p.ID)+"/config", nil).Body.String()
	if !strings.Contains(conf, "Endpoint = vpn.example.org:4500") || !strings.Contains(conf, "PersistentKeepalive = 15") {
		t.Errorf("client config: %s", conf)
	}
	if rec := env.do("PUT", "/api/interfaces/"+itoa(ifc.ID), map[string]any{"wg_endpoint": "no-port"}); rec.Code != http.StatusBadRequest {
		t.Errorf("endpoint without port accepted: %d", rec.Code)
	}
}

func itoa(n uint) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// TestDeployEndToEnd drives portitor-web against a real (dry-run)
// portitor-agent over TLS with certificate pinning.
func TestDeployEndToEnd(t *testing.T) {
	env := newEnv(t)

	dir := t.TempDir()
	token := strings.Repeat("t", 40)
	tokenFile := filepath.Join(dir, "token")
	_ = os.WriteFile(tokenFile, []byte(token), 0o600)
	cfgFile := filepath.Join(dir, "agent.yaml")
	_ = os.WriteFile(cfgFile, []byte("dry_run: true\ntoken_file: "+tokenFile+"\npaths:\n  etc_dir: "+dir+"/etc\n  state_dir: "+dir+"/state\n  run_dir: "+dir+"/run\n  kea_data_dir: "+dir+"/kea\n"), 0o600)
	acfg, err := agent.LoadConfig(cfgFile)
	if err != nil {
		t.Fatal(err)
	}
	ag := agent.New(acfg)
	defer ag.Stop()
	ts := httptest.NewTLSServer(ag.Handler())
	defer ts.Close()
	sum := sha256.Sum256(ts.Certificate().Raw)

	if rec := env.do("PUT", "/api/settings", map[string]any{
		"agent_url": ts.URL, "agent_token": token, "agent_fingerprint": hex.EncodeToString(sum[:]), "confirm_timeout": 120,
	}); rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), token) {
		t.Fatalf("settings: %d %s", rec.Code, rec.Body)
	}

	inst := env.create("/api/instances", map[string]any{"name": "main", "dns_enabled": true, "dhcp_enabled": true, "dhcp_domain_name": "home.arpa"})
	env.create("/api/interfaces", map[string]any{"instance_id": inst, "name": "eth0", "ipv4_mode": "dhcp", "enabled": true})
	eth1 := env.create("/api/interfaces", map[string]any{"instance_id": inst, "name": "eth1", "enabled": true, "dns_listen": true})
	env.create("/api/interface-zones", map[string]any{"instance_id": inst, "name": "lan", "interfaces": []string{"eth1"}})
	env.create("/api/ipam/prefixes", map[string]any{"instance_id": inst, "prefix": "192.168.1.0/24", "dhcp_enabled": true, "dhcp_range_start": "192.168.1.100", "dhcp_range_end": "192.168.1.200"})
	env.create("/api/ipam/addresses", map[string]any{"instance_id": inst, "address": "192.168.1.1", "interface_id": eth1})
	env.create("/api/rules", map[string]any{"instance_id": inst, "chain": "forward", "in_interfaces": []string{"lan"}, "out_interfaces": []string{"eth0"}, "action": "accept", "enabled": true})
	nat := env.create("/api/nat", map[string]any{"instance_id": inst, "kind": "masquerade", "out_interfaces": []string{"eth0"}, "enabled": true})

	// Problems block the deploy.
	bad := env.create("/api/ipam/addresses", map[string]any{"instance_id": inst, "address": "10.0.0.1", "interface_id": eth1})
	if rec := env.do("POST", "/api/deploy/apply", map[string]any{}); rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "not inside any IPAM prefix") {
		t.Fatalf("expected problems: %d %s", rec.Code, rec.Body)
	}
	env.do("DELETE", "/api/ipam/addresses/"+itoa(bad), nil)

	rec := env.do("POST", "/api/deploy/preview", map[string]any{})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `oifname \"eth0\" meta nfproto ipv4 counter masquerade`) {
		t.Fatalf("preview: %d %s", rec.Code, rec.Body)
	}

	changes := func() string {
		t.Helper()
		return env.do("GET", "/api/deploy/changes", nil).Body.String()
	}
	if got := changes(); !strings.Contains(got, `"changed":true,"deployed":false`) {
		t.Errorf("changes before first deploy: %s", got)
	}

	// Apply 1 has nothing to roll back to, so it is not pending.
	rec = env.do("POST", "/api/deploy/apply", map[string]any{})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"applied"`) {
		t.Fatalf("apply 1: %d %s", rec.Code, rec.Body)
	}
	if got := changes(); !strings.Contains(got, `"changed":false`) {
		t.Errorf("changes after deploy: %s", got)
	}
	env.do("PUT", "/api/nat/"+itoa(nat), map[string]any{"enabled": false})
	if got := changes(); !strings.Contains(got, `"changed":true`) {
		t.Errorf("changes after edit: %s", got)
	}
	env.do("PUT", "/api/nat/"+itoa(nat), map[string]any{"enabled": true})
	if got := changes(); !strings.Contains(got, `"changed":false`) {
		t.Errorf("changes after undoing the edit: %s", got)
	}
	rec = env.do("POST", "/api/deploy/apply", map[string]any{})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"pending"`) {
		t.Fatalf("apply 2: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("GET", "/api/agent/status", nil); !strings.Contains(rec.Body.String(), `"pending":{"generation":2`) {
		t.Fatalf("status: %s", rec.Body)
	}
	if rec := env.do("POST", "/api/deploy/confirm", map[string]any{}); rec.Code != http.StatusOK {
		t.Fatalf("confirm: %d %s", rec.Code, rec.Body)
	}
	var dep models.Deployment
	env.srv.db.Order("id desc").First(&dep)
	if dep.Status != "confirmed" || dep.Generation != 2 {
		t.Errorf("deployment %+v", dep)
	}

	// A wrong pin must fail closed.
	env.do("PUT", "/api/settings", map[string]any{"agent_fingerprint": strings.Repeat("ab", 32)})
	if rec := env.do("GET", "/api/agent/status", nil); rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "fingerprint mismatch") {
		t.Errorf("wrong pin: %d %s", rec.Code, rec.Body)
	}
}

func TestAutoRules(t *testing.T) {
	env := newEnv(t)
	inst := env.create("/api/instances", map[string]any{"name": "main"})
	env.create("/api/interfaces", map[string]any{"instance_id": inst, "name": "wan", "kind": "physical", "enabled": true, "ipv4_mode": "dhcp"})
	env.create("/api/interfaces", map[string]any{"instance_id": inst, "name": "wg0", "kind": "wireguard", "enabled": true, "ipv4_mode": "none", "wg_listen_port": 51820})

	rec := env.do("GET", fmt.Sprintf("/api/rules/auto?instance_id=%d", inst), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("auto rules: %d %s", rec.Code, rec.Body)
	}
	var got []struct {
		Service      string   `json:"service"`
		InInterfaces []string `json:"in_interfaces"`
		DstPort      int      `json:"dst_port"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	var names []string
	for _, r := range got {
		names = append(names, fmt.Sprintf("%s %v %d", r.Service, r.InInterfaces, r.DstPort))
	}
	if want := "dhcp client [wan] 68|wireguard wg0 [] 51820"; strings.Join(names, "|") != want {
		t.Errorf("got %q, want %q", strings.Join(names, "|"), want)
	}
	if rec := env.do("GET", "/api/rules/auto?instance_id=999", nil); rec.Code != http.StatusNotFound {
		t.Errorf("unknown instance: %d", rec.Code)
	}
}

func TestAutoRulesAntiLockout(t *testing.T) {
	env := newEnv(t)
	if err := env.srv.ensureDefaultInstance(); err != nil {
		t.Fatal(err)
	}
	var main models.Instance
	env.srv.db.Where("is_default = ?", true).First(&main)
	other := env.create("/api/instances", map[string]any{"name": "guest"})
	fake := &statusAgent{antiLockout: &render.AntiLockout{Port: 8443, AllowFrom: []string{"192.168.1.0/24"}}}
	env.srv.newAgent = func(*models.Settings) (agentAPI, error) { return fake, nil }

	get := func(id uint) string {
		t.Helper()
		rec := env.do("GET", fmt.Sprintf("/api/rules/auto?instance_id=%d", id), nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("auto rules: %d %s", rec.Code, rec.Body)
		}
		var got []render.AutoRule
		_ = json.Unmarshal(rec.Body.Bytes(), &got)
		var out []string
		for _, r := range got {
			out = append(out, fmt.Sprintf("%s %s %d %v", r.Service, r.Protocol, r.DstPort, r.Source))
		}
		return strings.Join(out, "|")
	}
	if got, want := get(main.ID), "anti-lockout tcp 8443 [192.168.1.0/24]"; got != want {
		t.Errorf("default: got %q, want %q", got, want)
	}
	if got := get(other); got != "" {
		t.Errorf("anti-lockout belongs to the default instance only: %q", got)
	}
	fake.antiLockout = nil
	if got := get(main.ID); got != "" {
		t.Errorf("disabled: %q", got)
	}
}

func TestInterfaceZones(t *testing.T) {
	env := newEnv(t)
	inst := env.create("/api/instances", map[string]any{"name": "main"})
	other := env.create("/api/instances", map[string]any{"name": "guest"})
	eth0 := env.create("/api/interfaces", map[string]any{"instance_id": inst, "name": "eth0"})
	eth1 := env.create("/api/interfaces", map[string]any{"instance_id": inst, "name": "eth1"})
	link := env.create("/api/links", map[string]any{"name": "up", "instance_a_id": inst, "interface_a": "lk-guest", "instance_b_id": other, "interface_b": "lk-main"})

	// Zero or more interfaces, link ends included; duplicates dropped.
	env.create("/api/interface-zones", map[string]any{"instance_id": inst, "name": "empty"})
	zone := env.create("/api/interface-zones", map[string]any{"instance_id": inst, "name": "lan", "interfaces": []string{"eth1", "lk-guest", "eth1"}})
	var z models.InterfaceZone
	env.srv.db.First(&z, zone)
	if strings.Join(z.Interfaces, " ") != "eth1 lk-guest" {
		t.Errorf("members %v", z.Interfaces)
	}
	if rec := env.do("POST", "/api/interface-zones", map[string]any{"instance_id": inst, "name": "eth0"}); rec.Code != http.StatusBadRequest {
		t.Errorf("zone named like an interface: %d", rec.Code)
	}
	if rec := env.do("POST", "/api/interfaces", map[string]any{"instance_id": inst, "name": "lan"}); rec.Code != http.StatusBadRequest {
		t.Errorf("interface named like a zone: %d", rec.Code)
	}
	if rec := env.do("POST", "/api/interface-zones", map[string]any{"instance_id": inst, "name": "x", "interfaces": []string{"lk-main"}}); rec.Code != http.StatusBadRequest {
		t.Errorf("other instance's link end accepted: %d", rec.Code)
	}

	rule := env.create("/api/rules", map[string]any{"instance_id": inst, "chain": "forward", "action": "accept", "in_interfaces": []string{"lan", "eth0"}, "out_interfaces": []string{"lk-guest"}})
	nat := env.create("/api/nat", map[string]any{"instance_id": inst, "kind": "masquerade", "out_interfaces": []string{"eth0"}})
	if rec := env.do("POST", "/api/rules", map[string]any{"instance_id": inst, "chain": "forward", "action": "accept", "in_interfaces": []string{"nope"}}); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown interface accepted: %d", rec.Code)
	}
	input := env.create("/api/rules", map[string]any{"instance_id": inst, "chain": "input", "action": "accept", "in_interfaces": []string{"lan"}, "out_interfaces": []string{"eth0"}})
	var in models.Rule
	env.srv.db.First(&in, input)
	if len(in.OutInterfaces) != 0 {
		t.Errorf("input rule kept outgoing interfaces %v", in.OutInterfaces)
	}
	comment := env.create("/api/rules", map[string]any{"instance_id": inst, "chain": "input", "kind": "comment", "description": " note ", "action": "bogus", "in_interfaces": []string{"lan"}})
	var cm models.Rule
	env.srv.db.First(&cm, comment)
	if cm.Description != "note" || cm.Action != "" || len(cm.InInterfaces) != 0 || !cm.Enabled {
		t.Errorf("comment row kept rule fields: %+v", cm)
	}
	if rec := env.do("POST", "/api/rules", map[string]any{"instance_id": inst, "chain": "input", "kind": "bogus", "action": "accept"}); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown rule kind accepted: %d", rec.Code)
	}

	// Renames follow into zones and rules.
	env.do("PUT", "/api/interfaces/"+itoa(eth1), map[string]any{"name": "eth9"})
	env.do("PUT", "/api/interfaces/"+itoa(eth0), map[string]any{"name": "wan0"})
	env.do("PUT", "/api/interface-zones/"+itoa(zone), map[string]any{"name": "inside"})
	env.do("PUT", "/api/links/"+itoa(link), map[string]any{"interface_a": "lk-g"})
	env.srv.db.First(&z, zone)
	var r models.Rule
	env.srv.db.First(&r, rule)
	var n models.NatRule
	env.srv.db.First(&n, nat)
	if strings.Join(z.Interfaces, " ") != "eth9 lk-g" || strings.Join(r.InInterfaces, " ") != "inside wan0" ||
		strings.Join(r.OutInterfaces, " ") != "lk-g" || strings.Join(n.OutInterfaces, " ") != "wan0" {
		t.Errorf("after rename: zone %v, rule %v -> %v, nat %v", z.Interfaces, r.InInterfaces, r.OutInterfaces, n.OutInterfaces)
	}

	// In use: refused. Only a zone member: removed from the zone.
	if rec := env.do("DELETE", "/api/interfaces/"+itoa(eth0), nil); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "NAT rule") {
		t.Errorf("delete interface in use: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("DELETE", "/api/interface-zones/"+itoa(zone), nil); rec.Code != http.StatusBadRequest {
		t.Errorf("delete zone in use: %d", rec.Code)
	}
	if rec := env.do("DELETE", "/api/links/"+itoa(link), nil); rec.Code != http.StatusBadRequest {
		t.Errorf("delete link in use: %d", rec.Code)
	}
	if rec := env.do("DELETE", "/api/interfaces/"+itoa(eth1), nil); rec.Code != http.StatusNoContent {
		t.Errorf("delete zone member: %d %s", rec.Code, rec.Body)
	}
	env.srv.db.First(&z, zone)
	if strings.Join(z.Interfaces, " ") != "lk-g" {
		t.Errorf("deleted interface left in zone: %v", z.Interfaces)
	}
}

func TestAddressObjects(t *testing.T) {
	env := newEnv(t)
	inst := env.create("/api/instances", map[string]any{"name": "main"})
	obj := env.create("/api/objects", map[string]any{"name": "nas", "addresses": []string{" 192.168.1.10 ", "fd00::10/128"}})
	env.create("/api/objects", map[string]any{"name": "lan", "addresses": []string{"192.168.1.0/24"}})

	var o models.AddressObject
	env.srv.db.First(&o, obj)
	if strings.Join(o.Addresses, " ") != "192.168.1.10 fd00::10" {
		t.Errorf("addresses not normalised: %v", o.Addresses)
	}
	for _, body := range []map[string]any{
		{"name": "default", "addresses": []string{"10.0.0.1"}},
		{"name": "empty", "addresses": []string{}},
		{"name": "bad", "addresses": []string{"nas"}},
	} {
		if rec := env.do("POST", "/api/objects", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%v: %d %s", body, rec.Code, rec.Body)
		}
	}

	rule := env.create("/api/rules", map[string]any{"instance_id": inst, "chain": "forward", "action": "accept", "dst_addrs": []string{"nas", "10.0.0.0/8"}})
	env.create("/api/nat", map[string]any{"instance_id": inst, "kind": "dnat", "protocol": "tcp", "dst_ports": "443", "to_addr": "nas"})
	for path, body := range map[string]map[string]any{
		"/api/rules":  {"instance_id": inst, "chain": "forward", "action": "accept", "src_addrs": []string{"ghost"}},
		"/api/nat":    {"instance_id": inst, "kind": "dnat", "to_addr": "lan"},
		"/api/routes": {"instance_id": inst, "destination": "default", "gateway": "lan"},
	} {
		if rec := env.do("POST", path, body); rec.Code != http.StatusBadRequest {
			t.Errorf("POST %s %v: %d %s", path, body, rec.Code, rec.Body)
		}
	}

	// In use: delete refused. Renamed: references follow.
	if rec := env.do("DELETE", fmt.Sprintf("/api/objects/%d", obj), nil); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "used by") {
		t.Errorf("delete in use: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("PUT", fmt.Sprintf("/api/objects/%d", obj), map[string]any{"name": "fileserver"}); rec.Code != http.StatusOK {
		t.Fatalf("rename: %d %s", rec.Code, rec.Body)
	}
	var r models.Rule
	env.srv.db.First(&r, rule)
	var n models.NatRule
	env.srv.db.First(&n)
	if strings.Join(r.DstAddrs, " ") != "fileserver 10.0.0.0/8" || n.ToAddr != "fileserver" {
		t.Errorf("references not renamed: %v %q", r.DstAddrs, n.ToAddr)
	}
}

func TestIpv6PrefixChecks(t *testing.T) {
	env := newEnv(t)
	inst := env.create("/api/instances", map[string]any{"name": "main"})
	for _, body := range []map[string]any{
		{"prefix": "192.168.1.0/24", "ra_enabled": true},
		{"prefix": "fd00:2::/56", "ra_enabled": true, "ra_slaac": true},
		{"prefix": "fd00:3::/64", "dhcp_enabled": true},
		{"prefix": "fd00:4::/64", "ra_enabled": true, "dhcp_enabled": true, "dhcp_gateway": "fd00:4::1"},
	} {
		body["instance_id"] = inst
		if rec := env.do("POST", "/api/ipam/prefixes", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%v: %d %s", body, rec.Code, rec.Body)
		}
	}
	env.create("/api/ipam/prefixes", map[string]any{"instance_id": inst, "prefix": "fd00:1::/64", "ra_enabled": true, "ra_slaac": true,
		"dhcp_enabled": true, "dhcp_range_start": "fd00:1::1000", "dhcp_range_end": "fd00:1::1fff"})
	env.create("/api/ipam/addresses", map[string]any{"instance_id": inst, "address": "fd00:1::10", "dns_name": "nas.home.arpa", "mac": "02:00:00:00:00:10"})
}

func TestDnsTemplates(t *testing.T) {
	env := newEnv(t)
	inst := env.create("/api/instances", map[string]any{"name": "main"})
	soa := env.create("/api/dns/soa-templates", map[string]any{"name": "std", "mname": "NS1.example.com.", "rname": "hostmaster@example.com",
		"refresh": 86400, "retry": 7200, "expire": 3600000, "minimum": 3600})
	var s models.DnsSoaTemplate
	env.srv.db.First(&s, soa)
	if s.Mname != "ns1.example.com" || s.Rname != "hostmaster.example.com" {
		t.Errorf("soa not normalised: %+v", s)
	}
	policy := env.create("/api/dns/dnssec-policies", map[string]any{"name": "signed", "ksk_algorithm": "ed25519", "zsk_algorithm": "ed25519", "zsk_lifetime": "30d"})
	tmpl := env.create("/api/dns/templates", map[string]any{"name": "std", "soa_template_id": soa, "default_ttl": 3600,
		"dnssec_policy_id": policy, "nameservers": []string{"ns1.example.com.", " ", "ns2.example.com"}})
	var tm models.DnsTemplate
	env.srv.db.First(&tm, tmpl)
	if strings.Join(tm.Nameservers, " ") != "ns1.example.com ns2.example.com" {
		t.Errorf("nameservers not normalised: %v", tm.Nameservers)
	}
	for path, body := range map[string]map[string]any{
		"/api/dns/soa-templates":   {"name": "bad", "mname": "ns1.example.com", "rname": "x.example.com", "refresh": 1, "retry": 0, "expire": 1},
		"/api/dns/dnssec-policies": {"name": "default", "ksk_algorithm": "ed25519", "zsk_algorithm": "ed25519"},
		"/api/dns/templates":       {"name": "nons", "soa_template_id": soa, "default_ttl": 3600, "nameservers": []string{}},
		"/api/dns/zones":           {"instance_id": inst, "name": "example.com", "dns_template_id": 999},
	} {
		if rec := env.do("POST", path, body); rec.Code != http.StatusBadRequest {
			t.Errorf("POST %s %v: %d %s", path, body, rec.Code, rec.Body)
		}
	}
	env.create("/api/dns/zones", map[string]any{"instance_id": inst, "name": "example.com", "dns_template_id": tmpl})

	for _, path := range []string{
		fmt.Sprintf("/api/dns/soa-templates/%d", soa),
		fmt.Sprintf("/api/dns/dnssec-policies/%d", policy),
		fmt.Sprintf("/api/dns/templates/%d", tmpl),
	} {
		if rec := env.do("DELETE", path, nil); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "used by") {
			t.Errorf("DELETE %s in use: %d %s", path, rec.Code, rec.Body)
		}
	}
}

func TestZoneRecordsGrid(t *testing.T) {
	env := newEnv(t)
	inst := env.create("/api/instances", map[string]any{"name": "main", "dns_enabled": true})
	zone := env.create("/api/dns/zones", map[string]any{"instance_id": inst, "name": "home.arpa"})
	path := fmt.Sprintf("/api/dns/zones/%d/records", zone)

	grid := []map[string]any{
		{"type": "A", "name": "nas", "value": "192.168.1.10", "mac": "0200.0000.0010"},
		{"type": "COMMENT", "value": "lab hosts"},
		{"type": "$DOMAIN", "name": "lab.home.arpa."},
		{"type": "A", "name": "@", "value": "192.168.2.1"},
		{"type": "CNAME", "name": "www", "value": "nas.home.arpa."},
	}
	rec := env.do("PUT", path, grid)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT: %d %s", rec.Code, rec.Body)
	}
	var got []models.DnsRecord
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if len(got) != 5 || got[0].Mac != "02:00:00:00:00:10" || got[1].Type != "COMMENT" || got[2].Name != "lab" || got[4].Rank != 4 {
		t.Fatalf("records: %+v", got)
	}

	doc, _ := builder.Build(env.srv.db, 1)
	var names []string
	for _, r := range doc.Instance("main").DNS.Zones[0].Records {
		names = append(names, r.Name+"/"+r.Type)
	}
	if strings.Join(names, " ") != "nas/A lab/A www.lab/CNAME" {
		t.Errorf("built records: %v", names)
	}

	// A bad row rejects the whole grid, naming the row; nothing changes.
	grid[3]["value"] = "fd00::1"
	if rec := env.do("PUT", path, grid); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "record 4") {
		t.Errorf("bad grid: %d %s", rec.Code, rec.Body)
	}
	var n int64
	env.srv.db.Model(&models.DnsRecord{}).Where("zone_id = ?", zone).Count(&n)
	if n != 5 {
		t.Errorf("records after rejected save: %d", n)
	}
}

func TestRememberMe(t *testing.T) {
	env := newEnv(t)
	if env.cookie.MaxAge != 0 {
		t.Errorf("without remember: MaxAge %d, want a browser session cookie", env.cookie.MaxAge)
	}
	env.cookie = nil
	rec := env.do("POST", "/api/login", map[string]any{"username": "admin", "password": "correct horse battery", "remember": true})
	if rec.Code != http.StatusOK {
		t.Fatalf("login: %d %s", rec.Code, rec.Body)
	}
	sessionCookie := func(rec *httptest.ResponseRecorder) *http.Cookie {
		for _, c := range rec.Result().Cookies() {
			if c.Name == cookieName {
				return c
			}
		}
		t.Fatal("no session cookie")
		return nil
	}
	env.cookie = sessionCookie(rec)
	if want := int(rememberTTL.Seconds()); env.cookie.MaxAge != want {
		t.Errorf("with remember: MaxAge %d, want %d", env.cookie.MaxAge, want)
	}

	// A password change reissues the session and keeps remember.
	rec = env.do("POST", "/api/me/password", map[string]string{"current": "correct horse battery", "new": "another long password"})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("change password: %d %s", rec.Code, rec.Body)
	}
	if c := sessionCookie(rec); c.MaxAge != int(rememberTTL.Seconds()) {
		t.Errorf("after password change: MaxAge %d", c.MaxAge)
	}
}

func TestEnsureDefaultInstance(t *testing.T) {
	env := newEnv(t)
	for range 2 {
		if err := env.srv.ensureDefaultInstance(); err != nil {
			t.Fatal(err)
		}
	}
	var got []models.Instance
	env.srv.db.Find(&got)
	if len(got) != 1 || got[0].Name != DefaultInstanceName || !got[0].IsDefault || got[0].DhcpLeaseTime != 86400 {
		t.Errorf("instances: %+v", got)
	}
	var rules []models.Rule
	env.srv.db.Find(&rules)
	if len(rules) != 1 || rules[0].Chain != "output" || rules[0].Action != "accept" || !rules[0].Enabled || len(rules[0].OutInterfaces) != 0 {
		t.Errorf("seeded rules: %+v", rules)
	}
}
