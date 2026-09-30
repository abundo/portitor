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
	"reflect"
	"strings"
	"testing"

	"github.com/labstack/echo/v5"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/abundo/portitor/internal/agent"
	"github.com/abundo/portitor/internal/builder"
	"github.com/abundo/portitor/internal/dbmigrate"
	"github.com/abundo/portitor/internal/fwconfig"
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
	env.create("/api/interfaces", map[string]any{"instance_id": other, "name": "eth2", "label": " LAN "})
	var eth2 models.Interface
	env.srv.db.Where("name = ?", "eth2").First(&eth2)
	if eth2.Label != "LAN" {
		t.Errorf("label %q", eth2.Label)
	}
	if rec := env.do("POST", "/api/interfaces", map[string]any{"instance_id": other, "name": "eth3", "label": "a\nb"}); rec.Code != http.StatusBadRequest {
		t.Errorf("label with a newline accepted: %d", rec.Code)
	}
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

	// Free peer addresses follow the prefixes of the interface's
	// addresses, skipping IPAM and existing peers.
	if rec := env.do("PUT", "/api/interfaces/"+itoa(ifc.ID), map[string]any{"addresses": []string{"172.25.34.1/32", "10.99.0.1/24", "fd99::1/64"}}); rec.Code != http.StatusOK {
		t.Fatalf("addresses: %d %s", rec.Code, rec.Body)
	}
	env.create("/api/ipam/addresses", map[string]any{"instance_id": inst, "address": "10.99.0.3"})
	free := env.do("GET", "/api/interfaces/"+itoa(ifc.ID)+"/wg-next-free", nil)
	if !strings.Contains(free.Body.String(), "172.25.34.1/32 on wg0 is a single address") {
		t.Errorf("no warning for a single address: %s", free.Body)
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

	// A site peer: its networks are refused as a default route, and its
	// config routes this instance's prefixes (not those behind it), with
	// no DNS.
	if rec := env.do("POST", "/api/wg/peers", map[string]any{"interface_id": ifc.ID, "name": "all", "allowed_ips": []string{"10.99.0.9/32"}, "networks": []string{"0.0.0.0/0"}, "enabled": true}); rec.Code != http.StatusBadRequest {
		t.Errorf("default route as network accepted: %d", rec.Code)
	}
	env.create("/api/ipam/prefixes", map[string]any{"instance_id": inst, "prefix": "192.168.50.0/24"})
	site := env.do("POST", "/api/wg/peers", map[string]any{"interface_id": ifc.ID, "name": "office", "allowed_ips": []string{"10.99.0.5/32"}, "networks": []string{"192.168.50.0/24"}, "enabled": true})
	if site.Code != http.StatusCreated {
		t.Fatalf("site peer: %d %s", site.Code, site.Body)
	}
	var sp models.WgPeer
	env.srv.db.Where("name = ?", "office").First(&sp)
	rec := env.do("GET", "/api/wg/peers/"+itoa(sp.ID)+"/config", nil)
	var sc struct {
		Config string `json:"config"`
		Site   bool   `json:"site"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &sc)
	if !sc.Site || !strings.Contains(sc.Config, "Address = 10.99.0.5/32\n") || strings.Contains(sc.Config, "192.168.50.0/24") ||
		!strings.Contains(sc.Config, "10.99.0.0/24") || strings.Contains(sc.Config, "0.0.0.0/0") || strings.Contains(sc.Config, "DNS =") {
		t.Errorf("site config: %s", rec.Body)
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
	env.create("/api/interfaces", map[string]any{"instance_id": inst, "name": "eth1", "enabled": true, "dns_listen": true, "addresses": []string{"192.168.1.1/24"}})
	env.create("/api/interface-zones", map[string]any{"instance_id": inst, "name": "lan", "interfaces": []string{"eth1"}})
	env.create("/api/ipam/prefixes", map[string]any{"instance_id": inst, "prefix": "192.168.1.0/24", "dhcp_enabled": true, "dhcp_range_start": "192.168.1.100", "dhcp_range_end": "192.168.1.200"})
	env.create("/api/rules", map[string]any{"instance_id": inst, "chain": "forward", "in_interfaces": []string{"lan"}, "out_interfaces": []string{"eth0"}, "action": "accept", "enabled": true})
	nat := env.create("/api/nat", map[string]any{"instance_id": inst, "kind": "masquerade", "out_interfaces": []string{"eth0"}, "enabled": true})

	// Problems block the deploy.
	bad := env.create("/api/ipam/prefixes", map[string]any{"instance_id": inst, "prefix": "10.5.0.0/24", "dhcp_enabled": true})
	if rec := env.do("POST", "/api/deploy/apply", map[string]any{}); rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "no interface has an address in it") {
		t.Fatalf("expected problems: %d %s", rec.Code, rec.Body)
	}
	env.do("DELETE", "/api/ipam/prefixes/"+itoa(bad), nil)

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
	if rec := env.do("POST", "/api/deploy/apply", map[string]any{}); rec.Code != http.StatusConflict {
		t.Fatalf("apply while pending: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("POST", "/api/deploy/confirm", map[string]any{}); rec.Code != http.StatusOK {
		t.Fatalf("confirm: %d %s", rec.Code, rec.Body)
	}
	var dep models.Deployment
	env.srv.db.Order("id desc").First(&dep)
	if dep.Status != "confirmed" || dep.Generation != 2 {
		t.Errorf("deployment %+v", dep)
	}

	// Revert discards uncommitted edits, new rows included.
	var nRules, nDeployed int64
	env.srv.db.Model(&models.Rule{}).Count(&nDeployed)
	env.do("PUT", "/api/nat/"+itoa(nat), map[string]any{"enabled": false})
	env.create("/api/rules", map[string]any{"instance_id": inst, "chain": "input", "action": "drop", "enabled": true})
	if got := changes(); !strings.Contains(got, `"changed":true`) {
		t.Errorf("changes before revert: %s", got)
	}
	if rec := env.do("POST", "/api/deploy/revert", map[string]any{}); rec.Code != http.StatusOK {
		t.Fatalf("revert: %d %s", rec.Code, rec.Body)
	}
	if got := changes(); !strings.Contains(got, `"changed":false`) {
		t.Errorf("changes after revert: %s", got)
	}
	env.srv.db.Model(&models.Rule{}).Count(&nRules)
	if nRules != nDeployed {
		t.Errorf("rules after revert: %d, want %d", nRules, nDeployed)
	}
	if rec := env.do("GET", "/api/settings", nil); !strings.Contains(rec.Body.String(), ts.URL) {
		t.Errorf("revert lost the agent settings: %s", rec.Body)
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
	fake := &statusAgent{antiLockout: &render.AntiLockout{Port: 8443, SSHPort: 22, AllowFrom: []string{"192.168.1.0/24"}}}
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
	if got, want := get(main.ID), "anti-lockout tcp 22 [192.168.1.0/24]|anti-lockout tcp 8443 [192.168.1.0/24]"; got != want {
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
	group := env.create("/api/rules", map[string]any{"instance_id": inst, "chain": "input", "kind": "group", "description": " Admin ", "action": "accept", "src_addrs": []string{"10.0.0.1"}})
	var gr models.Rule
	env.srv.db.First(&gr, group)
	if gr.Description != "Admin" || gr.Action != "" || len(gr.SrcAddrs) != 0 || !gr.Enabled {
		t.Errorf("group row kept rule fields: %+v", gr)
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

func TestObjectFolders(t *testing.T) {
	env := newEnv(t)
	top := env.create("/api/object-folders", map[string]any{"kind": "hosts", "name": " Servers "})
	sub := env.create("/api/object-folders", map[string]any{"kind": "hosts", "name": "NAS", "parent_id": top})
	lists := env.create("/api/object-folders", map[string]any{"kind": "ip_lists", "name": "Servers"})
	for _, body := range []map[string]any{
		{"kind": "hosts", "name": ""},
		{"kind": "rules", "name": "x"},
		{"kind": "hosts", "name": "Servers"},                    // same name, same place
		{"kind": "hosts", "name": "x", "parent_id": lists},      // other kind
		{"kind": "ip_lists", "name": "x", "parent_id": 1 << 20}, // missing
	} {
		if rec := env.do("POST", "/api/object-folders", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%v: %d %s", body, rec.Code, rec.Body)
		}
	}
	if rec := env.do("PUT", fmt.Sprintf("/api/object-folders/%d", top), map[string]any{"parent_id": sub}); rec.Code != http.StatusBadRequest {
		t.Errorf("folder into its own subfolder: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("PUT", fmt.Sprintf("/api/object-folders/%d", top), map[string]any{"kind": "ip_lists"}); rec.Code != http.StatusBadRequest {
		t.Errorf("kind changed: %d %s", rec.Code, rec.Body)
	}

	host := env.create("/api/objects", map[string]any{"name": "nas", "addresses": []string{"192.168.1.10"}, "folder_id": sub})
	if rec := env.do("POST", "/api/objects", map[string]any{"name": "x", "addresses": []string{"10.0.0.1"}, "folder_id": lists}); rec.Code != http.StatusBadRequest {
		t.Errorf("host in an IP list folder: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("POST", "/api/ip-lists", map[string]any{"name": "bl", "source": "url", "url": "https://example.com/bl.txt", "folder_id": top}); rec.Code != http.StatusBadRequest {
		t.Errorf("IP list in a host folder: %d %s", rec.Code, rec.Body)
	}
	env.create("/api/ip-lists", map[string]any{"name": "bl", "source": "url", "url": "https://example.com/bl.txt", "folder_id": lists})

	// Not empty: delete refused. Moved out: allowed.
	for _, id := range []uint{top, sub, lists} {
		if rec := env.do("DELETE", fmt.Sprintf("/api/object-folders/%d", id), nil); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "not empty") {
			t.Errorf("delete folder %d: %d %s", id, rec.Code, rec.Body)
		}
	}
	if rec := env.do("PUT", fmt.Sprintf("/api/objects/%d", host), map[string]any{"folder_id": nil}); rec.Code != http.StatusOK {
		t.Fatalf("move host out: %d %s", rec.Code, rec.Body)
	}
	for _, id := range []uint{sub, top} {
		if rec := env.do("DELETE", fmt.Sprintf("/api/object-folders/%d", id), nil); rec.Code != http.StatusNoContent && rec.Code != http.StatusOK {
			t.Errorf("delete empty folder %d: %d %s", id, rec.Code, rec.Body)
		}
	}
}

func TestCustomServices(t *testing.T) {
	env := newEnv(t)
	inst := env.create("/api/instances", map[string]any{"name": "main"})
	tcp := func(lo, hi int) map[string]any { return map[string]any{"protocol": "tcp", "dst_lo": lo, "dst_hi": hi} }
	svc := env.create("/api/custom-services", map[string]any{"name": " UniFi ", "type": "tcp/udp/sctp", "description": "controller",
		"ports": []any{tcp(8080, 8080), tcp(8443, 0)}, "icmp_type": "echo-request", "ip_protocol": 6})
	env.create("/api/custom-services", map[string]any{"name": "unreach", "type": "icmp", "icmp_type": "destination-unreachable", "icmp_code": 4})

	var s models.Service
	env.srv.db.First(&s, svc)
	if s.Name != "unifi" || len(s.Ports) != 2 || s.Ports[0].DstHi != 0 || s.IcmpType != "" || s.IpProtocol != 0 {
		t.Errorf("not normalised: %+v", s)
	}
	for _, body := range []map[string]any{
		{"name": "ssh", "type": "tcp/udp/sctp", "ports": []any{tcp(2222, 0)}},
		{"name": "1x", "type": "tcp/udp/sctp", "ports": []any{tcp(1, 0)}},
		{"name": "empty", "type": "tcp/udp/sctp", "ports": []any{}},
		{"name": "badrange", "type": "tcp/udp/sctp", "ports": []any{tcp(9000, 8000)}},
		{"name": "badproto", "type": "tcp/udp/sctp", "ports": []any{map[string]any{"protocol": "icmp", "dst_lo": 1}}},
		{"name": "badtype", "type": "tcp"},
		{"name": "v6type", "type": "icmp", "icmp_type": "nd-neighbor-solicit"},
		{"name": "codeonly", "type": "icmp6", "icmp_code": 1},
		{"name": "bignum", "type": "ip", "ip_protocol": 300},
	} {
		if rec := env.do("POST", "/api/custom-services", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%v: %d %s", body, rec.Code, rec.Body)
		}
	}

	rule := env.create("/api/rules", map[string]any{"instance_id": inst, "chain": "forward", "action": "accept", "enabled": true, "services": []string{"ssh", "unifi", "unreach", "ssh"}})
	if rec := env.do("POST", "/api/rules", map[string]any{"instance_id": inst, "chain": "forward", "action": "accept", "services": []string{"ghost"}}); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown service accepted: %d %s", rec.Code, rec.Body)
	}

	doc, _ := builder.Build(env.srv.db, 1)
	in := doc.Instances[0]
	code := 4
	want := []fwconfig.ServiceMatch{
		{Protocol: "tcp", DstPorts: "22,8080,8443"},
		{Protocol: "icmp", ICMPType: "destination-unreachable", ICMPCode: &code},
	}
	if last := in.Rules[len(in.Rules)-1]; !reflect.DeepEqual(last.Services, want) {
		t.Errorf("not expanded: %+v", last.Services)
	}

	// In use: delete refused. Renamed: references follow.
	if rec := env.do("DELETE", fmt.Sprintf("/api/custom-services/%d", svc), nil); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "used by") {
		t.Errorf("delete in use: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("PUT", fmt.Sprintf("/api/custom-services/%d", svc), map[string]any{"name": "controller"}); rec.Code != http.StatusOK {
		t.Fatalf("rename: %d %s", rec.Code, rec.Body)
	}
	var r models.Rule
	env.srv.db.First(&r, rule)
	if strings.Join(r.Services, " ") != "ssh controller unreach" {
		t.Errorf("references not renamed: %v", r.Services)
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
	if rec := env.do("PUT", fmt.Sprintf("/api/dns/zones/%d", zone), map[string]any{"type": "reverse4", "name": "192.168.1.0/24"}); rec.Code != http.StatusBadRequest {
		t.Errorf("zone type change: %d %s", rec.Code, rec.Body)
	}

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

// login switches env to a new session for username.
func (env *testEnv) login(username, password string) {
	env.t.Helper()
	env.cookie = nil
	rec := env.do("POST", "/api/login", map[string]string{"username": username, "password": password})
	if rec.Code != http.StatusOK {
		env.t.Fatalf("login %s: %d %s", username, rec.Code, rec.Body)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == cookieName {
			env.cookie = c
		}
	}
}

func TestViewerRole(t *testing.T) {
	env := newEnv(t)
	id := env.create("/api/users", map[string]string{"username": "ann", "password": "a long password", "role": "viewer"})
	if rec := env.do("POST", "/api/users", map[string]string{"username": "bob", "password": "a long password", "role": "root"}); rec.Code != http.StatusBadRequest {
		t.Errorf("bad role: %d", rec.Code)
	}
	env.login("ann", "a long password")

	if rec := env.do("GET", "/api/instances", nil); rec.Code != http.StatusOK {
		t.Errorf("viewer read: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("PUT", "/api/me", map[string]string{"full_name": "Ann", "role": "admin"}); rec.Code != http.StatusOK {
		t.Errorf("viewer profile: %d %s", rec.Code, rec.Body)
	}
	var me models.User
	_ = json.Unmarshal(env.do("GET", "/api/me", nil).Body.Bytes(), &me)
	if me.Role != models.RoleViewer {
		t.Errorf("viewer became %q", me.Role)
	}
	// Every route that isn't a plain read is refused, except the few a
	// viewer needs; so is every read that hands out secrets.
	checked := 0
	for _, r := range env.e.Router().Routes() {
		if !strings.HasPrefix(r.Path, "/api/") || r.Path == "/api/*" || r.Path == "/api/login" || r.Path == "/api/logout" || r.Path == "/api/version" {
			continue
		}
		read := r.Method == http.MethodGet || r.Method == http.MethodHead
		want := !read && !viewerWrites[r.Method+" "+r.Path] || read && viewerDenied[r.Path]
		path := strings.ReplaceAll(r.Path, ":id", "1")
		rec := env.do(r.Method, path, map[string]any{})
		if got := rec.Code == http.StatusForbidden && strings.Contains(rec.Body.String(), "read-only"); got != want {
			t.Errorf("%s %s: %d %s", r.Method, r.Path, rec.Code, rec.Body)
		}
		checked++
	}
	if checked < 50 {
		t.Errorf("only %d routes checked", checked)
	}

	// Promoting ann ends her session.
	env.login("admin", "correct horse battery")
	if rec := env.do("PUT", fmt.Sprintf("/api/users/%d", id), map[string]string{"role": "admin"}); rec.Code != http.StatusOK {
		t.Fatalf("promote: %d %s", rec.Code, rec.Body)
	}
	var admin models.User
	_ = json.Unmarshal(env.do("GET", "/api/me", nil).Body.Bytes(), &admin)
	if rec := env.do("PUT", fmt.Sprintf("/api/users/%d", admin.ID), map[string]string{"role": "viewer"}); rec.Code != http.StatusBadRequest {
		t.Errorf("own role: %d", rec.Code)
	}
	var ann models.User
	if err := env.srv.db.First(&ann, id).Error; err != nil || ann.Role != models.RoleAdmin || ann.TokenVersion == 0 {
		t.Errorf("ann: %+v %v", ann, err)
	}
}

func TestInterfaceMove(t *testing.T) {
	env := newEnv(t)
	inst := env.create("/api/instances", map[string]any{"name": "main"})
	other := env.create("/api/instances", map[string]any{"name": "guest"})
	eth1 := env.create("/api/interfaces", map[string]any{"instance_id": inst, "name": "eth1", "addresses": []string{"10.9.9.1/24"}})
	zone := env.create("/api/interface-zones", map[string]any{"instance_id": inst, "name": "lan", "interfaces": []string{"eth1"}})
	vlan := env.create("/api/interfaces", map[string]any{"instance_id": inst, "name": "eth1.10", "kind": "vlan", "parent": "eth1", "vlan_id": 10})
	route := env.create("/api/routes", map[string]any{"instance_id": inst, "destination": "10.9.0.0/16", "gateway": "", "interface_id": eth1})
	rule := env.create("/api/rules", map[string]any{"instance_id": inst, "chain": "forward", "action": "accept", "in_interfaces": []string{"eth1"}})

	move := func() *httptest.ResponseRecorder {
		return env.do("PUT", "/api/interfaces/"+itoa(eth1), map[string]any{"instance_id": other})
	}
	for _, step := range []struct{ path, want string }{
		{"/api/rules/" + itoa(rule), "rule"},
		{"/api/interfaces/" + itoa(vlan), "interface eth1.10"},
		{"/api/routes/" + itoa(route), "route 10.9.0.0/16"},
	} {
		if rec := move(); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), step.want) {
			t.Fatalf("move while used by %s: %d %s", step.want, rec.Code, rec.Body)
		}
		if rec := env.do("DELETE", step.path, nil); rec.Code != http.StatusNoContent {
			t.Fatalf("delete %s: %d %s", step.path, rec.Code, rec.Body)
		}
	}
	if rec := move(); rec.Code != http.StatusOK {
		t.Fatalf("move: %d %s", rec.Code, rec.Body)
	}
	var i models.Interface
	env.srv.db.First(&i, eth1)
	var z models.InterfaceZone
	env.srv.db.First(&z, zone)
	if i.InstanceID != other || len(z.Interfaces) != 0 || len(i.Addresses) != 1 {
		t.Errorf("after move: instance %d, old zone %v, addresses %v (they move along)", i.InstanceID, z.Interfaces, i.Addresses)
	}
}

func TestDnsFromDhcp(t *testing.T) {
	env := newEnv(t)
	inst := env.create("/api/instances", map[string]any{"name": "main", "dns_upstream": "dhcp"})
	wan1 := env.create("/api/interfaces", map[string]any{"instance_id": inst, "name": "eth0", "ipv4_mode": "dhcp", "dns_from_dhcp": true})
	wan2 := env.create("/api/interfaces", map[string]any{"instance_id": inst, "name": "eth1", "ipv4_mode": "dhcp"})
	lan := env.create("/api/interfaces", map[string]any{"instance_id": inst, "name": "eth2", "dns_from_dhcp": true})
	flag := func(id uint) bool {
		var i models.Interface
		env.srv.db.First(&i, id)
		return i.DnsFromDhcp
	}
	if !flag(wan1) || flag(lan) {
		t.Fatalf("a static interface can't give DNS from DHCP: eth0 %v, eth2 %v", flag(wan1), flag(lan))
	}
	// One per instance: taking the flag moves it.
	if rec := env.do("PUT", "/api/interfaces/"+itoa(wan2), map[string]any{"dns_from_dhcp": true}); rec.Code != http.StatusOK {
		t.Fatalf("put: %d %s", rec.Code, rec.Body)
	}
	if flag(wan1) || !flag(wan2) {
		t.Errorf("after moving the flag: eth0 %v, eth1 %v", flag(wan1), flag(wan2))
	}
	if rec := env.do("PUT", "/api/instances/"+itoa(inst), map[string]any{"dns_upstream": "peer"}); rec.Code != http.StatusBadRequest {
		t.Errorf("bad upstream: %d %s", rec.Code, rec.Body)
	}
}

func TestInterfaceAddresses(t *testing.T) {
	env := newEnv(t)
	inst := env.create("/api/instances", map[string]any{"name": "main"})
	eth1 := env.create("/api/interfaces", map[string]any{"instance_id": inst, "name": "eth1",
		"addresses": []string{" 192.168.1.1/24 ", "fd00:1:0::1/64", "192.168.1.1/24", "10.0.0.0/31", ""}})
	var i models.Interface
	env.srv.db.First(&i, eth1)
	if got := strings.Join(i.Addresses, " "); got != "192.168.1.1/24 fd00:1::1/64 10.0.0.0/31" {
		t.Errorf("addresses stored as %q, want canonical, without repeats", got)
	}
	for _, c := range []struct {
		body map[string]any
		want string
	}{
		{map[string]any{"name": "eth2", "addresses": []string{"192.168.2.0/24"}}, "network address"},
		{map[string]any{"name": "eth2", "addresses": []string{"fd00:2::/64"}}, "network address"},
		{map[string]any{"name": "eth2", "addresses": []string{"192.168.2.1"}}, "with a prefix length"},
		{map[string]any{"name": "eth2", "addresses": []string{"192.168.1.1/25"}}, "192.168.1.1 is already on eth1"},
		{map[string]any{"name": "eth2", "ipv4_mode": "dhcp", "addresses": []string{"192.168.2.1/24"}}, "IPv4 comes from the DHCP client"},
	} {
		c.body["instance_id"] = inst
		if rec := env.do("POST", "/api/interfaces", c.body); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), c.want) {
			t.Errorf("%v: %d %s, want %q", c.body, rec.Code, rec.Body, c.want)
		}
	}
	env.create("/api/interfaces", map[string]any{"instance_id": inst, "name": "eth0", "ipv4_mode": "dhcp", "addresses": []string{"2001:db8::2/64"}})

	// The tree shows the interfaces' prefixes and addresses without IPAM
	// entries.
	tree := env.do("GET", "/api/ipam/tree?instance_id="+itoa(inst), nil).Body.String()
	for _, want := range []string{
		`"kind":"prefix","id":0,"auto":true,"cidr":"192.168.1.0/24"`,
		`"kind":"address","id":0,"auto":true,"cidr":"192.168.1.1","interface_id":` + itoa(eth1),
		`"cidr":"2001:db8::/64"`,
		`"cidr":"fd00:1::/64"`,
	} {
		if !strings.Contains(tree, want) {
			t.Errorf("tree lacks %s:\n%s", want, tree)
		}
	}
	// Next free skips the interface's address.
	pfx := env.create("/api/ipam/prefixes", map[string]any{"instance_id": inst, "prefix": "192.168.1.0/24"})
	if got := env.do("GET", "/api/ipam/prefixes/"+itoa(pfx)+"/next-free", nil).Body.String(); !strings.Contains(got, `"192.168.1.2"`) {
		t.Errorf("next free: %s", got)
	}
}
