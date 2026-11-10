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
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/abundo/portitor/internal/agent"
	"github.com/abundo/portitor/internal/builder"
	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/dbmigrate"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/ipam"
	"github.com/abundo/portitor/internal/render"
	"github.com/abundo/portitor/models"
)

type testEnv struct {
	t      *testing.T
	srv    *Server
	e      *echo.Echo
	cookie *http.Cookie
}

// firstFirewall reads the firewall the installation started with.
func firstFirewall(t *testing.T, env *testEnv) models.Firewall {
	t.Helper()
	var fw models.Firewall
	if err := env.srv.db.Order("id").First(&fw).Error; err != nil {
		t.Fatal(err)
	}
	return fw
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
	// Most tests use several instances.
	if err := srv.editConfig(t.Context(), func(work *datastore.Tree) error {
		return work.Set(datastore.Path{{Name: "settings"}, {Name: "virtual-firewalls"}}, "true")
	}); err != nil {
		t.Fatal(err)
	}
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
	if rec := env.do("GET", "/api/config/candidate/instance", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated: %d", rec.Code)
	}
	if rec := env.do("POST", "/api/login", map[string]string{"username": "admin", "password": "wrong"}); rec.Code != http.StatusUnauthorized {
		t.Errorf("wrong password: %d", rec.Code)
	}
	env.cookie = cookie

	// CSRF: a form post is refused even with a valid cookie.
	req := httptest.NewRequest("POST", "/api/config/candidate/instance", strings.NewReader("name=x"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	env.e.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("form post: %d", rec.Code)
	}

	// A DELETE has no body, so the browser sends no Content-Type.
	env.host("main") // the default, which stays
	env.vf("gone")
	req = httptest.NewRequest("DELETE", "/api/config/candidate/instance=gone", nil)
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
	rec := env.do("PUT", "/api/me", map[string]string{"username": "root", "full_name": "Ada Admin", "email": "ada@example.org", "date_format": "dmy"})
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	var me models.User
	if err := json.Unmarshal(env.do("GET", "/api/me", nil).Body.Bytes(), &me); err != nil {
		t.Fatal(err)
	}
	if me.Username != "admin" || me.FullName != "Ada Admin" || me.Email != "ada@example.org" || me.DateFormat != "dmy" {
		t.Errorf("got %+v", me)
	}
	for _, body := range []map[string]string{
		{"email": "not an address"},
		{"full_name": "a\nb"},
		{"date_format": "yyyy"},
	} {
		if rec := env.do("PUT", "/api/me", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%v: %d", body, rec.Code)
		}
	}
}

func TestValidationAndSecrets(t *testing.T) {
	env := newEnv(t)
	fw := firstFirewall(t, env).Name
	if rec := env.cfg("POST", "instance", map[string]any{"name": "Bad Name", "firewall": fw, "is-default": true}); rec.Code != http.StatusBadRequest {
		t.Errorf("bad instance name: %d", rec.Code)
	}
	env.host("main")
	// The default stays: it can't be deleted, and the flag doesn't move.
	env.vf("other")
	if rec := env.cfg("DELETE", "instance=main", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("delete the default: %d %s", rec.Code, rec.Body)
	}
	if rec := env.cfg("PATCH", "instance=other", map[string]any{"is-default": true}); rec.Code != http.StatusBadRequest {
		t.Errorf("a second default: %d %s", rec.Code, rec.Body)
	}
	if rec := env.cfg("PATCH", "instance=main", map[string]any{"is-default": false}); rec.Code != http.StatusBadRequest {
		t.Errorf("the default given up: %d %s", rec.Code, rec.Body)
	}
	env.mustCfg("DELETE", "instance=other", nil)
	if rec := env.cfg("POST", "instance", map[string]any{"name": "main", "firewall": fw}); rec.Code != http.StatusBadRequest {
		t.Errorf("duplicate: %d", rec.Code)
	}
	env.vf("guest")
	env.put("instance=guest/interface=eth2", map[string]any{"kind": "physical", "label": " LAN "})
	if l := env.node("instance=guest/interface=eth2").Leaf("label"); l != "LAN" {
		t.Errorf("label %q", l)
	}
	if rec := env.cfg("PUT", "instance=guest/interface=eth3", map[string]any{"kind": "physical", "label": "a\nb"}); rec.Code != http.StatusBadRequest {
		t.Errorf("label with a newline accepted: %d", rec.Code)
	}
	if rec := env.cfg("PUT", "instance=main/interface-zone=lan", map[string]any{"interfaces": []string{"eth2"}}); rec.Code != http.StatusBadRequest {
		t.Errorf("interface of another instance accepted in a zone: %d", rec.Code)
	}
	if rec := env.cfg("POST", "instance=main/rule", map[string]any{"chain": "forward", "action": "accept", "in-interfaces": []string{"eth2"}}); rec.Code != http.StatusBadRequest {
		t.Errorf("interface of another instance accepted in a rule: %d", rec.Code)
	}

	// WireGuard: keys made, the private key never answered nor overwritten
	// by a replace without it.
	wg0 := "instance=main/interface=wg0"
	env.put(wg0, map[string]any{"kind": "wireguard", "wg-listen-port": 51820})
	priv := env.node(wg0).Leaf("wg-private-key")
	if priv == "" || env.node(wg0).Leaf("wg-public-key") == "" {
		t.Fatal("no keys")
	}
	if rec := env.do("GET", "/api/config/candidate/"+wg0, nil); strings.Contains(rec.Body.String(), priv) {
		t.Error("private key leaked")
	}
	env.put(wg0, map[string]any{"kind": "wireguard", "wg-listen-port": 51820, "description": "vpn"})
	if n := env.node(wg0); n.Leaf("wg-private-key") != priv || n.Leaf("description") != "vpn" {
		t.Error("replace lost the key")
	}
	env.post(wg0+"/wireguard-peer", map[string]any{"name": "phone", "allowed-ips": []string{"10.99.0.2/32"}, "enabled": true})
	if env.node(wg0+"/wireguard-peer=phone").Leaf("client-private-key") == "" {
		t.Fatal("no client key")
	}

	// Free peer addresses follow the prefixes of the interface's
	// addresses, skipping IPAM and existing peers.
	env.patch(wg0, map[string]any{"addresses": []string{"172.25.34.1/32", "10.99.0.1/24", "fd99::1/64"}})
	env.post("instance=main/ipam-address", map[string]any{"address": "10.99.0.3"})
	free := env.do("GET", "/api/config/candidate/"+wg0+"?action=wg-next-free", nil)
	if !strings.Contains(free.Body.String(), "172.25.34.1/32 on wg0 is a single address") {
		t.Errorf("no warning for a single address: %s", free.Body)
	}
	if !strings.Contains(free.Body.String(), `"addresses":["10.99.0.4/32","fd99::4/128"]`) {
		t.Errorf("next free: %d %s", free.Code, free.Body)
	}
	// Client config uses the interface's endpoint and keepalive.
	env.patch(wg0, map[string]any{"wg-endpoint": "vpn.example.org:4500", "wg-keepalive": 15})
	conf := env.do("GET", "/api/config/candidate/"+wg0+"/wireguard-peer=phone?action=client-config", nil).Body.String()
	if !strings.Contains(conf, "Endpoint = vpn.example.org:4500") || !strings.Contains(conf, "PersistentKeepalive = 15") {
		t.Errorf("client config: %s", conf)
	}
	if rec := env.cfg("PATCH", wg0, map[string]any{"wg-endpoint": "no-port"}); rec.Code != http.StatusBadRequest {
		t.Errorf("endpoint without port accepted: %d", rec.Code)
	}

	// A site peer: its networks are refused as a default route, and its
	// config routes this instance's prefixes (not those behind it), with
	// no DNS.
	if rec := env.cfg("POST", wg0+"/wireguard-peer", map[string]any{"name": "all", "allowed-ips": []string{"10.99.0.9/32"}, "networks": []string{"0.0.0.0/0"}, "enabled": true}); rec.Code != http.StatusBadRequest {
		t.Errorf("default route as network accepted: %d", rec.Code)
	}
	env.post("instance=main/ipam-prefix", map[string]any{"prefix": "192.168.50.0/24"})
	env.post(wg0+"/wireguard-peer", map[string]any{"name": "office", "allowed-ips": []string{"10.99.0.5/32"}, "networks": []string{"192.168.50.0/24"}, "enabled": true})
	rec := env.do("GET", "/api/config/candidate/"+wg0+"/wireguard-peer=office?action=client-config", nil)
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
	_ = os.WriteFile(cfgFile, []byte("dry_run: true\ntoken_file: "+tokenFile+"\npaths:\n  etc_dir: "+dir+"/etc\n  state_dir: "+dir+"/state\n  run_dir: "+dir+"/run\n"), 0o600)
	acfg, err := agent.LoadConfig(cfgFile)
	if err != nil {
		t.Fatal(err)
	}
	ag := agent.New(acfg)
	defer ag.Stop()
	ts := httptest.NewTLSServer(ag.Handler())
	defer ts.Close()
	sum := sha256.Sum256(ts.Certificate().Raw)

	if rec := env.do("PUT", "/api/firewalls/1", map[string]any{
		"name": "firewall", "agent_url": ts.URL, "agent_token": token, "agent_fingerprint": hex.EncodeToString(sum[:]),
	}); rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), token) {
		t.Fatalf("firewall: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("PUT", "/api/settings", map[string]any{"confirm_timeout": 120}); rec.Code != http.StatusOK {
		t.Fatalf("settings: %d %s", rec.Code, rec.Body)
	}

	env.host("main")
	env.patch("instance=main", map[string]any{"dns-upstream": "root", "dhcp-enabled": true, "dhcp-domain-name": "home.arpa"})
	env.post("instance=main/interface", map[string]any{"kind": "physical", "name": "eth0", "ipv4-mode": "dhcp", "enabled": true})
	env.post("instance=main/interface", map[string]any{"kind": "physical", "name": "eth1", "enabled": true, "dns-listen": true, "addresses": []string{"192.168.1.1/24"}})
	env.post("instance=main/interface-zone", map[string]any{"name": "lan", "interfaces": []string{"eth1"}})
	env.post("instance=main/ipam-prefix", map[string]any{"prefix": "192.168.1.0/24", "dhcp-enabled": true, "dhcp-range-start": "192.168.1.100", "dhcp-range-end": "192.168.1.200"})
	env.post("instance=main/rule", map[string]any{"chain": "forward", "in-interfaces": []string{"lan"}, "out-interfaces": []string{"eth0"}, "action": "accept", "enabled": true})
	nat := env.post("instance=main/nat-rule", map[string]any{"kind": "masquerade", "out-interfaces": []string{"eth0"}, "enabled": true})

	// What the deploy would refuse is refused when saved.
	if rec := env.cfg("POST", "instance=main/ipam-prefix", map[string]any{"prefix": "10.5.0.0/24", "dhcp-enabled": true}); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "no interface has an address in it") {
		t.Fatalf("expected problems: %d %s", rec.Code, rec.Body)
	}

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
	env.patch("instance=main/nat-rule="+nat, map[string]any{"enabled": false})
	if got := changes(); !strings.Contains(got, `"changed":true`) {
		t.Errorf("changes after edit: %s", got)
	}
	env.patch("instance=main/nat-rule="+nat, map[string]any{"enabled": true})
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
	nDeployed := len(env.view().Rules)
	env.patch("instance=main/nat-rule="+nat, map[string]any{"enabled": false})
	env.post("instance=main/rule", map[string]any{"chain": "input", "action": "drop", "enabled": true})
	if got := changes(); !strings.Contains(got, `"changed":true`) {
		t.Errorf("changes before revert: %s", got)
	}
	if rec := env.do("POST", "/api/deploy/revert", map[string]any{}); rec.Code != http.StatusOK {
		t.Fatalf("revert: %d %s", rec.Code, rec.Body)
	}
	if got := changes(); !strings.Contains(got, `"changed":false`) {
		t.Errorf("changes after revert: %s", got)
	}
	if nRules := len(env.view().Rules); nRules != nDeployed {
		t.Errorf("rules after revert: %d, want %d", nRules, nDeployed)
	}
	if fw := firstFirewall(t, env); fw.AgentURL != ts.URL {
		t.Errorf("revert lost the agent settings: %+v", fw)
	}

	// A wrong pin must fail closed.
	env.do("PUT", "/api/firewalls/1", map[string]any{"name": "firewall", "agent_url": ts.URL, "agent_fingerprint": strings.Repeat("ab", 32)})
	if rec := env.do("GET", "/api/agent/status", nil); rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "fingerprint mismatch") {
		t.Errorf("wrong pin: %d %s", rec.Code, rec.Body)
	}
}

func TestAutoRules(t *testing.T) {
	env := newEnv(t)
	env.host("main")
	env.post("instance=main/interface", map[string]any{"name": "wan", "kind": "physical", "enabled": true, "ipv4-mode": "dhcp"})
	env.post("instance=main/interface", map[string]any{"name": "wg0", "kind": "wireguard", "enabled": true, "ipv4-mode": "none", "wg-listen-port": 51820})

	rec := env.do("GET", "/api/rules/auto?instance=main", nil)
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
	if want := "dhcp client [wan] 68|iperf3 server [] 0|wireguard wg0 [] 51820"; strings.Join(names, "|") != want {
		t.Errorf("got %q, want %q", strings.Join(names, "|"), want)
	}
	if rec := env.do("GET", "/api/rules/auto?instance=nope", nil); rec.Code != http.StatusNotFound {
		t.Errorf("unknown instance: %d", rec.Code)
	}
}

func TestAutoRulesAntiLockout(t *testing.T) {
	env := newEnv(t)
	if err := env.srv.ensureDefaultInstance(); err != nil {
		t.Fatal(err)
	}
	main := env.instanceRow("")
	env.vf("guest")
	fake := &statusAgent{antiLockout: &render.AntiLockout{Port: 8443, SSHPort: 22, AllowFrom: []string{"192.168.1.0/24"}}}
	env.srv.newAgent = func(*models.Firewall) (agentAPI, error) { return fake, nil }

	get := func(name string) string {
		t.Helper()
		rec := env.do("GET", "/api/rules/auto?instance="+name, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("auto rules: %d %s", rec.Code, rec.Body)
		}
		var got []render.AutoRule
		_ = json.Unmarshal(rec.Body.Bytes(), &got)
		var out []string
		for _, r := range got {
			if r.Service == render.IperfService { // every instance's
				continue
			}
			out = append(out, fmt.Sprintf("%s %s %d %v", r.Service, r.Protocol, r.DstPort, r.Source))
		}
		return strings.Join(out, "|")
	}
	if got, want := get(main.Name), "anti-lockout tcp 22 [192.168.1.0/24]|anti-lockout tcp 8443 [192.168.1.0/24]"; got != want {
		t.Errorf("default: got %q, want %q", got, want)
	}
	if got := get("guest"); got != "" {
		t.Errorf("anti-lockout belongs to the default instance only: %q", got)
	}
	fake.antiLockout = nil
	if got := get(main.Name); got != "" {
		t.Errorf("disabled: %q", got)
	}
}

func TestInterfaceZones(t *testing.T) {
	env := newEnv(t)
	env.host("main")
	env.vf("guest")
	env.put("instance=main/interface=eth0", map[string]any{"kind": "physical"})
	env.put("instance=main/interface=eth1", map[string]any{"kind": "physical"})
	env.put("link=up", map[string]any{"instance-a": "main", "interface-a": "lk-guest", "instance-b": "guest", "interface-b": "lk-main"})

	// Zero or more interfaces, link ends included; duplicates dropped.
	env.put("instance=main/interface-zone=empty", map[string]any{})
	env.put("instance=main/interface-zone=lan", map[string]any{"interfaces": []string{"eth1", "lk-guest", "eth1"}})
	if got := env.node("instance=main/interface-zone=lan").LeafLists["interfaces"]; strings.Join(got, " ") != "eth1 lk-guest" {
		t.Errorf("members %v", got)
	}
	if rec := env.cfg("PUT", "instance=main/interface-zone=eth0", map[string]any{}); rec.Code != http.StatusBadRequest {
		t.Errorf("zone named like an interface: %d", rec.Code)
	}
	if rec := env.cfg("PUT", "instance=main/interface=lan", map[string]any{"kind": "physical"}); rec.Code != http.StatusBadRequest {
		t.Errorf("interface named like a zone: %d", rec.Code)
	}
	if rec := env.cfg("PUT", "instance=main/interface-zone=x", map[string]any{"interfaces": []string{"lk-main"}}); rec.Code != http.StatusBadRequest {
		t.Errorf("other instance's link end accepted: %d", rec.Code)
	}

	rule := env.post("instance=main/rule", map[string]any{"chain": "forward", "action": "accept", "in-interfaces": []string{"lan", "eth0"}, "out-interfaces": []string{"lk-guest"}})
	nat := env.post("instance=main/nat-rule", map[string]any{"kind": "masquerade", "out-interfaces": []string{"eth0"}})
	if rec := env.cfg("POST", "instance=main/rule", map[string]any{"chain": "forward", "action": "accept", "in-interfaces": []string{"nope"}}); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown interface accepted: %d", rec.Code)
	}
	input := env.post("instance=main/rule", map[string]any{"chain": "input", "action": "accept", "in-interfaces": []string{"lan"}, "out-interfaces": []string{"eth0"}})
	if got := env.node("instance=main/rule=" + input).LeafLists["out-interfaces"]; len(got) != 0 {
		t.Errorf("input rule kept outgoing interfaces %v", got)
	}
	comment := env.post("instance=main/rule", map[string]any{"chain": "input", "kind": "comment", "description": " note ", "action": "drop", "in-interfaces": []string{"lan"}})
	if cm := env.node("instance=main/rule=" + comment); cm.Leaf("description") != "note" || cm.Leaves["action"] != "" || len(cm.LeafLists) != 0 {
		t.Errorf("comment row kept rule fields: %+v %v", cm.Leaves, cm.LeafLists)
	}
	group := env.post("instance=main/rule", map[string]any{"chain": "input", "kind": "group", "description": " Admin ", "action": "accept", "src-addrs": []string{"10.0.0.1"}})
	if gr := env.node("instance=main/rule=" + group); gr.Leaf("description") != "Admin" || gr.Leaves["action"] != "" || len(gr.LeafLists) != 0 {
		t.Errorf("group row kept rule fields: %+v %v", gr.Leaves, gr.LeafLists)
	}
	if rec := env.cfg("POST", "instance=main/rule", map[string]any{"chain": "input", "kind": "bogus", "action": "accept"}); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown rule kind accepted: %d", rec.Code)
	}

	// Renames follow into zones and rules.
	env.mustCfg("POST", "instance=main/interface=eth1?action=rename", map[string]any{"keys": []string{"eth9"}})
	env.mustCfg("POST", "instance=main/interface=eth0?action=rename", map[string]any{"keys": []string{"wan0"}})
	env.mustCfg("POST", "instance=main/interface-zone=lan?action=rename", map[string]any{"keys": []string{"inside"}})
	env.patch("link=up", map[string]any{"interface-a": "lk-g"})
	z := env.node("instance=main/interface-zone=inside").LeafLists["interfaces"]
	r, n := env.node("instance=main/rule="+rule), env.node("instance=main/nat-rule="+nat)
	if strings.Join(z, " ") != "eth9 lk-g" || strings.Join(r.LeafLists["in-interfaces"], " ") != "inside wan0" ||
		strings.Join(r.LeafLists["out-interfaces"], " ") != "lk-g" || strings.Join(n.LeafLists["out-interfaces"], " ") != "wan0" {
		t.Errorf("after rename: zone %v, rule %v -> %v, nat %v", z, r.LeafLists["in-interfaces"], r.LeafLists["out-interfaces"], n.LeafLists["out-interfaces"])
	}

	// In use: refused. Only a zone member: removed from the zone.
	if rec := env.cfg("DELETE", "instance=main/interface=wan0", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("delete interface in use: %d %s", rec.Code, rec.Body)
	}
	if rec := env.cfg("DELETE", "instance=main/interface-zone=inside", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("delete zone in use: %d", rec.Code)
	}
	if rec := env.cfg("DELETE", "link=up", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("delete link in use: %d", rec.Code)
	}
	env.mustCfg("DELETE", "instance=main/interface=eth9", nil)
	if z := env.node("instance=main/interface-zone=inside").LeafLists["interfaces"]; strings.Join(z, " ") != "lk-g" {
		t.Errorf("deleted interface left in zone: %v", z)
	}
	env.mustCfg("DELETE", "instance=main/interface-zone=empty", nil)
}

func TestAddressObjects(t *testing.T) {
	env := newEnv(t)
	env.host("main")
	env.put("host=nas", map[string]any{"addresses": []string{" 192.168.1.10 ", "fd00::10/128"}})
	env.put("host=lan", map[string]any{"addresses": []string{"192.168.1.0/24"}})
	if got := env.node("host=nas").LeafLists["addresses"]; strings.Join(got, " ") != "192.168.1.10 fd00::10" {
		t.Errorf("addresses not normalised: %v", got)
	}
	for _, body := range []map[string]any{
		{"name": "default", "addresses": []string{"10.0.0.1"}},
		{"name": "empty", "addresses": []string{}},
		{"name": "bad", "addresses": []string{"nas"}},
	} {
		if rec := env.cfg("POST", "host", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%v: %d %s", body, rec.Code, rec.Body)
		}
	}

	rule := env.post("instance=main/rule", map[string]any{"chain": "forward", "action": "accept", "dst-addrs": []string{"nas", "10.0.0.0/8"}})
	nat := env.post("instance=main/nat-rule", map[string]any{"kind": "dnat", "protocol": "tcp", "dst-ports": "443", "to-addr": "nas"})
	for path, body := range map[string]map[string]any{
		"instance=main/rule":     {"chain": "forward", "action": "accept", "src-addrs": []string{"ghost"}},
		"instance=main/nat-rule": {"kind": "dnat", "to-addr": "lan"},
		"instance=main/route":    {"destination": "default", "gateway": "lan"},
	} {
		if rec := env.cfg("POST", path, body); rec.Code != http.StatusBadRequest {
			t.Errorf("POST %s %v: %d %s", path, body, rec.Code, rec.Body)
		}
	}

	// In use: delete refused. Renamed: references follow.
	if rec := env.cfg("DELETE", "host=nas", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("delete in use: %d %s", rec.Code, rec.Body)
	}
	env.mustCfg("POST", "host=nas?action=rename", map[string]any{"keys": []string{"fileserver"}})
	if r, n := env.node("instance=main/rule="+rule), env.node("instance=main/nat-rule="+nat); strings.Join(r.LeafLists["dst-addrs"], " ") != "fileserver 10.0.0.0/8" || n.Leaf("to-addr") != "fileserver" {
		t.Errorf("references not renamed: %v %q", r.LeafLists["dst-addrs"], n.Leaf("to-addr"))
	}
}

func TestAddressLists(t *testing.T) {
	env := newEnv(t)
	env.host("main")
	env.put("host=nas", map[string]any{"addresses": []string{"192.168.1.10", "fd00::10"}})
	env.put("address-list=servers", map[string]any{"entries": []string{"nas", " 10.0.0.0/8 ", "192.168.1.11/32"}})
	env.put("address-list=all", map[string]any{"entries": []string{"servers", "198.51.100.1"}})
	if got := env.node("address-list=servers").LeafLists["entries"]; strings.Join(got, " ") != "nas 10.0.0.0/8 192.168.1.11" {
		t.Errorf("entries not normalised: %v", got)
	}
	for _, body := range []map[string]any{
		{"name": "nas", "entries": []string{"10.0.0.1"}},   // a host's name
		{"name": "empty", "entries": []string{}},           // nothing
		{"name": "ghost", "entries": []string{"nobody"}},   // unknown name
		{"name": "iplist", "entries": []string{"@drop"}},   // IP lists can't be in one
		{"name": "self", "entries": []string{"self"}},      // itself
		{"name": "bad", "entries": []string{"10.0.0.300"}}, // not an address
	} {
		if rec := env.cfg("POST", "address-list", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%v: %d %s", body, rec.Code, rec.Body)
		}
	}
	if rec := env.cfg("POST", "host", map[string]any{"name": "servers", "addresses": []string{"10.0.0.1"}}); rec.Code != http.StatusBadRequest {
		t.Errorf("host named like a list: %d %s", rec.Code, rec.Body)
	}
	// A loop through another list.
	if rec := env.cfg("PATCH", "address-list=servers", map[string]any{"entries": []string{"all"}}); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "contains itself") {
		t.Errorf("loop: %d %s", rec.Code, rec.Body)
	}

	rule := env.post("instance=main/rule", map[string]any{"chain": "forward", "action": "accept", "enabled": true, "src-addrs": []string{"all", "nas"}, "dst-addrs": []string{"servers"}})
	// Elsewhere a list is expanded: a route gateway needs one address per version.
	if rec := env.cfg("POST", "instance=main/route", map[string]any{"destination": "default", "gateway": "servers"}); rec.Code != http.StatusBadRequest {
		t.Errorf("list of prefixes as gateway: %d %s", rec.Code, rec.Body)
	}
	env.post("instance=main/nat-rule", map[string]any{"kind": "masquerade", "enabled": true, "src-addrs": []string{"servers"}})

	doc, err := builder.Build(env.input(), 1)
	if err != nil {
		t.Fatal(err)
	}
	in := doc.Instance("main")
	var got fwconfig.Rule
	for _, r := range in.Rules {
		if len(r.SrcAddrs) > 0 {
			got = r
		}
	}
	if strings.Join(got.SrcAddrs, " ") != "$all 192.168.1.10 fd00::10" || strings.Join(got.DstAddrs, " ") != "$servers" {
		t.Errorf("rule addresses: %v %v", got.SrcAddrs, got.DstAddrs)
	}
	if len(in.AddressSets) != 2 || in.AddressSets[0].Name != "all" ||
		strings.Join(in.AddressSets[0].Addresses, " ") != "192.168.1.10 fd00::10 10.0.0.0/8 192.168.1.11 198.51.100.1" {
		t.Errorf("address sets: %+v", in.AddressSets)
	}
	if len(in.NAT) != 1 || strings.Join(in.NAT[0].SrcAddrs, " ") != "192.168.1.10 fd00::10 10.0.0.0/8 192.168.1.11" {
		t.Errorf("NAT not expanded: %+v", in.NAT)
	}
	if err := doc.Validate(); err != nil {
		t.Errorf("validate: %v", err)
	}

	// In use: delete refused, for the list and the host in it. Renamed:
	// references follow, in rules and in other lists.
	for _, path := range []string{"address-list=servers", "host=nas"} {
		if rec := env.cfg("DELETE", path, nil); rec.Code != http.StatusBadRequest {
			t.Errorf("delete %s in use: %d %s", path, rec.Code, rec.Body)
		}
	}
	env.mustCfg("POST", "address-list=servers?action=rename", map[string]any{"keys": []string{"srv"}})
	env.mustCfg("POST", "host=nas?action=rename", map[string]any{"keys": []string{"fileserver"}})
	r := env.node("instance=main/rule=" + rule)
	al, sl := env.node("address-list=all").LeafLists["entries"], env.node("address-list=srv").LeafLists["entries"]
	if strings.Join(r.LeafLists["dst-addrs"], " ") != "srv" || strings.Join(r.LeafLists["src-addrs"], " ") != "all fileserver" ||
		strings.Join(al, " ") != "srv 198.51.100.1" || strings.Join(sl, " ") != "fileserver 10.0.0.0/8 192.168.1.11" {
		t.Errorf("references not renamed: %v %v %v %v", r.LeafLists["src-addrs"], r.LeafLists["dst-addrs"], al, sl)
	}
}

func TestObjectFolders(t *testing.T) {
	env := newEnv(t)
	top := env.post("object-folder", map[string]any{"kind": "hosts", "name": " Servers "})
	sub := env.post("object-folder", map[string]any{"kind": "hosts", "name": "NAS", "parent": top})
	lists := env.post("object-folder", map[string]any{"kind": "ip_lists", "name": "Servers"})
	for _, body := range []map[string]any{
		{"kind": "hosts", "name": ""},
		{"kind": "rules", "name": "x"},
		{"kind": "hosts", "name": "Servers"},            // same name, same place
		{"kind": "hosts", "name": "x", "parent": lists}, // other kind
		{"kind": "ip_lists", "name": "x", "parent": "999999"},
	} {
		if rec := env.cfg("POST", "object-folder", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%v: %d %s", body, rec.Code, rec.Body)
		}
	}
	if rec := env.cfg("PATCH", "object-folder="+top, map[string]any{"parent": sub}); rec.Code != http.StatusBadRequest {
		t.Errorf("folder into its own subfolder: %d %s", rec.Code, rec.Body)
	}
	if rec := env.cfg("PATCH", "object-folder="+top, map[string]any{"kind": "ip_lists"}); rec.Code != http.StatusBadRequest {
		t.Errorf("kind changed: %d %s", rec.Code, rec.Body)
	}

	env.put("host=nas", map[string]any{"addresses": []string{"192.168.1.10"}, "folder": sub})
	if rec := env.cfg("POST", "host", map[string]any{"name": "x", "addresses": []string{"10.0.0.1"}, "folder": lists}); rec.Code != http.StatusBadRequest {
		t.Errorf("host in an IP list folder: %d %s", rec.Code, rec.Body)
	}
	if rec := env.cfg("POST", "ip-list", map[string]any{"name": "bl", "source": "url", "url": "https://example.com/bl.txt", "folder": top}); rec.Code != http.StatusBadRequest {
		t.Errorf("IP list in a host folder: %d %s", rec.Code, rec.Body)
	}
	env.post("ip-list", map[string]any{"name": "bl", "source": "url", "url": "https://example.com/bl.txt", "folder": lists})

	// Not empty: delete refused. Moved out: allowed.
	if rec := env.cfg("DELETE", "object-folder="+sub, nil); rec.Code != http.StatusBadRequest {
		t.Errorf("delete a folder in use: %d %s", rec.Code, rec.Body)
	}
	env.patch("host=nas", map[string]any{"folder": nil})
	env.mustCfg("DELETE", "object-folder="+sub, nil)
}

func TestCustomServices(t *testing.T) {
	env := newEnv(t)
	env.host("main")
	tcp := func(lo, hi int) map[string]any {
		return map[string]any{"protocol": "tcp", "dst-lo": lo, "dst-hi": hi, "src-lo": 0, "src-hi": 0}
	}
	env.post("service", map[string]any{"name": " UniFi ", "type": "tcp/udp/sctp", "description": "controller", "port": []any{tcp(8080, 0), tcp(8443, 0)}, "icmp-type": "echo-request", "ip-protocol": 6})
	env.post("service", map[string]any{"name": "unreach", "type": "icmp", "icmp-type": "destination-unreachable", "icmp-code": 4})
	if s := env.node("service=unifi"); s == nil || len(s.Lists["port"]) != 2 || s.Leaf("icmp-type") != "" || s.Leaf("ip-protocol") != "" {
		t.Errorf("not normalised: %+v", s)
	}
	for _, body := range []map[string]any{
		{"name": "ssh", "type": "tcp/udp/sctp", "port": []any{tcp(2222, 0)}},
		{"name": "SSH", "type": "tcp/udp/sctp", "port": []any{tcp(1, 0)}},
		{"name": "empty", "type": "tcp/udp/sctp"},
		{"name": "badrange", "type": "tcp/udp/sctp", "port": []any{tcp(9000, 8000)}},
		{"name": "badproto", "type": "tcp/udp/sctp", "port": []any{map[string]any{"protocol": "icmp", "dst-lo": 1, "dst-hi": 0, "src-lo": 0, "src-hi": 0}}},
		{"name": "badtype", "type": "tcp"},
		{"name": "v6type", "type": "icmp", "icmp-type": "nd-neighbor-solicit"},
		{"name": "codeonly", "type": "icmp6", "icmp-code": 1},
		{"name": "bignum", "type": "ip", "ip-protocol": 300},
	} {
		if rec := env.cfg("POST", "service", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%v: %d %s", body, rec.Code, rec.Body)
		}
	}

	rule := env.post("instance=main/rule", map[string]any{"chain": "forward", "action": "accept", "enabled": true, "services": []string{"ssh", "unifi", "unreach", "ssh"}})
	if rec := env.cfg("POST", "instance=main/rule", map[string]any{"chain": "forward", "action": "accept", "services": []string{"ghost"}}); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown service accepted: %d %s", rec.Code, rec.Body)
	}

	doc, _ := builder.Build(env.input(), 1)
	code := 4
	want := []fwconfig.ServiceMatch{
		{Protocol: "tcp", DstPorts: "22,8080,8443"},
		{Protocol: "icmp", ICMPType: "destination-unreachable", ICMPCode: &code},
	}
	var got []fwconfig.ServiceMatch
	for _, r := range doc.Instance("main").Rules {
		if r.Chain == "forward" {
			got = r.Services
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("not expanded: %+v", got)
	}

	// In use: delete refused. Renamed: references follow.
	if rec := env.cfg("DELETE", "service=unifi", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("delete in use: %d %s", rec.Code, rec.Body)
	}
	env.mustCfg("POST", "service=unifi?action=rename", map[string]any{"keys": []string{"controller"}})
	if got := env.node("instance=main/rule=" + rule).LeafLists["services"]; strings.Join(got, " ") != "ssh controller unreach" {
		t.Errorf("references not renamed: %v", got)
	}
}

func TestPortNames(t *testing.T) {
	env := newEnv(t)
	env.host("main")
	env.put("instance=main/interface=eth0", map[string]any{"kind": "physical", "enabled": true})
	env.post("port-name", map[string]any{"name": " Web ", "port": 8080})
	for _, body := range []map[string]any{
		{"name": "ssh", "port": 2222},
		{"name": "1bad", "port": 80},
		{"name": "zero", "port": 0},
		{"name": "big", "port": 70000},
		{"name": "web", "port": 81},
	} {
		if rec := env.cfg("POST", "port-name", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%v: %d %s", body, rec.Code, rec.Body)
		}
	}
	nat := env.post("instance=main/nat-rule", map[string]any{"kind": "dnat", "in-interfaces": []string{"eth0"}, "protocol": "tcp", "dst-ports": "WEB, https", "to-addr": "192.168.1.10", "enabled": true})
	if rec := env.cfg("POST", "instance=main/nat-rule", map[string]any{"kind": "dnat", "protocol": "tcp", "dst-ports": "ghost", "to-addr": "192.168.1.10"}); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown port name accepted: %d %s", rec.Code, rec.Body)
	}
	doc, _ := builder.Build(env.input(), 1)
	if got := doc.Instance("main").NAT[0].DstPorts; got != "8080, https" {
		t.Errorf("not resolved: %q", got)
	}
	if rec := env.cfg("DELETE", "port-name=web", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("delete in use: %d %s", rec.Code, rec.Body)
	}
	env.mustCfg("POST", "port-name=web?action=rename", map[string]any{"keys": []string{"proxy"}})
	if got := env.node("instance=main/nat-rule=" + nat).Leaf("dst-ports"); got != "proxy, https" {
		t.Errorf("references not renamed: %q", got)
	}
}

func TestIpv6PrefixChecks(t *testing.T) {
	env := newEnv(t)
	env.host("main")
	for _, body := range []map[string]any{
		{"prefix": "192.168.1.0/24", "ra-enabled": true},
		{"prefix": "fd00:2::/56", "ra-enabled": true, "ra-slaac": true},
		{"prefix": "fd00:3::/64", "dhcp-enabled": true},
		{"prefix": "fd00:4::/64", "ra-enabled": true, "dhcp-enabled": true, "dhcp-gateway": "fd00:4::1"},
	} {
		if rec := env.cfg("POST", "instance=main/ipam-prefix", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%v: %d %s", body, rec.Code, rec.Body)
		}
	}
	env.put("instance=main/interface=eth1", map[string]any{"kind": "physical", "enabled": true, "addresses": []string{"fd00:1::1/64"}})
	env.post("instance=main/ipam-prefix", map[string]any{"prefix": "fd00:1::/64", "ra-enabled": true, "ra-slaac": true, "dhcp-enabled": true, "dhcp-range-start": "fd00:1::1000", "dhcp-range-end": "fd00:1::1fff"})
	env.put("instance=main/dns-zone=home.arpa", map[string]any{})
	env.post("instance=main/ipam-address", map[string]any{"address": "fd00:1::10", "dns-name": "nas.home.arpa", "mac": "02:00:00:00:00:10"})
	// A MAC in the GUI's form is stored with colons.
	env.post("instance=main/ipam-address", map[string]any{"address": "fd00:1::11", "dns-name": "nas2.home.arpa", "mac": "0200.0000.00AB"})
	if m := env.node("instance=main/ipam-address=fd00:1::11").Leaf("mac"); m != "02:00:00:00:00:ab" {
		t.Errorf("dotted MAC: %q", m)
	}
}

func TestDnsTemplates(t *testing.T) {
	env := newEnv(t)
	env.host("main")
	env.put("instance=main/dns-soa-template=std", map[string]any{"mname": "NS1.example.com.", "rname": "hostmaster@example.com", "refresh": 86400, "retry": 7200, "expire": 3600000, "minimum": 3600})
	if s := env.node("instance=main/dns-soa-template=std"); s.Leaf("mname") != "ns1.example.com" || s.Leaf("rname") != "hostmaster.example.com" {
		t.Errorf("soa not normalised: %+v", s.Leaves)
	}
	env.put("instance=main/dnssec-policy=signed", map[string]any{"ksk-algorithm": "ed25519", "zsk-algorithm": "ed25519", "zsk-lifetime": "30d"})
	env.put("instance=main/dns-template=std", map[string]any{"soa-template": "std", "default-ttl": 3600, "dnssec-policy": "signed", "nameserver": []any{
		map[string]string{"name": "ns1.example.com.", "address": ""},
		map[string]string{"name": "NS2.example.com", "address": " 192.0.2.2"}, map[string]string{"name": "ns2.example.com", "address": "2001:DB8::2"}}})
	var names []string
	for _, n := range env.node("instance=main/dns-template=std").Lists["nameserver"] {
		names = append(names, n.Leaf("name")+"="+n.Leaf("address"))
	}
	if strings.Join(names, " ") != "ns1.example.com= ns2.example.com=192.0.2.2 ns2.example.com=2001:db8::2" {
		t.Errorf("nameservers not normalised: %v", names)
	}
	for path, body := range map[string]map[string]any{
		"instance=main/dns-soa-template=bad":  {"mname": "ns1.example.com", "rname": "x.example.com", "refresh": 1, "retry": 0, "expire": 1},
		"instance=main/dnssec-policy=default": {"ksk-algorithm": "ed25519", "zsk-algorithm": "ed25519"},
		"instance=main/dns-template=nons":     {"soa-template": "std", "default-ttl": 3600},
		"instance=main/dns-zone=example.com":  {"dns-template": "nope"},
		"instance=main/dns-template=badns":    {"soa-template": "std", "default-ttl": 3600, "nameserver": []any{map[string]string{"name": "ns1.example.com", "address": "ns1.example.com"}}},
	} {
		if rec := env.cfg("PUT", path, body); rec.Code != http.StatusBadRequest {
			t.Errorf("PUT %s %v: %d %s", path, body, rec.Code, rec.Body)
		}
	}
	env.put("instance=main/dns-zone=example.com", map[string]any{"dns-template": "std"})
	for _, path := range []string{"instance=main/dns-soa-template=std", "instance=main/dnssec-policy=signed", "instance=main/dns-template=std"} {
		if rec := env.cfg("DELETE", path, nil); rec.Code != http.StatusBadRequest {
			t.Errorf("DELETE %s in use: %d %s", path, rec.Code, rec.Body)
		}
	}
}

func TestZoneRecordsGrid(t *testing.T) {
	env := newEnv(t)
	env.host("main")
	env.patch("instance=main", map[string]any{"dns-upstream": "root"})
	env.put("instance=main/dns-zone=home.arpa", map[string]any{})
	if rec := env.cfg("PATCH", "instance=main/dns-zone=home.arpa", map[string]any{"type": "reverse4"}); rec.Code != http.StatusBadRequest {
		t.Errorf("zone type change: %d %s", rec.Code, rec.Body)
	}
	// The grid saves as a PUT of the zone's whole record list.
	path := "instance=main/dns-zone=home.arpa/record"

	grid := []map[string]any{
		{"type": "A", "name": "nas", "value": "192.168.1.10", "mac": "0200.0000.0010"},
		{"type": "COMMENT", "value": "lab hosts"},
		{"type": "$DOMAIN", "name": "lab.home.arpa."},
		{"type": "A", "name": "@", "value": "192.168.2.1"},
		{"type": "CNAME", "name": "www", "value": "nas.home.arpa."},
	}
	env.put(path, grid)
	rs := env.node("instance=main/dns-zone=home.arpa").Lists["record"]
	if len(rs) != 5 || rs[0].Leaf("mac") != "02:00:00:00:00:10" || rs[1].Leaf("type") != "COMMENT" || rs[2].Leaf("name") != "lab" || rs[4].Leaf("type") != "CNAME" {
		t.Fatalf("the candidate's records: %v", rs)
	}

	doc, _ := builder.Build(env.input(), 1)
	var names []string
	for _, r := range doc.Instance("main").DNS.Zones[0].Records {
		names = append(names, r.Name+"/"+r.Type)
	}
	if strings.Join(names, " ") != "nas/A lab/A www.lab/CNAME" {
		t.Errorf("built records: %v", names)
	}

	// The A records show up in the prefix tree, fully qualified.
	env.post("instance=main/ipam-prefix", map[string]any{"prefix": "192.168.0.0/16"})
	var tree []ipam.Node
	_ = json.Unmarshal(env.do("GET", "/api/ipam/tree?instance=main", nil).Body.Bytes(), &tree)
	var addrs []string
	for _, n := range tree[0].Children {
		addrs = append(addrs, n.CIDR+"="+n.DnsName)
	}
	if strings.Join(addrs, " ") != "192.168.1.10=nas.home.arpa 192.168.2.1=lab.home.arpa" {
		t.Errorf("tree addresses: %v", addrs)
	}

	// A bad row rejects the whole grid, naming the row; nothing changes.
	grid[3]["value"] = "fd00::1"
	if rec := env.cfg("PUT", path, grid); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "record[id=") {
		t.Errorf("bad grid: %d %s", rec.Code, rec.Body)
	}
	if rs := env.node("instance=main/dns-zone=home.arpa").Lists["record"]; len(rs) != 5 {
		t.Errorf("records after rejected save: %d", len(rs))
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
	got := env.view().Instances
	if len(got) != 1 || got[0].Name != DefaultInstanceName || !got[0].IsDefault || got[0].DhcpLeaseTime != 86400 {
		t.Errorf("instances: %+v", got)
	}
	rules := env.view().Rules
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

	if rec := env.do("GET", "/api/config/candidate/instance?shallow", nil); rec.Code != http.StatusOK {
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
		if got := rec.Code == http.StatusForbidden && strings.Contains(rec.Body.String(), "can't do this"); got != want {
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

	// An admin sets ann's password, which ends her sessions; not their own.
	if rec := env.do("POST", fmt.Sprintf("/api/users/%d/password", id), map[string]string{"password": "short"}); rec.Code != http.StatusBadRequest {
		t.Errorf("short password: %d", rec.Code)
	}
	if rec := env.do("POST", fmt.Sprintf("/api/users/%d/password", admin.ID), map[string]string{"password": "another long password"}); rec.Code != http.StatusBadRequest {
		t.Errorf("own password: %d", rec.Code)
	}
	if rec := env.do("POST", fmt.Sprintf("/api/users/%d/password", id), map[string]string{"password": "another long password"}); rec.Code != http.StatusNoContent {
		t.Fatalf("set password: %d %s", rec.Code, rec.Body)
	}
	var ann2 models.User
	env.srv.db.First(&ann2, id)
	if ann2.TokenVersion <= ann.TokenVersion || bcrypt.CompareHashAndPassword([]byte(ann2.PasswordHash), []byte("another long password")) != nil {
		t.Errorf("ann after reset: %+v", ann2)
	}
}

// An interface others use (a rule, a VLAN, a route) can't be deleted; one
// that is only a zone's member can, and leaves the zone.
func TestInterfaceInUse(t *testing.T) {
	env := newEnv(t)
	env.host("main")
	env.put("instance=main/interface=eth1", map[string]any{"kind": "physical", "addresses": []string{"10.9.9.1/24"}})
	env.put("instance=main/interface-zone=lan", map[string]any{"interfaces": []string{"eth1"}})
	env.put("instance=main/interface=eth1.10", map[string]any{"kind": "vlan", "parent": "eth1", "vlan-id": 10})
	route := env.post("instance=main/route", map[string]any{"destination": "10.9.0.0/16", "interface": "eth1"})
	rule := env.post("instance=main/rule", map[string]any{"chain": "forward", "action": "accept", "in-interfaces": []string{"eth1"}})
	for _, user := range []string{"instance=main/rule=" + rule, "instance=main/interface=eth1.10", "instance=main/route=" + route} {
		if rec := env.cfg("DELETE", "instance=main/interface=eth1", nil); rec.Code != http.StatusBadRequest {
			t.Fatalf("delete while used by %s: %d %s", user, rec.Code, rec.Body)
		}
		env.mustCfg("DELETE", user, nil)
	}
	env.mustCfg("DELETE", "instance=main/interface=eth1", nil)
	if z := env.node("instance=main/interface-zone=lan"); len(z.LeafLists["interfaces"]) != 0 {
		t.Errorf("zone after the delete: %v", z.LeafLists["interfaces"])
	}
}

func TestDnsFromDhcp(t *testing.T) {
	env := newEnv(t)
	env.host("main")
	env.put("instance=main/interface=eth0", map[string]any{"kind": "physical", "ipv4-mode": "dhcp", "dns-from-dhcp": true})
	env.put("instance=main/interface=eth1", map[string]any{"kind": "physical", "ipv4-mode": "dhcp"})
	env.put("instance=main/interface=eth2", map[string]any{"kind": "physical", "dns-from-dhcp": true})
	flag := func(name string) bool { return on(env.node("instance=main/interface="+name), "dns-from-dhcp") }
	if !flag("eth0") || flag("eth2") {
		t.Fatalf("a static interface can't give DNS from DHCP: eth0 %v, eth2 %v", flag("eth0"), flag("eth2"))
	}
	env.patch("instance=main", map[string]any{"dns-upstream": "dhcp"})
	// One per instance: taking the flag moves it.
	env.patch("instance=main/interface=eth1", map[string]any{"dns-from-dhcp": true})
	if flag("eth0") || !flag("eth1") {
		t.Errorf("after moving the flag: eth0 %v, eth1 %v", flag("eth0"), flag("eth1"))
	}
	if rec := env.cfg("PATCH", "instance=main", map[string]any{"dns-upstream": "peer"}); rec.Code != http.StatusBadRequest {
		t.Errorf("bad upstream: %d %s", rec.Code, rec.Body)
	}
	env.patch("instance=main", map[string]any{"dns-upstream": "forward", "dns-forwarders": []string{"9.9.9.9"}})
}

func TestInterfaceAddresses(t *testing.T) {
	env := newEnv(t)
	env.host("main")
	env.put("instance=main/interface=eth1", map[string]any{"kind": "physical", "addresses": []string{" 192.168.1.1/24 ", "fd00:1:0::1/64", "192.168.1.1/24", "10.0.0.0/31"}})
	if got := strings.Join(env.node("instance=main/interface=eth1").LeafLists["addresses"], " "); got != "192.168.1.1/24 fd00:1::1/64 10.0.0.0/31" {
		t.Errorf("addresses stored as %q, want canonical, without repeats", got)
	}
	for _, c := range []struct {
		body map[string]any
		want string
	}{
		{map[string]any{"addresses": []string{"192.168.2.0/24"}}, "network address"},
		{map[string]any{"addresses": []string{"fd00:2::/64"}}, "network address"},
		{map[string]any{"addresses": []string{"192.168.2.1"}}, "192.168.2.1"},
		{map[string]any{"addresses": []string{"192.168.1.1/25"}}, "192.168.1.1 is already on eth1"},
		{map[string]any{"ipv4-mode": "dhcp", "addresses": []string{"192.168.2.1/24"}}, "IPv4 comes from the DHCP client"},
	} {
		c.body["kind"] = "physical"
		if rec := env.cfg("PUT", "instance=main/interface=eth2", c.body); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), c.want) {
			t.Errorf("%v: %d %s, want %q", c.body, rec.Code, rec.Body, c.want)
		}
	}
	env.put("instance=main/interface=eth0", map[string]any{"kind": "physical", "ipv4-mode": "dhcp", "addresses": []string{"2001:db8::2/64"}})

	// The tree shows the interfaces' prefixes and addresses without IPAM
	// entries.
	tree := env.do("GET", "/api/ipam/tree?instance=main", nil).Body.String()
	for _, want := range []string{
		`"kind":"prefix","auto":true,"cidr":"192.168.1.0/24"`,
		`"kind":"address","auto":true,"cidr":"192.168.1.1","interface":"eth1"`,
		`"cidr":"2001:db8::/64"`,
		`"cidr":"fd00:1::/64"`,
	} {
		if !strings.Contains(tree, want) {
			t.Errorf("tree lacks %s:\n%s", want, tree)
		}
	}
	// Next free skips the interface's address.
	env.post("instance=main/ipam-prefix", map[string]any{"prefix": "192.168.1.0/24"})
	if got := env.do("GET", "/api/config/candidate/instance=main/ipam-prefix=192.168.1.0%2F24?action=next-free", nil).Body.String(); !strings.Contains(got, `"192.168.1.2"`) {
		t.Errorf("next free: %s", got)
	}
}

// DNS templates belong to a virtual firewall; the default one's may be
// global, used read-only by the others.
func TestDnsTemplatesGlobal(t *testing.T) {
	env := newEnv(t)
	if err := env.srv.ensureDefaultInstance(); err != nil {
		t.Fatal(err)
	}
	env.vf("other")
	soa := map[string]any{"mname": "ns1.example.com", "rname": "hostmaster.example.com",
		"refresh": 86400, "retry": 7200, "expire": 3600000, "minimum": 3600}
	tmpl := func(soa string) map[string]any {
		return map[string]any{"soa-template": soa, "default-ttl": 3600,
			"nameserver": []map[string]string{{"name": "ns1.example.com", "address": ""}}}
	}
	env.put("instance=main/dns-soa-template=local", soa)
	env.put("dns-soa-template=fw", soa)
	for what, c := range map[string]struct {
		path string
		body map[string]any
	}{
		"the firewall's name in a VF":         {"instance=other/dns-soa-template=fw", soa},
		"a VF's name for the firewall's":      {"dns-soa-template=local", soa},
		"the firewall's template, a VF's SOA": {"dns-template=t", tmpl("local")},
		"another VF's SOA":                    {"instance=other/dns-template=t", tmpl("local")},
	} {
		if rec := env.cfg("PUT", c.path, c.body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", what, rec.Code, rec.Body)
		}
	}
	// The same name in two VFs is fine; a VF's template may use the
	// firewall's SOA, and its zones the firewall's templates.
	env.put("instance=other/dns-soa-template=local", soa)
	env.put("dns-template=gt", tmpl("fw"))
	env.put("instance=other/dns-template=ot", tmpl("fw"))
	env.put("instance=other/dns-zone=example.com", map[string]any{"dns-template": "gt"})
	env.put("instance=other/dns-zone=example.org", map[string]any{"dns-template": "ot"})

	if rec := env.cfg("DELETE", "dns-template=gt", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("template used by a VF's zone deleted: %d %s", rec.Code, rec.Body)
	}
	// A rename follows into the VF.
	env.mustCfg("POST", "dns-template=gt?action=rename", map[string]any{"keys": []string{"std"}})
	if z := env.node("instance=other/dns-zone=example.com"); z.Leaf("dns-template") != "std" {
		t.Errorf("zone after the rename: %v", z.Leaves)
	}
	doc, err := builder.Build(env.input(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if dns := doc.Instance("other").DNS; dns.ZoneTemplate("std") == nil || dns.ZoneTemplate("ot") == nil || len(dns.SOATemplates) != 1 || dns.SOATemplates[0].Name != "fw" {
		t.Errorf("other's DNS: %+v %+v", dns.ZoneTemplates, dns.SOATemplates)
	}
	// Deleting a VF deletes its zones and templates.
	env.mustCfg("DELETE", "instance=other", nil)
}

// An admin sets a user's full name and email; a bad email is refused, and
// a body without them keeps them.
func TestUserNameEmail(t *testing.T) {
	env := newEnv(t)
	id := env.create("/api/users", map[string]string{"username": "ann", "full_name": "Ann Example", "email": "ann@example.com", "password": "a long password", "role": "viewer"})
	var u models.User
	env.srv.db.First(&u, id)
	if u.FullName != "Ann Example" || u.Email != "ann@example.com" {
		t.Errorf("created: %+v", u)
	}
	if rec := env.do("POST", "/api/users", map[string]string{"username": "bob", "email": "not an email", "password": "a long password"}); rec.Code != http.StatusBadRequest {
		t.Errorf("bad email on create: %d", rec.Code)
	}
	url := "/api/users/" + itoa(id)
	if rec := env.do("PUT", url, map[string]any{"role": "viewer", "email": "nope"}); rec.Code != http.StatusBadRequest {
		t.Errorf("bad email: %d", rec.Code)
	}
	if rec := env.do("PUT", url, map[string]any{"role": "viewer", "full_name": " Ann E. "}); rec.Code != http.StatusOK {
		t.Fatalf("update: %d %s", rec.Code, rec.Body)
	}
	env.srv.db.First(&u, id)
	if u.FullName != "Ann E." || u.Email != "ann@example.com" {
		t.Errorf("updated: %+v", u)
	}
}
