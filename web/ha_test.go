// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/models"
)

// asHost makes the server portitor-config on the host of firewall id, its
// agent answering with pc.
func asHost(t *testing.T, env *testEnv, id uint, pc agentapi.HAPeerConfig) {
	t.Helper()
	env.srv.cfg.Local, env.srv.cfg.AgentURL = true, "https://127.0.0.1:8443"
	env.srv.localHA = func(context.Context) (*agentapi.HAPeerConfig, *models.Firewall, error) {
		var fw models.Firewall
		if err := env.srv.db.First(&fw, id).Error; err != nil {
			return nil, nil, err
		}
		out := pc
		return &out, &fw, nil
	}
	env.srv.checkRole(context.Background())
}

// Each host reaches its own agent at its agent_url and the other at the
// firewall's agent URL, from the same copy of the firewalls.
func TestAgentURL(t *testing.T) {
	env, _, pair := haPair(t)
	var prim, sec models.Firewall
	env.srv.db.First(&prim, 1)
	env.srv.db.First(&sec, pair)
	prim.AgentFingerprint, sec.AgentFingerprint = strings.Repeat("ab", 32), strings.Repeat("cd", 32)
	if u := env.srv.agentURL(&prim); u != "https://192.0.2.1:8443" {
		t.Errorf("not local: %s", u)
	}
	env.srv.cfg.Local, env.srv.cfg.AgentURL = true, "https://127.0.0.1:8443"
	env.srv.role.fingerprint = strings.Repeat("CD", 32)
	if u := env.srv.agentURL(&sec); u != "https://127.0.0.1:8443" {
		t.Errorf("own agent: %s", u)
	}
	if u := env.srv.agentURL(&prim); u != "https://192.0.2.1:8443" {
		t.Errorf("peer's agent: %s", u)
	}
}

// haPairConfigured is haPair with a LAN that has the secondary's address,
// a VRRP router with a priority for each, BGP with a router id for each,
// and committed to both.
func haPairConfigured(t *testing.T) (*testEnv, map[uint]*fleetAgent, uint) {
	t.Helper()
	env, agents, pair := haPair(t)
	main := instanceID(t, env, "main")
	env.create("/api/interfaces", map[string]any{"instance_id": main, "name": "lan", "kind": "bridge", "enabled": true,
		"ipv4_mode": "static", "addresses": []string{"10.0.0.1/24"}, "peer_addresses": []string{"10.0.0.2/24"}})
	env.create("/api/vrrp/routers", map[string]any{"instance_id": main, "interface": "lan", "vrid": 10, "enabled": true,
		"priority": 200, "peer_priority": 100, "ipv4": []string{"10.0.0.254"}})
	if rec := env.do("POST", "/api/deploy/apply", map[string]any{}); rec.Code != http.StatusOK {
		t.Fatalf("commit: %d %s", rec.Code, rec.Body)
	}
	return env, agents, pair
}

func TestPromote(t *testing.T) {
	env, agents, pair := haPairConfigured(t)
	asHost(t, env, pair, agentapi.HAPeerConfig{Node: fwconfig.HASecondary})
	if !env.srv.isReplica() {
		t.Fatal("the secondary's portitor-config is not a replica")
	}
	main := instanceID(t, env, "main")
	if rec := env.do("POST", "/api/rules", map[string]any{"instance_id": main, "chain": "input", "action": "drop", "enabled": true}); rec.Code != http.StatusConflict {
		t.Fatalf("a write on the replica: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("GET", "/api/me", nil); !strings.Contains(rec.Body.String(), `"replica":true`) {
		t.Errorf("me: %s", rec.Body)
	}
	var sec models.Firewall
	env.srv.db.First(&sec, pair)

	// The primary lost: promoted, the secondary commits as the primary.
	agents[1].down = true
	rec := env.do("POST", "/api/ha/promote", map[string]any{})
	if rec.Code != http.StatusOK {
		t.Fatalf("promote: %d %s", rec.Code, rec.Body)
	}
	if env.srv.isReplica() {
		t.Error("still a replica after the promotion")
	}
	var p, q models.Firewall
	env.srv.db.First(&p, pair)
	env.srv.db.First(&q, 1)
	if p.HAPrimaryID != nil || q.HAPrimaryID == nil || *q.HAPrimaryID != pair || q.HAEpoch != 1 || q.HASecret != sec.HASecret || p.HASecret != "" {
		t.Fatalf("after: %+v / %+v", p, q)
	}
	if p.AgentURL != "https://192.0.2.3:8443" || q.AgentURL != "https://192.0.2.1:8443" {
		t.Errorf("agent URLs: %s / %s", p.AgentURL, q.AgentURL)
	}
	var n int64
	env.srv.db.Model(&models.Instance{}).Where("firewall_id = ?", 1).Count(&n)
	if n != 0 {
		t.Errorf("%d instances left on the old primary", n)
	}
	var lan models.Interface
	env.srv.db.Where("name = ?", "lan").First(&lan)
	if !slices.Equal(lan.Addresses, models.StringList{"10.0.0.2/24"}) || !slices.Equal(lan.PeerAddresses, models.StringList{"10.0.0.1/24"}) {
		t.Errorf("lan swapped: %v / %v", lan.Addresses, lan.PeerAddresses)
	}
	var vr models.VrrpRouter
	env.srv.db.First(&vr)
	if vr.Priority != 100 || vr.PeerPriority == nil || *vr.PeerPriority != 200 {
		t.Errorf("VRRP priorities: %d %v", vr.Priority, vr.PeerPriority)
	}
	// It runs as the primary at the next epoch, with its own address.
	doc := agents[pair].last()
	if doc.HA == nil || doc.HA.Node != fwconfig.HAPrimary || doc.HA.Epoch != 1 || doc.HA.Peer != "https://192.0.2.1:8443" {
		t.Fatalf("promoted host's HA: %+v", doc.HA)
	}
	in := doc.Instance("main")
	if a := in.Interfaces[slices.IndexFunc(in.Interfaces, func(i fwconfig.Interface) bool { return i.Name == "lan" })].Addresses; !slices.Equal(a, []string{"10.0.0.2/24"}) {
		t.Errorf("promoted host's lan: %v", a)
	}
	// The old primary is skipped, and caught up as the secondary with its
	// own address.
	var dep models.Deployment
	env.srv.db.Where("firewall_id = ?", 1).Order("id desc").First(&dep)
	if dep.Status != "skipped" {
		t.Fatalf("old primary's deployment: %s %s", dep.Status, dep.Message)
	}
	agents[1].down = false
	env.srv.catchUp(context.Background(), q)
	old := agents[1].last()
	if old.HA == nil || old.HA.Node != fwconfig.HASecondary || old.HA.Epoch != 1 {
		t.Fatalf("old primary caught up: %+v", old.HA)
	}
	in = old.Instance("main")
	if a := in.Interfaces[slices.IndexFunc(in.Interfaces, func(i fwconfig.Interface) bool { return i.Name == "lan" })].Addresses; !slices.Equal(a, []string{"10.0.0.1/24"}) {
		t.Errorf("old primary's lan: %v", a)
	}
	// Writes are the new primary's.
	if rec := env.do("POST", "/api/rules", map[string]any{"instance_id": main, "chain": "input", "action": "drop", "enabled": true}); rec.Code != http.StatusCreated {
		t.Errorf("a write after the promotion: %d %s", rec.Code, rec.Body)
	}
}

func TestPromoteRefused(t *testing.T) {
	env, _, pair := haPairConfigured(t)
	// Not a replica: nothing to promote.
	asHost(t, env, 1, agentapi.HAPeerConfig{Node: fwconfig.HAPrimary, PeerAlive: true})
	if rec := env.do("POST", "/api/ha/promote", map[string]any{}); rec.Code != http.StatusConflict {
		t.Errorf("promote the primary: %d %s", rec.Code, rec.Body)
	}
	// The primary heard: only with force.
	asHost(t, env, pair, agentapi.HAPeerConfig{Node: fwconfig.HASecondary, PeerAlive: true})
	if rec := env.do("POST", "/api/ha/promote", map[string]any{}); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "hears the primary") {
		t.Errorf("promote with the primary alive: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("POST", "/api/ha/promote", map[string]any{"force": true}); rec.Code != http.StatusOK {
		t.Errorf("promote by force: %d %s", rec.Code, rec.Body)
	}
}

func TestReplicaCopy(t *testing.T) {
	prim, _, pair := haPairConfigured(t)
	asHost(t, prim, 1, agentapi.HAPeerConfig{Node: fwconfig.HAPrimary})
	ts := httptest.NewTLSServer(prim.e)
	defer ts.Close()
	sum := sha256.Sum256(ts.Certificate().Raw)
	var sec models.Firewall
	prim.srv.db.First(&sec, pair)

	// A new secondary, with a database of its own before its first copy.
	rep := newEnv(t)
	if err := rep.srv.ensureDefaultInstance(); err != nil {
		t.Fatal(err)
	}
	peer := agentapi.HAPeerConfig{Node: fwconfig.HASecondary, URL: ts.URL, Fingerprint: hex.EncodeToString(sum[:]), Secret: "wrong" + sec.HASecret}
	asHost(t, rep, 1, peer)
	if err := rep.srv.copyPrimary(context.Background()); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("copy with a wrong secret: %v", err)
	}
	peer.Secret = sec.HASecret
	asHost(t, rep, 1, peer)
	if err := rep.srv.copyPrimary(context.Background()); err != nil {
		t.Fatalf("copy: %v", err)
	}
	var fws, lans int64
	rep.srv.db.Model(&models.Firewall{}).Where("name = ? AND ha_primary_id = 1", "fw1b").Count(&fws)
	rep.srv.db.Model(&models.Interface{}).Where("name = ?", "lan").Count(&lans)
	if fws != 1 || lans != 1 {
		t.Fatalf("the copy lacks the primary's configuration: %d %d", fws, lans)
	}
	if rep.srv.role.etag == "" {
		t.Error("no ETag kept")
	}
	// Unchanged, the next copy is not sent again.
	etag := rep.srv.role.etag
	if err := rep.srv.copyPrimary(context.Background()); err != nil || rep.srv.role.etag != etag {
		t.Errorf("second copy: %v", err)
	}
	// The primary's users log in on the replica.
	rec := rep.do("POST", "/api/login", map[string]string{"username": "admin", "password": "correct horse battery"})
	if rec.Code != http.StatusOK {
		t.Errorf("login on the replica: %d %s", rec.Code, rec.Body)
	}
	// A replica gives no copy.
	ts2 := httptest.NewTLSServer(rep.e)
	defer ts2.Close()
	req, _ := http.NewRequest(http.MethodGet, ts2.URL+replicaPath, nil)
	req.Header.Set("Authorization", "Bearer "+sec.HASecret)
	res, err := ts2.Client().Do(req)
	if err != nil || res.StatusCode != http.StatusConflict {
		t.Errorf("a copy from the replica: %v %v", res, err)
	}
}

func TestPortal(t *testing.T) {
	env := newEnv(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<html><head><title>x</title></head></html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	env.srv.static = os.DirFS(dir)
	env.e = env.srv.Echo()
	backend := httptest.NewServer(env.e)
	defer backend.Close()
	cfg := &PortalConfig{Firewalls: []PortalFirewall{{Name: "fw1", URL: backend.URL}, {Name: "fw2", URL: "http://127.0.0.1:1"}}}
	if err := cfg.check(); err != nil {
		t.Fatal(err)
	}
	p, err := NewPortal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	portal := httptest.NewServer(p.Handler())
	defer portal.Close()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	get := func(path string) *http.Response {
		t.Helper()
		res, err := client.Get(portal.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	body := func(res *http.Response) string {
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return string(b)
	}

	// The firewall's GUI, with its path as the base.
	if b := body(get("/fw/fw1/rules")); !strings.Contains(b, `<base href="/fw/fw1/">`) {
		t.Errorf("index through the portal: %s", b)
	}
	if res := get("/fw/fw1"); res.StatusCode != http.StatusFound || res.Header.Get("Location") != "/fw/fw1/" {
		t.Errorf("without the slash: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	if res := get("/fw/nope/"); res.StatusCode != http.StatusNotFound {
		t.Errorf("unknown firewall: %d", res.StatusCode)
	}
	if res := get("/fw/fw2/api/version"); res.StatusCode != http.StatusBadGateway {
		t.Errorf("unreachable firewall: %d", res.StatusCode)
	}
	// The login's cookie is kept to the firewall's path.
	res, err := client.Post(portal.URL+"/fw/fw1/api/login", "application/json",
		strings.NewReader(`{"username":"admin","password":"correct horse battery"}`))
	if err != nil {
		t.Fatal(err)
	}
	body(res)
	if c := res.Cookies(); res.StatusCode != http.StatusOK || len(c) == 0 || c[0].Path != "/fw/fw1/" {
		t.Fatalf("login through the portal: %d %v", res.StatusCode, c)
	}
	// The list has both; one of them does not answer.
	if b := body(get("/portal/")); !strings.Contains(b, `href="/fw/fw1/"`) || !strings.Contains(b, "does not answer") {
		t.Errorf("portal page: %s", b)
	}
	// / opens the first firewall, or the one opened last.
	if res := get("/"); res.StatusCode != http.StatusFound || res.Header.Get("Location") != "/fw/fw1/" {
		t.Errorf("/: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	req, _ := http.NewRequest("GET", portal.URL+"/", nil)
	req.AddCookie(&http.Cookie{Name: lastFirewallCookie, Value: "fw2"})
	if res, err := client.Do(req); err != nil || res.Header.Get("Location") != "/fw/fw2/" {
		t.Errorf("/ after fw2: %v %v", res, err)
	}
	if c := get("/fw/fw1/rules").Cookies(); len(c) == 0 || c[0].Name != lastFirewallCookie || c[0].Value != "fw1" {
		t.Errorf("the GUI's page does not remember its firewall: %v", c)
	}
	// Without its own address in X-Forwarded-For trusted, portitor-config
	// sees the portal's; with trusted_proxies, the browser's.
	env.srv.cfg.TrustedProxies = []string{"127.0.0.1"}
	env.e = env.srv.Echo()
	req = httptest.NewRequest("GET", "/api/version", nil)
	req.RemoteAddr = "127.0.0.1:5000"
	req.Header.Set("X-Forwarded-For", "198.51.100.7")
	ctx := env.e.NewContext(req, httptest.NewRecorder())
	if ip := ctx.RealIP(); ip != "198.51.100.7" {
		t.Errorf("real IP behind the portal: %s", ip)
	}
}

func TestPortalConfig(t *testing.T) {
	for _, c := range []struct {
		fw   PortalFirewall
		want string
	}{
		{PortalFirewall{Name: "-fw", URL: "https://a:1", Fingerprint: strings.Repeat("ab", 32)}, "name"},
		{PortalFirewall{Name: "fw", URL: "https://a:1"}, "fingerprint"},
		{PortalFirewall{Name: "FW1_a.lab", URL: "https://a:1"}, "fingerprint"},
		{PortalFirewall{Name: "fw", URL: "http://192.0.2.1:8444"}, "http:// only to this host"},
		{PortalFirewall{Name: "fw", URL: "https://a:1/path", Fingerprint: strings.Repeat("ab", 32)}, "url must be"},
	} {
		cfg := &PortalConfig{Firewalls: []PortalFirewall{c.fw}}
		if err := cfg.check(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: want %q, got %v", c.fw, c.want, err)
		}
	}
}

func TestWitnessString(t *testing.T) {
	env, agents, _ := haPairConfigured(t)
	if rec := env.do("GET", "/api/firewalls/1/witness", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("witness string of a local witness: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("PUT", "/api/firewalls/1", map[string]any{"ha_witness": "external"}); rec.Code != http.StatusOK {
		t.Fatalf("external witness: %d %s", rec.Code, rec.Body)
	}
	var fw models.Firewall
	env.srv.db.First(&fw, 1)
	if len(fw.HAWitnessSecret) < 32 {
		t.Fatal("no witness secret")
	}
	if rec := env.do("GET", "/api/firewalls", nil); strings.Contains(rec.Body.String(), fw.HAWitnessSecret) {
		t.Error("the witness secret is in the firewall list")
	}
	rec := env.do("GET", "/api/firewalls/1/witness", nil)
	var out struct {
		Witness string `json:"witness"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &out) != nil {
		t.Fatalf("witness string: %d %s", rec.Code, rec.Body)
	}
	w, err := ParseWitness(out.Witness)
	if err != nil || w.Secret != fw.HAWitnessSecret || len(w.Hosts) != 2 || w.Hosts[1].URL != "https://192.0.2.3:8443" {
		t.Fatalf("parsed: %+v %v", w, err)
	}
	if _, err := NewWitness([]string{out.Witness}); err != nil {
		t.Errorf("witness: %v", err)
	}
	// Committed, both hosts take the witness's secret; portitor-config
	// no longer votes.
	if rec := env.do("POST", "/api/deploy/apply", map[string]any{}); rec.Code != http.StatusOK {
		t.Fatalf("commit: %d %s", rec.Code, rec.Body)
	}
	if agents[1].last().HA.WitnessSecret != fw.HAWitnessSecret {
		t.Error("the primary's document lacks the witness secret")
	}
	var dep models.Deployment
	env.srv.db.Where("firewall_id = ?", 1).Order("id desc").First(&dep)
	if strings.Contains(dep.Document, fw.HAWitnessSecret) {
		t.Error("the witness secret is in the deployment history")
	}
}

// A promotion whose commit failed is still the promotion after a restart:
// the agent says secondary, the database primary.
func TestPromotedRestart(t *testing.T) {
	env, agents, pair := haPairConfigured(t)
	asHost(t, env, pair, agentapi.HAPeerConfig{Node: fwconfig.HASecondary})
	agents[1].down, agents[pair].fail = true, true
	if rec := env.do("POST", "/api/ha/promote", map[string]any{}); rec.Code == http.StatusOK {
		t.Fatalf("promote with the apply failing: %d %s", rec.Code, rec.Body)
	}
	// A new process: no memory of the promotion.
	env.srv.role = hostRole{}
	asHost(t, env, pair, agentapi.HAPeerConfig{Node: fwconfig.HASecondary})
	if env.srv.isReplica() {
		t.Error("a replica again after the restart")
	}
	// The old primary back, its agent stale: a replica of the new one,
	// though its database has it the primary.
	old := newEnv(t)
	if err := old.srv.ensureDefaultInstance(); err != nil {
		t.Fatal(err)
	}
	old.create("/api/firewalls", map[string]any{"name": "sec", "ha_primary_id": 1})
	asHost(t, old, 1, agentapi.HAPeerConfig{Node: fwconfig.HAPrimary, Stale: true})
	if !old.srv.isReplica() {
		t.Error("a taken-over primary is not a replica")
	}
}

func TestPairSession(t *testing.T) {
	env, _, pair := haPairConfigured(t)
	fpA, fpB, fpC := strings.Repeat("01", 32), strings.Repeat("02", 32), strings.Repeat("03", 32)
	for id, fp := range map[uint]string{1: fpA, pair: fpB} {
		if rec := env.do("PUT", "/api/firewalls/"+itoa(id), map[string]any{"config_url": "https://192.0.2.9:8444", "config_fingerprint": fp}); rec.Code != http.StatusOK {
			t.Fatalf("config url: %d %s", rec.Code, rec.Body)
		}
	}
	rec := env.do("POST", "/api/login", map[string]string{"username": "admin", "password": "correct horse battery"})
	if rec.Code != http.StatusOK {
		t.Fatalf("login: %d %s", rec.Code, rec.Body)
	}
	if h := rec.Header().Get(PairHeader); !strings.Contains(h, fpA) || !strings.Contains(h, fpB) {
		t.Errorf("pair header: %q", h)
	}
	cookies := (&http.Response{Header: rec.Header()}).Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies: %v", cookies)
	}
	// Signed with the pair's key, not jwt_secret: the other host, with a
	// jwt_secret of its own and a copy of the database, takes it.
	env.srv.jwtKey = []byte(strings.Repeat("x", 32))
	env.cookie = cookies[0]
	if rec := env.do("GET", "/api/me", nil); rec.Code != http.StatusOK {
		t.Errorf("the pair's session on the other host: %d %s", rec.Code, rec.Body)
	}

	// portitor-web sets it on both hosts' paths, not on another firewall's.
	p := &Portal{cfg: &PortalConfig{Firewalls: []PortalFirewall{{Name: "a", Fingerprint: fpA}, {Name: "b", Fingerprint: fpB}, {Name: "c", Fingerprint: fpC}}}}
	if got := p.pairPrefixes("a", []string{fpA, fpB}); strings.Join(got, " ") != "/fw/a /fw/b" {
		t.Errorf("pair paths: %v", got)
	}
	if got := p.pairPrefixes("c", []string{fpA, fpB}); strings.Join(got, " ") != "/fw/c" {
		t.Errorf("a firewall naming a pair it is not in: %v", got)
	}
	h := http.Header{}
	h.Add("Set-Cookie", "fw_session=v; Path=/; HttpOnly")
	portalCookies(h, []string{"/fw/a", "/fw/b"})
	var paths []string
	for _, c := range (&http.Response{Header: h}).Cookies() {
		paths = append(paths, c.Path)
	}
	if strings.Join(paths, " ") != "/fw/a/ /fw/b/" {
		t.Errorf("cookie paths: %v", paths)
	}
}
