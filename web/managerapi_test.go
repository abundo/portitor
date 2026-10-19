// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abundo/portitor/models"
)

const testManagerToken = "manager-token-0123456789abcdef0123456789"

// localEnv is portitor-config: local mode with a manager token.
func localEnv(t *testing.T) *testEnv {
	t.Helper()
	env := newEnv(t)
	tok := filepath.Join(t.TempDir(), "manager.token")
	if err := os.WriteFile(tok, []byte(testManagerToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env.srv.cfg.Local, env.srv.cfg.ManagerTokenFile = true, tok
	env.e = env.srv.Echo()
	if err := env.srv.ensureDefaultInstance(); err != nil {
		t.Fatal(err)
	}
	return env
}

// manager calls the manager API.
func (env *testEnv) manager(method, path string, body any) *httptest.ResponseRecorder {
	env.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, "/manager/v1"+path, &buf)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testManagerToken)
	rec := httptest.NewRecorder()
	env.e.ServeHTTP(rec, req)
	return rec
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

func TestManagerAPI(t *testing.T) {
	hq := newEnv(t)
	richInstance(t, hq, "shop")
	fw := localEnv(t)

	// The token is required.
	req := httptest.NewRequest("GET", "/manager/v1/state", nil)
	rec := httptest.NewRecorder()
	fw.e.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("state without the token: %d", rec.Code)
	}

	// A local host of a name the manager pushes blocks the push.
	nas := fw.create("/api/objects", map[string]any{"name": "nas", "addresses": []string{"192.168.5.10"}})
	b := bundleOf(t, hq, "shop")
	if rec := fw.manager("PUT", "/instances/shop", map[string]any{"manager": "hq", "bundle": b}); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "nas") {
		t.Fatalf("push over a local host: %d %s", rec.Code, rec.Body)
	}
	fw.do("DELETE", "/api/objects/"+itoa(nas), nil)
	if rec := fw.manager("PUT", "/instances/shop", map[string]any{"manager": "hq", "bundle": b}); rec.Code != http.StatusOK {
		t.Fatalf("push: %d %s", rec.Code, rec.Body)
	}

	// Its hash here is the manager's.
	var st ManagedState
	_ = json.Unmarshal(fw.manager("GET", "/state", nil).Body.Bytes(), &st)
	want, _ := InstanceHash(hq.srv.db, "shop")
	found := false
	for _, in := range st.Instances {
		if in.Name == "shop" {
			found = true
			if in.Hash != want || in.ManagedBy != "hq" || in.Diverged {
				t.Errorf("state %+v, want hash %s", in, want)
			}
		}
	}
	if !found {
		t.Fatalf("state: %+v", st)
	}

	// Managed: read-only here, the instance, its rows and the shared
	// objects alike; managed_by can't be cleared through the API.
	shop := instanceID(t, fw, "shop")
	for _, c := range []struct {
		method, path string
		body         any
	}{
		{"POST", "/api/rules", map[string]any{"instance_id": shop, "chain": "input", "action": "drop", "enabled": true}},
		{"PUT", "/api/instances/" + itoa(shop), map[string]any{"description": "x", "managed_by": ""}},
		{"DELETE", "/api/instances/" + itoa(shop), nil},
	} {
		if rec := fw.do(c.method, c.path, c.body); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "managed by hq") {
			t.Errorf("%s %s: %d %s", c.method, c.path, rec.Code, rec.Body)
		}
	}
	var host models.AddressObject
	fw.srv.db.Where("name = ?", "nas").First(&host)
	if host.ManagedBy != "hq" {
		t.Errorf("pushed host %+v", host)
	}
	if rec := fw.do("PUT", "/api/objects/"+itoa(host.ID), map[string]any{"addresses": []string{"10.0.0.1"}}); rec.Code != http.StatusForbidden {
		t.Errorf("edit a pushed host: %d %s", rec.Code, rec.Body)
	}

	// A new version replaces it; the role's members stay.
	user := fw.create("/api/users", map[string]any{"username": "ops", "password": "another long password", "role": "none"})
	var role models.Role
	fw.srv.db.Where("instance_id = ?", shop).First(&role)
	fw.srv.db.Create(&models.RoleMember{RoleID: role.ID, UserID: user, Level: "admin"})
	hq.create("/api/rules", map[string]any{"instance_id": instanceID(t, hq, "shop"), "chain": "input", "action": "drop", "enabled": true})
	if rec := fw.manager("PUT", "/instances/shop", map[string]any{"manager": "hq", "bundle": bundleOf(t, hq, "shop")}); rec.Code != http.StatusOK {
		t.Fatalf("second push: %d %s", rec.Code, rec.Body)
	}
	if got, want := docOf(t, fw, "shop"), docOf(t, hq, "shop"); got != want {
		t.Errorf("after the second push:\n got %s\nwant %s", got, want)
	}
	var n int64
	fw.srv.db.Model(&models.RoleMember{}).Where("user_id = ? AND role_id IN (?)", user,
		fw.srv.db.Model(&models.Role{}).Select("id").Where("instance_id = ?", instanceID(t, fw, "shop"))).Count(&n)
	if n != 1 {
		t.Error("the role's member was lost")
	}

	// Break-glass: edited here, then a push needs overwrite.
	shop = instanceID(t, fw, "shop")
	if rec := fw.do("POST", "/api/instances/"+itoa(shop)+"/break-glass", nil); rec.Code != http.StatusOK {
		t.Fatalf("break-glass: %d %s", rec.Code, rec.Body)
	}
	if rec := fw.do("POST", "/api/rules", map[string]any{"instance_id": shop, "chain": "input", "action": "accept", "enabled": true}); rec.Code != http.StatusCreated {
		t.Errorf("edit after break-glass: %d %s", rec.Code, rec.Body)
	}
	b = bundleOf(t, hq, "shop")
	if rec := fw.manager("PUT", "/instances/shop", map[string]any{"manager": "hq", "bundle": b}); rec.Code != http.StatusConflict {
		t.Errorf("push over a diverged instance: %d %s", rec.Code, rec.Body)
	}
	if rec := fw.manager("PUT", "/instances/shop", map[string]any{"manager": "hq", "bundle": b, "overwrite": true}); rec.Code != http.StatusOK {
		t.Errorf("overwrite: %d %s", rec.Code, rec.Body)
	}
	// Another manager's, or the host, are not this one's.
	if rec := fw.manager("DELETE", "/instances/shop?manager=other", nil); rec.Code != http.StatusConflict {
		t.Errorf("delete by another manager: %d %s", rec.Code, rec.Body)
	}
	if rec := fw.manager("PUT", "/instances/main", map[string]any{"manager": "hq", "bundle": b}); rec.Code != http.StatusConflict {
		t.Errorf("push over the host: %d %s", rec.Code, rec.Body)
	}
	if rec := fw.manager("DELETE", "/instances/shop?manager=hq", nil); rec.Code != http.StatusNoContent {
		t.Errorf("delete: %d %s", rec.Code, rec.Body)
	}

	// Local mode deploys to its own firewall alone.
	if rec := fw.do("POST", "/api/firewalls", map[string]any{"name": "other"}); rec.Code != http.StatusBadRequest {
		t.Errorf("another firewall in local mode: %d %s", rec.Code, rec.Body)
	}
	// And the manager API is not there outside local mode.
	if rec := hq.manager("GET", "/state", nil); rec.Code != http.StatusNotFound {
		t.Errorf("manager API on a manager: %d", rec.Code)
	}
}

func TestManagerCommit(t *testing.T) {
	fw := localEnv(t)
	agent := &fleetAgent{}
	fw.srv.newAgent = func(*models.Firewall) (agentAPI, error) { return agent, nil }
	if rec := fw.manager("POST", "/commit", map[string]any{"manager": "hq", "confirm_timeout": 60}); rec.Code != http.StatusOK {
		t.Fatalf("commit: %d %s", rec.Code, rec.Body)
	}
	if rec := fw.manager("POST", "/confirm", nil); rec.Code != http.StatusOK || len(agent.confirmed) != 1 {
		t.Errorf("confirm: %d %s", rec.Code, rec.Body)
	}
}

// The console acts as an admin in-process; the API's checks still apply.
func TestConsoleRequest(t *testing.T) {
	fw := localEnv(t)
	hq := newEnv(t)
	richInstance(t, hq, "shop")
	fw.manager("PUT", "/instances/shop", map[string]any{"manager": "hq", "bundle": bundleOf(t, hq, "shop")})

	code, body := fw.srv.ConsoleRequest(context.Background(), "GET", "/api/settings", nil)
	if code != http.StatusOK {
		t.Errorf("console GET: %d %s", code, body)
	}
	// Not from the network.
	req := httptest.NewRequest("GET", "/api/settings", nil)
	rec := httptest.NewRecorder()
	fw.e.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("without a session: %d", rec.Code)
	}
	main := instanceID(t, fw, "main")
	code, body = fw.srv.ConsoleRequest(context.Background(), "PUT", "/api/instances/"+itoa(main), []byte(`{"description":"from the console"}`))
	if code != http.StatusOK {
		t.Errorf("console edit of the host: %d %s", code, body)
	}
	code, _ = fw.srv.ConsoleRequest(context.Background(), "PUT", "/api/instances/"+itoa(instanceID(t, fw, "shop")), []byte(`{"description":"x"}`))
	if code != http.StatusForbidden {
		t.Errorf("console edit of a managed one: %d", code)
	}
}
