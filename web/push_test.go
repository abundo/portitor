// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/abundo/portitor/models"
)

// envConfig is a portitor-config test server as its manager's configAPI.
type envConfig struct{ env *testEnv }

func (e envConfig) call(method, path string, body, out any) error {
	rec := e.env.manager(method, path, body)
	if rec.Code/100 != 2 {
		var m struct {
			Error    string   `json:"error"`
			Problems []string `json:"problems"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &m)
		return &configError{status: rec.Code, msg: m.Error, problems: m.Problems}
	}
	if out != nil {
		return json.Unmarshal(rec.Body.Bytes(), out)
	}
	return nil
}

func (e envConfig) State(context.Context) (*ManagedState, error) {
	var st ManagedState
	return &st, e.call("GET", "/state", nil, &st)
}
func (e envConfig) Bundle(_ context.Context, name string) (*Bundle, error) {
	var b Bundle
	return &b, e.call("GET", "/instances/"+name+"/bundle", nil, &b)
}
func (e envConfig) Push(_ context.Context, name, manager string, overwrite bool, b *Bundle) ([]string, error) {
	return nil, e.call("PUT", "/instances/"+name, map[string]any{"manager": manager, "overwrite": overwrite, "bundle": b}, nil)
}
func (e envConfig) Delete(_ context.Context, name, manager string) error {
	return e.call("DELETE", "/instances/"+name+"?manager="+url.QueryEscape(manager), nil, nil)
}
func (e envConfig) PushUsers(_ context.Context, u *ManagedUsers) ([]string, error) {
	var out struct {
		Skipped []string `json:"skipped"`
	}
	return out.Skipped, e.call("PUT", "/users", u, &out)
}
func (e envConfig) Commit(_ context.Context, manager string, confirm int) (*commitResult, error) {
	var res commitResult
	return &res, e.call("POST", "/commit", map[string]any{"manager": manager, "confirm_timeout": confirm}, &res)
}
func (e envConfig) Confirm(context.Context) error {
	return e.call("POST", "/confirm", map[string]any{}, nil)
}
func (e envConfig) Rollback(context.Context) error {
	return e.call("POST", "/rollback", map[string]any{}, nil)
}

func TestManagedFirewall(t *testing.T) {
	hq := newEnv(t)
	hq.srv.cfg.ManagerName = "hq"
	richInstance(t, hq, "shop")
	fw := localEnv(t)
	agent := &fleetAgent{}
	fw.srv.newAgent = func(*models.Firewall) (agentAPI, error) { return agent, nil }
	hq.srv.newConfig = func(*models.Firewall) (configAPI, error) { return envConfig{fw}, nil }
	hq.srv.newAgent = func(*models.Firewall) (agentAPI, error) {
		t.Error("the manager called the agent of a firewall with portitor-config")
		return agent, nil
	}
	hq.do("PUT", "/api/firewalls/1", map[string]any{"name": "firewall", "config_url": "https://192.0.2.1:8444", "config_token": "x"})
	// Deployed to its agent before, at a generation portitor-config's
	// own count starts below.
	hq.srv.db.Create(&models.Deployment{FirewallID: 1, CommitID: 1, Generation: 500, Status: "confirmed", Instances: models.StringList{}})
	hq.srv.db.Model(&models.Settings{}).Where("id = 1").Update("last_commit", 1)

	// A commit pushes the virtual firewall and commits there.
	rec := hq.do("POST", "/api/deploy/apply", map[string]any{"confirm_timeout": 60})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"pending"`) {
		t.Fatalf("commit: %d %s", rec.Code, rec.Body)
	}
	if got, want := docOf(t, fw, "shop"), docOf(t, hq, "shop"); got != want {
		t.Errorf("pushed configuration differs:\n got %s\nwant %s", got, want)
	}
	if doc := agent.last(); doc == nil || doc.Instance("shop") == nil {
		t.Fatal("the firewall's agent did not get shop")
	}
	if rec := hq.do("POST", "/api/deploy/confirm", map[string]any{}); rec.Code != http.StatusOK || len(agent.confirmed) != 1 {
		t.Fatalf("confirm: %d %s", rec.Code, rec.Body)
	}
	drift := func() map[string]string {
		var items []driftItem
		_ = json.Unmarshal(hq.do("GET", "/api/firewalls/1/drift", nil).Body.Bytes(), &items)
		out := map[string]string{}
		for _, it := range items {
			out[it.Name] = it.State
		}
		return out
	}
	if d := drift(); d["shop"] != driftSame {
		t.Errorf("drift after commit: %v", d)
	}

	// Changed on the firewall (break-glass) and here: the commit stops
	// until it is settled; taking the firewall's version settles it.
	shopThere := instanceID(t, fw, "shop")
	fw.do("POST", "/api/instances/"+itoa(shopThere)+"/break-glass", nil)
	fw.create("/api/rules", map[string]any{"instance_id": shopThere, "chain": "input", "action": "drop", "enabled": true, "description": "local fix"})
	hq.create("/api/rules", map[string]any{"instance_id": instanceID(t, hq, "shop"), "chain": "input", "action": "accept", "enabled": true})
	if d := drift(); d["shop"] != driftThere {
		t.Errorf("drift after break-glass: %v", d)
	}
	if rec := hq.do("POST", "/api/deploy/apply", map[string]any{"confirm_timeout": 0}); rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "break-glass") {
		t.Errorf("commit over a diverged one: %d %s", rec.Code, rec.Body)
	}
	if rec := hq.do("POST", "/api/firewalls/1/drift/shop", map[string]any{"action": "take"}); rec.Code != http.StatusOK {
		t.Fatalf("take: %d %s", rec.Code, rec.Body)
	}
	if d := drift(); d["shop"] != driftSame {
		t.Errorf("drift after take: %v", d)
	}
	var fix int64
	hq.srv.db.Model(&models.Rule{}).Where("description = ?", "local fix").Count(&fix)
	if fix != 1 {
		t.Error("the firewall's fix was not taken")
	}

	// Deleted here: deleted there at the next commit.
	hq.do("DELETE", "/api/instances/"+itoa(instanceID(t, hq, "shop")), nil)
	if d := drift(); d["shop"] != driftGone {
		t.Errorf("drift after delete: %v", d)
	}
	if rec := hq.do("POST", "/api/deploy/apply", map[string]any{"confirm_timeout": 0}); rec.Code != http.StatusOK {
		t.Fatalf("commit after delete: %d %s", rec.Code, rec.Body)
	}
	var n int64
	fw.srv.db.Model(&models.Instance{}).Where("name = ?", "shop").Count(&n)
	if n != 0 {
		t.Error("shop is still on the firewall")
	}
}

// On a manager, the host of a firewall with portitor-config is read-only.
func TestManagedHostReadOnly(t *testing.T) {
	hq := newEnv(t)
	if err := hq.srv.ensureDefaultInstance(); err != nil {
		t.Fatal(err)
	}
	main := instanceID(t, hq, "main")
	if rec := hq.do("POST", "/api/rules", map[string]any{"instance_id": main, "chain": "input", "action": "drop", "enabled": true}); rec.Code != http.StatusCreated {
		t.Fatalf("rule before: %d %s", rec.Code, rec.Body)
	}
	hq.do("PUT", "/api/firewalls/1", map[string]any{"name": "firewall", "config_url": "https://192.0.2.1:8444"})
	rec := hq.do("POST", "/api/rules", map[string]any{"instance_id": main, "chain": "input", "action": "drop", "enabled": true})
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "portitor-config owns") {
		t.Errorf("rule on the host after: %d %s", rec.Code, rec.Body)
	}
}

// Users go with the virtual firewalls: the manager's, with their
// memberships, managed there; local ones stay.
func TestManagedUsers(t *testing.T) {
	hq := newEnv(t)
	hq.srv.cfg.ManagerName = "hq"
	shop := richInstance(t, hq, "shop")
	fw := localEnv(t)
	agent := &fleetAgent{}
	fw.srv.newAgent = func(*models.Firewall) (agentAPI, error) { return agent, nil }
	hq.srv.newConfig = func(*models.Firewall) (configAPI, error) { return envConfig{fw}, nil }
	hq.do("PUT", "/api/firewalls/1", map[string]any{"name": "firewall", "config_url": "https://192.0.2.1:8444"})
	ops := hq.create("/api/users", map[string]any{"username": "ops", "password": "another long password", "role": "none"})
	var role models.Role
	hq.srv.db.Where("instance_id = ?", shop).First(&role)
	hq.srv.db.Create(&models.RoleMember{RoleID: role.ID, UserID: ops, Level: "admin"})
	// A local user of a name the manager has stays local.
	fw.create("/api/users", map[string]any{"username": "clash", "password": "another long password", "role": "viewer"})
	hq.create("/api/users", map[string]any{"username": "clash", "password": "yet another long password", "role": "admin"})

	if rec := hq.do("POST", "/api/deploy/apply", map[string]any{"confirm_timeout": 0}); rec.Code != http.StatusOK {
		t.Fatalf("commit: %d %s", rec.Code, rec.Body)
	}
	var u models.User
	if err := fw.srv.db.Where("username = ?", "ops").First(&u).Error; err != nil || u.ManagedBy != "hq" {
		t.Fatalf("ops there: %+v %v", u, err)
	}
	var n int64
	fw.srv.db.Model(&models.RoleMember{}).Where("user_id = ? AND level = 'admin' AND role_id IN (?)", u.ID,
		fw.srv.db.Model(&models.Role{}).Select("id").Where("instance_id = ?", instanceID(t, fw, "shop"))).Count(&n)
	if n != 1 {
		t.Error("ops is not an admin of shop there")
	}
	var clash models.User
	fw.srv.db.Where("username = ?", "clash").First(&clash)
	if clash.ManagedBy != "" || clash.Role != "viewer" {
		t.Errorf("the local clash was replaced: %+v", clash)
	}
	// Changed there only.
	if rec := fw.do("POST", "/api/users/"+itoa(u.ID)+"/password", map[string]any{"password": "a local long password"}); rec.Code != http.StatusForbidden {
		t.Errorf("password of a managed user: %d %s", rec.Code, rec.Body)
	}
	// Gone on the manager: gone there at the next commit.
	hq.do("DELETE", "/api/users/"+itoa(ops), nil)
	if rec := hq.do("POST", "/api/deploy/apply", map[string]any{"confirm_timeout": 0}); rec.Code != http.StatusOK {
		t.Fatalf("second commit: %d %s", rec.Code, rec.Body)
	}
	fw.srv.db.Model(&models.User{}).Where("username = ?", "ops").Count(&n)
	if n != 0 {
		t.Error("ops is still there")
	}
}
