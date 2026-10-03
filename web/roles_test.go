// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/abundo/portitor/models"
)

func (env *testEnv) roles() map[string]models.Role {
	env.t.Helper()
	var list []models.Role
	if err := json.Unmarshal(env.do("GET", "/api/roles", nil).Body.Bytes(), &list); err != nil {
		env.t.Fatal(err)
	}
	out := map[string]models.Role{}
	for _, r := range list {
		out[r.Name] = r
	}
	return out
}

// TestRoles checks roles and their members, and that each instance's role
// follows the instance.
func TestRoles(t *testing.T) {
	env := newEnv(t)
	ann := env.create("/api/users", map[string]string{"username": "ann", "password": "a long password", "role": "viewer"})

	env.create("/api/instances", map[string]any{"name": "main"}) // the default, which stays
	if _, ok := env.roles()["vf-main"]; ok {
		t.Fatal("the default instance has a role")
	}
	inst := env.create("/api/instances", map[string]any{"name": "lab"})
	r, ok := env.roles()["vf-lab"]
	if !ok || r.InstanceID == nil || *r.InstanceID != inst {
		t.Fatalf("instance role: %+v", env.roles())
	}
	members := []map[string]any{{"user_id": ann, "level": "admin"}}
	if rec := env.do("PUT", fmt.Sprintf("/api/roles/%d", r.ID), map[string]any{"name": "other", "members": members}); rec.Code != http.StatusOK {
		t.Fatalf("update instance role: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("DELETE", fmt.Sprintf("/api/roles/%d", r.ID), nil); rec.Code != http.StatusBadRequest {
		t.Errorf("delete instance role: %d", rec.Code)
	}
	if rec := env.do("PUT", fmt.Sprintf("/api/instances/%d", inst), map[string]any{"name": "lab2"}); rec.Code != http.StatusOK {
		t.Fatalf("rename instance: %d %s", rec.Code, rec.Body)
	}
	r = env.roles()["vf-lab2"]
	if r.ID == 0 || len(r.Members) != 1 || r.Members[0].Level != "admin" {
		t.Fatalf("renamed instance role: %+v", env.roles())
	}

	for _, body := range []map[string]any{
		{"name": ""},
		{"name": "vf-x"},
		{"name": "ops", "members": []map[string]any{{"user_id": ann, "level": "root"}}},
		{"name": "ops", "members": []map[string]any{{"user_id": 999, "level": "viewer"}}},
		{"name": "ops", "members": []map[string]any{{"user_id": ann, "level": "viewer"}, {"user_id": ann, "level": "admin"}}},
	} {
		if rec := env.do("POST", "/api/roles", body); rec.Code != http.StatusBadRequest {
			t.Errorf("POST %v: %d %s", body, rec.Code, rec.Body)
		}
	}
	ops := env.create("/api/roles", map[string]any{"name": "ops", "members": []map[string]any{{"user_id": ann, "level": "viewer"}}})
	if rec := env.do("POST", "/api/roles", map[string]any{"name": "ops"}); rec.Code != http.StatusConflict {
		t.Errorf("duplicate name: %d", rec.Code)
	}

	// Deleting the user drops their memberships; deleting the instance its role.
	if rec := env.do("DELETE", fmt.Sprintf("/api/users/%d", ann), nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete user: %d", rec.Code)
	}
	if n := len(env.roles()["ops"].Members); n != 0 {
		t.Errorf("ops members after user delete: %d", n)
	}
	if rec := env.do("DELETE", fmt.Sprintf("/api/instances/%d", inst), nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete instance: %d %s", rec.Code, rec.Body)
	}
	if _, ok := env.roles()["vf-lab2"]; ok {
		t.Error("instance role left after delete")
	}
	if rec := env.do("DELETE", fmt.Sprintf("/api/roles/%d", ops), nil); rec.Code != http.StatusNoContent {
		t.Errorf("delete role: %d", rec.Code)
	}
}
