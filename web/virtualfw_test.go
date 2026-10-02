// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"net/http"
	"testing"

	"github.com/abundo/portitor/models"
)

// TestVirtualFirewallsSetting: off allows only one instance; it can't be
// turned off while there are more.
func TestVirtualFirewallsSetting(t *testing.T) {
	env := newEnv(t)
	env.srv.db.Model(&models.Settings{}).Where("id = 1").Update("virtual_firewalls", false)
	if rec := env.do("POST", "/api/instances", map[string]any{"name": "one"}); rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
		t.Fatalf("first instance: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("POST", "/api/instances", map[string]any{"name": "two"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("second instance while off: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("PUT", "/api/settings", map[string]any{"virtual_firewalls": true}); rec.Code != http.StatusOK {
		t.Fatalf("turn on: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("POST", "/api/instances", map[string]any{"name": "two"}); rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
		t.Fatalf("second instance: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("PUT", "/api/settings", map[string]any{"virtual_firewalls": false}); rec.Code != http.StatusBadRequest {
		t.Fatalf("turn off with two: %d %s", rec.Code, rec.Body)
	}
}
