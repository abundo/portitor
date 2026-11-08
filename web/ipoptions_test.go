// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"net/http"
	"slices"
	"testing"

	"github.com/abundo/portitor/internal/builder"
	"github.com/abundo/portitor/internal/fwconfig"
)

func TestDropIPOptionsSetting(t *testing.T) {
	env := newEnv(t)
	inst := env.create("/api/instances", map[string]any{"name": "main"})
	env.create("/api/interfaces", map[string]any{"instance_id": inst, "name": "eth0", "enabled": true})
	build := func() []string {
		t.Helper()
		doc, err := builder.BuildFirewall(tablesInput(t, env.srv.db), 1, 1)
		if err != nil {
			t.Fatal(err)
		}
		return doc.Instances[0].DropIPOptions
	}
	if got := build(); len(got) != 0 {
		t.Errorf("dropped by default: %v", got)
	}
	if rec := env.do("PUT", "/api/settings", map[string]any{"drop_ip_options_forward": true}); rec.Code != http.StatusOK {
		t.Fatalf("settings: %d %s", rec.Code, rec.Body)
	}
	if got := build(); !slices.Equal(got, []string{fwconfig.ChainForward}) {
		t.Errorf("forward only: %v", got)
	}
	if rec := env.do("PUT", "/api/settings", map[string]any{"drop_ip_options_input": true}); rec.Code != http.StatusOK {
		t.Fatalf("settings: %d %s", rec.Code, rec.Body)
	}
	if got := build(); !slices.Equal(got, []string{fwconfig.ChainInput, fwconfig.ChainForward}) {
		t.Errorf("both: %v", got)
	}
}
