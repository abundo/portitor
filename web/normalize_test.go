// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"net/http"
	"testing"

	"github.com/abundo/portitor/internal/builder"
)

func TestInterfaceNormalize(t *testing.T) {
	env := newEnv(t)
	inst := env.create("/api/instances", map[string]any{"name": "main"})
	if rec := env.do("POST", "/api/interfaces", map[string]any{"instance_id": inst, "name": "eth0", "enabled": true,
		"mss_clamp": true, "mss_clamp_value": 100}); rec.Code != http.StatusBadRequest {
		t.Errorf("mss 100: %d %s", rec.Code, rec.Body)
	}
	env.create("/api/interfaces", map[string]any{"instance_id": inst, "name": "eth0", "enabled": true,
		"mss_clamp": true, "mss_clamp_value": 1400, "rpf": true})
	// A value without clamping is dropped.
	env.create("/api/interfaces", map[string]any{"instance_id": inst, "name": "eth1", "enabled": true,
		"mss_clamp_value": 1400})
	doc, err := builder.BuildFirewall(tablesInput(t, env.srv.db), 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	in := doc.Instances[0]
	if ifc := in.Interface("eth0"); ifc == nil || !ifc.MSSClamp || ifc.MSSClampValue != 1400 || !ifc.RPF {
		t.Errorf("eth0: %+v", ifc)
	}
	if ifc := in.Interface("eth1"); ifc == nil || ifc.MSSClamp || ifc.MSSClampValue != 0 || ifc.RPF {
		t.Errorf("eth1: %+v", ifc)
	}
	if err := doc.Validate(); err != nil {
		t.Error(err)
	}
}
