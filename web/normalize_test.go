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
	env.host("main")
	if rec := env.cfg("POST", "instance=main/interface", map[string]any{"kind": "physical", "name": "eth0", "enabled": true, "mss-clamp": true, "mss-clamp-value": 100}); rec.Code != http.StatusBadRequest {
		t.Errorf("mss 100: %d %s", rec.Code, rec.Body)
	}
	env.post("instance=main/interface", map[string]any{"kind": "physical", "name": "eth0", "enabled": true, "mss-clamp": true, "mss-clamp-value": 1400, "rpf": true})
	// A value without clamping is dropped.
	env.post("instance=main/interface", map[string]any{"kind": "physical", "name": "eth1", "enabled": true, "mss-clamp-value": 1400})
	doc, err := builder.BuildFirewall(env.input(), 1, 1)
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
