// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"net/http"
	"testing"

	"github.com/abundo/portitor/internal/builder"
)

func TestBFD(t *testing.T) {
	env := newEnv(t)
	env.host("main")
	env.put("instance=main/interface=eth1", map[string]any{"kind": "physical", "enabled": true, "ipv4-mode": "static", "addresses": []string{"10.0.0.1/24"}})

	// Timers left empty are the virtual firewall's defaults.
	env.put("instance=main/bfd-interface=eth1", map[string]any{"enabled": true, "receive-interval": 100})
	if rec := env.cfg("PATCH", "instance=main", map[string]any{"bfd-detect-multiplier": 1}); rec.Code != http.StatusBadRequest {
		t.Errorf("default multiplier 1 accepted: %d %s", rec.Code, rec.Body)
	}
	env.patch("instance=main", map[string]any{"bfd-detect-multiplier": 5, "bfd-receive-interval": 200, "bfd-transmit-interval": 250})
	if rec := env.cfg("POST", "instance=main/bfd-interface", map[string]any{"interface": "eth1"}); rec.Code != http.StatusBadRequest {
		t.Errorf("twice accepted: %d %s", rec.Code, rec.Body)
	}
	if rec := env.cfg("POST", "instance=main/bfd-interface", map[string]any{"interface": "eth9"}); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown interface accepted: %d %s", rec.Code, rec.Body)
	}
	// A route with BFD needs a gateway.
	if rec := env.cfg("POST", "instance=main/route", map[string]any{"destination": "10.1.0.0/16", "interface": "eth1", "bfd": true}); rec.Code != http.StatusBadRequest {
		t.Errorf("BFD route without gateway: %d %s", rec.Code, rec.Body)
	}
	route := env.post("instance=main/route", map[string]any{"destination": "10.1.0.0/16", "gateway": "10.0.0.2", "bfd": true})

	// The document has it, and the route is FRR's.
	doc, err := builder.Build(env.input(), 1)
	if err != nil {
		t.Fatal(err)
	}
	exp := doc.Expand()
	in := exp.Instance("main")
	if len(in.BFD) != 1 || in.BFD[0].Name != "eth1" || !in.HasBFDRoutes() || !in.FRRRunning() {
		t.Errorf("document: %+v %+v", in.BFD, in.Routes)
	}
	if bi := in.BFD[0]; bi.DetectMultiplier != 5 || bi.ReceiveInterval != 100 || bi.TransmitInterval != 250 {
		t.Errorf("timers: %+v", bi)
	}

	// Renaming the interface rewrites it; disabled, it is left out.
	env.mustCfg("POST", "instance=main/interface=eth1?action=rename", map[string]any{"keys": []string{"lan"}})
	if env.node("instance=main/bfd-interface=lan") == nil {
		t.Error("not rewritten")
	}
	env.patch("instance=main/bfd-interface=lan", map[string]any{"enabled": false})
	doc, _ = builder.Build(env.input(), 2)
	if in := doc.Instance("main"); len(in.BFD) != 0 || len(in.KernelRoutes()) != 1 {
		t.Errorf("disabled: %+v", in.BFD)
	}
	env.mustCfg("DELETE", "instance=main/route="+route, nil)
}
