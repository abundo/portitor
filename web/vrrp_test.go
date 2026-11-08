// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/abundo/portitor/internal/builder"
)

func TestVRRP(t *testing.T) {
	env := newEnv(t)
	env.host("main")
	env.put("instance=main/interface=eth1", map[string]any{"kind": "bridge", "enabled": true, "ipv4-mode": "static", "addresses": []string{"10.0.0.1/24", "fd00::1/64"}})
	env.put("instance=main/interface=wg0", map[string]any{"kind": "wireguard", "enabled": true, "ipv4-mode": "static", "addresses": []string{"10.9.0.1/24"}})

	// Addresses made canonical.
	env.mustCfg("POST", "instance=main/vrrp-router", map[string]any{"interface": "eth1", "vrid": 10, "preempt": true, "enabled": true, "ipv4": []string{" 10.0.0.254 "}, "ipv6": []string{"FD00::FE", "fe80::1"}})
	r := env.node("instance=main/vrrp-router=eth1,10")
	if r == nil || !slices.Equal(r.LeafLists["ipv4"], []string{"10.0.0.254"}) || !slices.Equal(r.LeafLists["ipv6"], []string{"fd00::fe", "fe80::1"}) {
		t.Fatalf("not normalised: %+v", r)
	}
	for what, body := range map[string]map[string]any{
		"unknown interface": {"interface": "eth9", "vrid": 1, "ipv4": []string{"10.0.0.2"}},
		"same vrid":         {"interface": "eth1", "vrid": 10, "ipv4": []string{"10.0.0.2"}},
		"not an address":    {"interface": "eth1", "vrid": 2, "ipv4": []string{"gateway"}},
	} {
		if rec := env.cfg("POST", "instance=main/vrrp-router", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s accepted: %d %s", what, rec.Code, rec.Body)
		}
	}
	// What the build refuses is a warning when saved, and the commit's error.
	for what, body := range map[string]map[string]any{
		"wireguard":       {"interface": "wg0", "vrid": 1, "ipv4": []string{"10.9.0.2"}},
		"no addresses":    {"interface": "eth1", "vrid": 2},
		"outside network": {"interface": "eth1", "vrid": 3, "ipv4": []string{"10.1.0.2"}},
		"v6 with v2":      {"interface": "eth1", "vrid": 4, "version": 2, "ipv6": []string{"fd00::2"}},
		"address in use":  {"interface": "eth1", "vrid": 5, "ipv4": []string{"10.0.0.254"}},
	} {
		rec := env.cfg("POST", "instance=main/vrrp-router", body)
		if rec.Code/100 == 2 && !strings.Contains(rec.Body.String(), "warnings") {
			t.Errorf("%s: no warning: %d %s", what, rec.Code, rec.Body)
		}
		if rec.Code/100 == 2 {
			env.mustCfg("DELETE", "instance=main/vrrp-router="+body["interface"].(string)+","+fmt.Sprint(body["vrid"]), nil)
		}
	}

	// Renaming the interface rewrites it; deleting it is refused while a
	// virtual router is on it.
	env.mustCfg("POST", "instance=main/interface=eth1?action=rename", map[string]any{"keys": []string{"lan"}})
	if env.node("instance=main/vrrp-router=lan,10") == nil {
		t.Error("not rewritten")
	}
	if rec := env.cfg("DELETE", "instance=main/interface=lan", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("delete interface: %d %s", rec.Code, rec.Body)
	}

	// The document has it, and it validates; disabled, it is shut down.
	doc, err := builder.Build(env.input(), 1)
	if err != nil {
		t.Fatal(err)
	}
	in := doc.Instance("main")
	if len(in.VRRP) != 1 || in.VRRP[0].Interface != "lan" || in.VRRP[0].VRID != 10 || in.VRRP[0].NoPreempt || in.VRRP[0].Shutdown || !in.FRRRunning() {
		t.Errorf("document: %+v", in.VRRP)
	}
	env.patch("instance=main/vrrp-router=lan,10", map[string]any{"enabled": false, "preempt": false})
	doc, _ = builder.Build(env.input(), 2)
	if in := doc.Instance("main"); len(in.VRRP) != 1 || !in.VRRP[0].Shutdown || !in.VRRP[0].NoPreempt {
		t.Errorf("disabled: %+v", in.VRRP)
	}
}
