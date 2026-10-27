// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"net/http"
	"testing"

	"github.com/abundo/portitor/internal/builder"
)

func TestRuleSynProxy(t *testing.T) {
	env := newEnv(t)
	inst := env.create("/api/instances", map[string]any{"name": "main"})
	env.create("/api/interfaces", map[string]any{"instance_id": inst, "name": "eth0", "enabled": true})
	env.create("/api/interfaces", map[string]any{"instance_id": inst, "name": "eth1", "enabled": true})
	env.create("/api/rate-limits", map[string]any{"instance_id": inst, "name": "ssh", "rate": 4, "per": "minute"})
	rule := func(extra map[string]any) map[string]any {
		body := map[string]any{"instance_id": inst, "chain": "forward", "action": "accept", "in_interfaces": []string{"eth0"},
			"dst_addrs": []string{"192.168.1.10"}, "services": []string{"https"}, "syn_proxy": true, "syn_proxy_wscale": 7, "enabled": true}
		for k, v := range extra {
			body[k] = v
		}
		return body
	}
	for name, extra := range map[string]map[string]any{
		"input chain":   {"chain": "input"},
		"drop":          {"action": "drop"},
		"out interface": {"out_interfaces": []string{"eth1"}},
		"any protocol":  {"services": []string{}},
		"no tcp":        {"services": []string{"ntp"}},
		"packet limit":  {"rate_limit": "ssh"},
		"mss":           {"syn_proxy_mss": 100},
		"wscale":        {"syn_proxy_wscale": 15},
	} {
		if rec := env.do("POST", "/api/rules", rule(extra)); rec.Code != http.StatusBadRequest {
			t.Errorf("%s accepted: %d %s", name, rec.Code, rec.Body)
		}
	}
	env.create("/api/rules", rule(map[string]any{"syn_proxy_mss": 1400}))
	// Without the switch, the other fields are free.
	env.create("/api/rules", rule(map[string]any{"syn_proxy": false, "services": []string{"dns"}}))

	doc, err := builder.BuildFirewall(env.srv.db, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.Validate(); err != nil {
		t.Fatal(err)
	}
	var proxied int
	for _, r := range doc.Instances[0].Rules {
		if p := r.SynProxy; p != nil {
			proxied++
			if p.MSS != 1400 || p.WScale != 7 {
				t.Errorf("syn proxy %+v", *p)
			}
		}
	}
	if proxied != 1 {
		t.Errorf("%d rules with a syn proxy", proxied)
	}
}
