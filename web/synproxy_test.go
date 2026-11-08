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
	env.host("main")
	env.put("instance=main/interface=eth0", map[string]any{"kind": "physical", "enabled": true})
	env.put("instance=main/interface=eth1", map[string]any{"kind": "physical", "enabled": true})
	env.put("instance=main/rate-limit=ssh", map[string]any{"rate": 4})
	rule := func(extra map[string]any) map[string]any {
		body := map[string]any{"chain": "forward", "action": "accept", "in-interfaces": []string{"eth0"},
			"dst-addrs": []string{"192.168.1.10"}, "services": []string{"https"}, "syn-proxy": true, "syn-proxy-wscale": 7}
		for k, v := range extra {
			body[k] = v
		}
		return body
	}
	for name, extra := range map[string]map[string]any{
		"input chain":   {"chain": "input"},
		"drop":          {"action": "drop"},
		"out interface": {"out-interfaces": []string{"eth1"}},
		"any protocol":  {"services": []string{}},
		"no tcp":        {"services": []string{"ntp"}},
		"packet limit":  {"rate-limit": "ssh"},
		"mss":           {"syn-proxy-mss": 100},
		"wscale":        {"syn-proxy-wscale": 15},
	} {
		if rec := env.cfg("POST", "instance=main/rule", rule(extra)); rec.Code != http.StatusBadRequest {
			t.Errorf("%s accepted: %d %s", name, rec.Code, rec.Body)
		}
	}
	env.mustCfg("POST", "instance=main/rule", rule(map[string]any{"syn-proxy-mss": 1400}))
	// Without the switch, the other fields are free.
	env.mustCfg("POST", "instance=main/rule", rule(map[string]any{"syn-proxy": false, "services": []string{"dns"}}))

	fw := firstFirewall(t, env)
	doc, err := builder.BuildFirewall(env.input(), 1, fw.ID)
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
