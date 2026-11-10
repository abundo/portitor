// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"net/http"
	"testing"
)

// TestSettingsChecked: the Settings page and /api/config (the CLI's and
// NETCONF's path too) refuse the same values, by the schema and checkEdit.
func TestSettingsChecked(t *testing.T) {
	env := newEnv(t)
	env.host("one")
	for _, c := range []struct {
		page, leaf string
		value      any
	}{
		{"confirm_timeout", "confirm-timeout", -1},
		{"confirm_timeout", "confirm-timeout", 1801},
		{"capture_rate_kbps", "capture-rate-kbps", -1},
		{"capture_rate_kbps", "capture-rate-kbps", 10_000_001},
		{"wg_endpoint_host", "wg-endpoint-host", "not a host"},
		{"wg_endpoint_host", "wg-endpoint-host", "vpn.example.com:51820"},
	} {
		if rec := env.do("PUT", "/api/settings", map[string]any{c.page: c.value}); rec.Code != http.StatusBadRequest {
			t.Errorf("settings %s %v: %d %s", c.page, c.value, rec.Code, rec.Body)
		}
		if rec := env.cfg("PATCH", "settings", map[string]any{c.leaf: c.value}); rec.Code != http.StatusBadRequest {
			t.Errorf("config %s %v: %d %s", c.leaf, c.value, rec.Code, rec.Body)
		}
	}

	for _, h := range []string{" VPN.example.com ", "192.0.2.1", "2001:db8::1"} {
		if rec := env.do("PUT", "/api/settings", map[string]any{"wg_endpoint_host": h}); rec.Code != http.StatusOK {
			t.Errorf("endpoint host %q: %d %s", h, rec.Code, rec.Body)
		}
	}
	st, err := env.srv.settings()
	if err != nil {
		t.Fatal(err)
	}
	if st.WgEndpointHost != "2001:db8::1" {
		t.Errorf("endpoint host = %q", st.WgEndpointHost)
	}
	if rec := env.do("PUT", "/api/settings", map[string]any{"wg_endpoint_host": " VPN.example.com "}); rec.Code != http.StatusOK {
		t.Fatalf("endpoint host: %d %s", rec.Code, rec.Body)
	}
	if st, _ := env.srv.settings(); st.WgEndpointHost != "vpn.example.com" {
		t.Errorf("endpoint host = %q, want it trimmed and in lower case", st.WgEndpointHost)
	}

	// Virtual firewalls can't be turned off through the tree either while
	// a firewall has more than its host.
	env.patch("settings", map[string]any{"virtual-firewalls": true})
	env.vf("two")
	if rec := env.cfg("PATCH", "settings", map[string]any{"virtual-firewalls": false}); rec.Code != http.StatusBadRequest {
		t.Errorf("config: turn off with two: %d %s", rec.Code, rec.Body)
	}
}
