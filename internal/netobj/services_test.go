// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package netobj

import (
	"testing"

	"github.com/abundo/portitor/models"
)

func TestServiceNames(t *testing.T) {
	for _, s := range []string{"myapp", "web-alt", "a.b_c", "unifi2"} {
		if !ValidServiceName(s) {
			t.Errorf("%q should be a valid service name", s)
		}
	}
	for _, s := range []string{"", "ssh", "https", "any", "MyApp", "1app", "a b", "a,b", "8000-8080"} {
		if ValidServiceName(s) {
			t.Errorf("%q should not be a valid service name", s)
		}
	}
}

func TestExpandPorts(t *testing.T) {
	s := NewServices([]models.Service{
		{Name: "unifi", Ports: "8080, 8443"},
		{Name: "games", Ports: "27000-27050"},
	})
	for in, want := range map[string]string{
		"https,8883":        "https,8883", // no custom name: kept as it is
		"ssh, UniFi":        "ssh, 8080, 8443",
		"games,22":          "27000-27050, 22",
		" unifi , 100-200 ": "8080, 8443, 100-200",
	} {
		got, err := s.ExpandPorts(in)
		if err != nil || got != want {
			t.Errorf("ExpandPorts(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "ghost", "unifi,,22", "70000"} {
		if _, err := s.ExpandPorts(bad); err == nil {
			t.Errorf("ExpandPorts(%q): expected error", bad)
		}
	}
}
