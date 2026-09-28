// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"testing"

	"github.com/abundo/portitor/internal/fwconfig"
)

func TestDyndnsReconcile(t *testing.T) {
	m := newDyndnsManager(true)
	defer m.Stop()
	home := dyndnsItem{instance: "main", cfg: fwconfig.DynDNS{Name: "home", Interface: "eth0", Server: "192.0.2.53", Zone: "example.com"}}
	lab := dyndnsItem{instance: "lab", netns: "fw-lab", cfg: fwconfig.DynDNS{Name: "home", Interface: "eth3"}}

	m.Reconcile([]dyndnsItem{home, lab})
	st := m.Status()
	if len(st) != 2 || st[0].Instance != "lab" || st[1].Interface != "eth0" || st[1].State != "dry-run" {
		t.Fatalf("status %+v", st)
	}
	first := m.clients[dyndnsKey{"main", "home"}]

	m.Reconcile([]dyndnsItem{home, lab})
	if m.clients[dyndnsKey{"main", "home"}] != first {
		t.Error("an unchanged client was restarted")
	}

	home.cfg.Zone = "example.org"
	m.Reconcile([]dyndnsItem{home})
	if m.clients[dyndnsKey{"main", "home"}] == first {
		t.Error("a changed client was not restarted")
	}
	if len(m.Status()) != 1 {
		t.Errorf("removed client still listed: %+v", m.Status())
	}
}
