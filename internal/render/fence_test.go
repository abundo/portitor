// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package render

import (
	"testing"

	"github.com/abundo/portitor/internal/fwconfig"
)

func TestFence(t *testing.T) {
	doc := fwconfig.Document{Instances: []fwconfig.Instance{{
		Name: "main", Default: true,
		VRRP: []fwconfig.VRRP{{Interface: "lan", VRID: 10}},
		DHCP: fwconfig.DHCPServer{Enabled: true},
		RA:   []fwconfig.RAInterface{{Interface: "lan"}},
	}}}
	exp := doc.Expand()
	fence(&exp)
	in := exp.Instances[0]
	if !in.VRRP[0].Shutdown || in.DHCP.Enabled || in.RA != nil {
		t.Errorf("fenced instance: %+v", in)
	}
	// The caller's document is left as it was.
	if doc.Instances[0].VRRP[0].Shutdown || !doc.Instances[0].DHCP.Enabled {
		t.Error("fence changed the caller's document")
	}
}
