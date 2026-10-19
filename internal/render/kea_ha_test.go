// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package render

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/abundo/portitor/internal/fwconfig"
)

// withDHCPHA puts the sample's DHCP on an HA pair, as its standby.
func withDHCPHA(doc fwconfig.Document) fwconfig.Document {
	doc.Instances[0].DHCP.HA = &fwconfig.DHCPHA{Role: fwconfig.DHCPHAStandby, Interface: "eth1", This: "192.168.1.2", Peer: "192.168.1.1"}
	return doc
}

func TestKeaHA(t *testing.T) {
	b, err := Render(withDHCPHA(fwconfig.SampleDocument()), Options{Paths: DefaultPaths(), Units: DefaultUnits()})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		file, port string
	}{{"/etc/kea/kea-dhcp4.conf", ":8001/"}, {"/etc/kea/kea-dhcp6.conf", ":8002/"}} {
		text := mustFile(t, b, c.file)
		var conf map[string]map[string]any
		if err := json.Unmarshal([]byte(text[strings.Index(text, "{"):]), &conf); err != nil {
			t.Fatalf("%s: %v\n%s", c.file, err, text)
		}
		for _, d := range conf {
			hooks, _ := json.Marshal(d["hooks-libraries"])
			h := string(hooks)
			if !strings.Contains(h, "libdhcp_ha.so") || !strings.Contains(h, "libdhcp_lease_cmds.so") ||
				!strings.Contains(h, `"this-server-name":"standby"`) || !strings.Contains(h, `"hot-standby"`) ||
				!strings.Contains(h, "http://192.168.1.1"+c.port) || !strings.Contains(h, "http://192.168.1.2"+c.port) {
				t.Errorf("%s hooks: %s", c.file, h)
			}
		}
	}
	// Only the peer gets in, on both ports, from one set.
	nft := mustFile(t, b, "/etc/nftables.d/portitor.nft")
	if strings.Count(nft, "set AUTO_dhcp_ha_v4") != 1 || !strings.Contains(nft, "192.168.1.1") ||
		!strings.Contains(nft, "tcp dport 8001") || !strings.Contains(nft, "tcp dport 8002") {
		t.Errorf("ruleset:\n%s", nft)
	}
	// Without HA, no hooks.
	b, _ = Render(fwconfig.SampleDocument(), Options{Paths: DefaultPaths(), Units: DefaultUnits()})
	if strings.Contains(mustFile(t, b, "/etc/kea/kea-dhcp4.conf"), "hooks-libraries") {
		t.Error("hooks without HA")
	}
}
