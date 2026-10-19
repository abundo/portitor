// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/abundo/portitor/internal/fwconfig"
)

// The sample's main instance has an exception, an IPv4 gateway (policy
// route 2) and an interface (3, both versions).
func TestPolicyRoutes(t *testing.T) {
	doc := fwconfig.SampleDocument()
	in := doc.Instance("main")
	v4, v6 := policyRoutes(in, "-4"), policyRoutes(in, "-6")
	if len(v4) != 2 || len(v6) != 1 || v4[0].table != 6501 || v4[0].gateway != "192.168.1.253" || v6[0].dev != "wg0" || v6[0].mark != 0x5102 {
		t.Fatalf("routes: %+v %+v", v4, v6)
	}

	rules, err := parseRules([]byte(`[{"priority":0,"src":"all","table":"local"},
 {"priority":6400,"src":"192.0.0.1","iif":"lo","table":"6400","protocol":"99"},
 {"priority":6501,"src":"all","fwmark":"0x5101","table":"6501","protocol":"99"},
 {"priority":6510,"src":"all","fwmark":"0x510a","table":"6510","protocol":"99"},
 {"priority":6600,"src":"all","fwmark":"0x1","table":"6600"},
 {"priority":32766,"src":"all","table":"main"}]`))
	if err != nil {
		t.Fatal(err)
	}
	equal(t, planPolicyRules("", "-4", v4, rules),
		"ip -4 rule del pref 6510 fwmark 0x510a lookup 6510 proto 99",
		"ip -4 rule add pref 6502 fwmark 0x5102 lookup 6502 proto 99")
	equal(t, planPolicyRules("", "-6", v6, nil),
		"ip -6 rule add pref 6502 fwmark 0x5102 lookup 6502 proto 99")
	// NAT64's planner keeps its hands off them.
	for _, c := range cmdStrings(planNAT64Rules("", nil, rules, nil)) {
		if strings.Contains(c, "65") {
			t.Errorf("nat64 removes a policy rule: %s", c)
		}
	}

	var routes []tableRoute
	if err := json.Unmarshal([]byte(`[{"dst":"default","gateway":"192.168.1.253","dev":"eth1","table":"6501"},
 {"dst":"default","gateway":"192.168.1.9","dev":"eth1","table":"6502"},
 {"dst":"default","dev":"wg0","table":"6503"},
 {"dst":"10.50.0.0/16","gateway":"192.168.1.254","dev":"eth1"},
 {"dst":"default","dev":"n64-eth1","table":"6400"}]`), &routes); err != nil {
		t.Fatal(err)
	}
	equal(t, planPolicyTables("", "-4", v4, routes),
		"ip -4 route del default via 192.168.1.9 dev eth1 table 6502 proto 99",
		"ip -4 route del default dev wg0 table 6503 proto 99",
		"ip -4 route replace default dev wg0 table 6502 proto 99")
	equal(t, planPolicyTables("", "-6", nil, nil))
}
