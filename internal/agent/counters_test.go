// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"testing"

	"github.com/abundo/portitor/internal/agentapi"
)

func TestParseRuleCounters(t *testing.T) {
	out := []byte(`{"nftables": [{"metainfo": {"version": "1.1.6"}},
		{"counter": {"family": "inet", "name": "rule_5_orig", "table": "firewall", "handle": 2, "packets": 12, "bytes": 50632}},
		{"counter": {"family": "inet", "name": "rule_5_reply", "table": "firewall", "handle": 3, "packets": 8, "bytes": 300424}},
		{"counter": {"family": "inet", "name": "other", "table": "firewall", "handle": 4, "packets": 1, "bytes": 1}}]}`)
	got := map[uint32]agentapi.RuleCounters{}
	parseRuleCounters(out, got)
	want := agentapi.RuleCounters{OrigPackets: 12, OrigBytes: 50632, ReplyPackets: 8, ReplyBytes: 300424}
	if len(got) != 1 || got[5] != want {
		t.Errorf("got %+v", got)
	}
	parseRuleCounters([]byte("[]"), got) // dry-run answer
	if len(got) != 1 {
		t.Errorf("got %+v", got)
	}
}
