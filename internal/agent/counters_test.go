// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"reflect"
	"testing"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/fwconfig"
)

func TestParseRuleCounters(t *testing.T) {
	out := []byte(`{"nftables": [{"metainfo": {"version": "1.1.6"}},
		{"counter": {"family": "inet", "name": "rule_5_orig", "table": "firewall", "handle": 2, "packets": 12, "bytes": 50632}},
		{"counter": {"family": "inet", "name": "rule_5_reply", "table": "firewall", "handle": 3, "packets": 8, "bytes": 300424}},
		{"counter": {"family": "inet", "name": "drop_forward_policy", "table": "firewall", "handle": 5, "packets": 3, "bytes": 180}},
		{"counter": {"family": "inet", "name": "drop_forward_invalid", "table": "firewall", "handle": 6, "packets": 1, "bytes": 40}},
		{"counter": {"family": "inet", "name": "drop_nat_policy", "table": "firewall", "handle": 7, "packets": 1, "bytes": 1}},
		{"counter": {"family": "inet", "name": "other", "table": "firewall", "handle": 4, "packets": 1, "bytes": 1}}]}`)
	got := map[uint32]agentapi.RuleCounters{}
	drops := map[string]agentapi.ChainDrops{}
	parseCounters(out, got, drops)
	want := agentapi.RuleCounters{OrigPackets: 12, OrigBytes: 50632, ReplyPackets: 8, ReplyBytes: 300424}
	if len(got) != 1 || got[5] != want {
		t.Errorf("got %+v", got)
	}
	wantDrops := agentapi.ChainDrops{InvalidPackets: 1, InvalidBytes: 40, PolicyPackets: 3, PolicyBytes: 180}
	if len(drops) != 1 || drops["forward"] != wantDrops {
		t.Errorf("drops %+v", drops)
	}
	parseCounters([]byte("[]"), got, drops) // dry-run answer
	if len(got) != 1 || len(drops) != 1 {
		t.Errorf("got %+v", got)
	}
}

func TestRateLimitStats(t *testing.T) {
	in := fwconfig.Instance{
		Name: "default",
		RateLimits: []fwconfig.RateLimit{
			{Name: "ssh", Rate: 4, Per: fwconfig.RatePerMinute, PerSource: true},
			{Name: "guests", Rate: 10, Unit: fwconfig.RateUnitMBit, Per: fwconfig.RatePerSecond, Shape: true},
		},
		Rules: []fwconfig.Rule{
			{ID: 5, Chain: fwconfig.ChainInput, Action: fwconfig.ActionAccept, RateLimit: "ssh"},
			{ID: 6, Chain: fwconfig.ChainForward, Action: fwconfig.ActionAccept, RateLimit: "guests"},
			{ID: 7, Chain: fwconfig.ChainForward, Action: fwconfig.ActionAccept, RateLimit: "guests"},
			{ID: 8, Chain: fwconfig.ChainForward, Action: fwconfig.ActionAccept},
		},
		Interfaces: []fwconfig.Interface{
			{Name: "eth0", Enabled: true},
			{Name: "eth1", Enabled: true},
		},
	}
	out := []byte(`{"nftables": [{"metainfo": {"version": "1.1.6"}},
		{"counter": {"family": "inet", "name": "rule_5_orig", "table": "firewall", "packets": 12, "bytes": 720}},
		{"counter": {"family": "inet", "name": "rl_ssh_drop", "table": "firewall", "packets": 3, "bytes": 180}},
		{"counter": {"family": "inet", "name": "rule_6_orig", "table": "firewall", "packets": 10, "bytes": 1000}},
		{"counter": {"family": "inet", "name": "rule_6_reply", "table": "firewall", "packets": 20, "bytes": 30000}},
		{"counter": {"family": "inet", "name": "rule_7_orig", "table": "firewall", "packets": 1, "bytes": 100}},
		{"counter": {"family": "inet", "name": "rule_8_orig", "table": "firewall", "packets": 99, "bytes": 99}}]}`)
	stats := rateLimitCounters(&in, nftCounters(out))
	if s := stats["ssh"]; !reflect.DeepEqual(s, agentapi.RateLimitStats{OrigPackets: 12, OrigBytes: 720, DropPackets: 3, DropBytes: 180}) {
		t.Errorf("ssh %+v", s)
	}
	// As `tc -s -j` prints them (iproute2 6.x).
	classes := parseClasses([]byte(`[{"class":"htb","handle":"1:10","parent":"1:1","leaf":"0x8001","prio":0,"rate":1250000,"ceil":1250000,"burst":1600,"cburst":1600,"stats":{"bytes":31000,"packets":30,"drops":1,"overlimits":4,"requeues":0,"backlog":1514,"qlen":1,"lended":0,"borrowed":0,"giants":0,"tokens":20000,"ctokens":20000}},{"class":"htb","handle":"1:1","root":true,"rate":12500000,"ceil":12500000,"burst":1600,"cburst":1600,"stats":{"bytes":50000,"packets":50,"drops":0,"overlimits":0,"requeues":0,"backlog":0,"qlen":0}}]`))
	qdiscs := parseQdiscStats([]byte(`[{"kind":"htb","handle":"1:","dev":"eth1","root":true,"refcnt":2,"options":{"r2q":10,"default":"0xffff"},"bytes":50000,"packets":50,"drops":9,"overlimits":0,"requeues":0,"backlog":0,"qlen":0},{"kind":"fq_codel","handle":"8001:","dev":"eth1","parent":"1:10","options":{"limit":10240},"bytes":31000,"packets":30,"drops":2,"overlimits":0,"requeues":0,"backlog":0,"qlen":0},{"kind":"fq_codel","handle":"8002:","dev":"eth0","parent":"1:10","bytes":0,"packets":0,"drops":5}]`))
	addShaperStats(stats, &in, in.Shapers(), map[string][]tcClass{"eth1": classes}, qdiscs)
	want := agentapi.RateLimitStats{
		OrigPackets: 11, OrigBytes: 1100, ReplyPackets: 20, ReplyBytes: 30000,
		Interfaces: []agentapi.ShaperClass{{Interface: "eth1", Bytes: 31000, Packets: 30, Drops: 3, Overlimits: 4, Backlog: 1514, Qlen: 1}},
	}
	if got := stats["guests"]; !reflect.DeepEqual(got, want) {
		t.Errorf("guests %+v, want %+v", got, want)
	}
	// An HA pair's two hosts add up, interface by interface.
	got := stats["guests"]
	got.Add(want)
	if got.OrigPackets != 22 || len(got.Interfaces) != 1 || got.Interfaces[0].Bytes != 62000 {
		t.Errorf("added %+v", got)
	}
}
