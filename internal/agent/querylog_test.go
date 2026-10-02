// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"testing"
	"time"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/fwconfig"
)

func TestParseJournalQuery(t *testing.T) {
	for _, tc := range []struct {
		name, line string
		ok         bool
		want       agentapi.DNSQueryEntry
	}{
		{"ipv4", `{"MESSAGE":"client @0x7f8b2c0a1b68 192.168.1.10#50123 (www.example.com): query: www.example.com IN A +E(0)K (192.168.1.1)","__REALTIME_TIMESTAMP":"1700000000000000"}`, true,
			agentapi.DNSQueryEntry{Time: time.UnixMicro(1700000000000000), Client: "192.168.1.10", ClientPort: 50123, Name: "www.example.com", Class: "IN", Type: "A", Flags: "+E(0)K", Server: "192.168.1.1"}},
		{"ipv6 view", `{"MESSAGE":"client @0x1 fd00::5#53 (x.home.arpa): view internal: query: x.home.arpa IN AAAA - (fd00::1)","__REALTIME_TIMESTAMP":"1700000000000000"}`, true,
			agentapi.DNSQueryEntry{Time: time.UnixMicro(1700000000000000), Client: "fd00::5", ClientPort: 53, Name: "x.home.arpa", Class: "IN", Type: "AAAA", Flags: "-", Server: "fd00::1"}},
		{"other message", `{"MESSAGE":"zone home.arpa/IN: loaded serial 1"}`, false, agentapi.DNSQueryEntry{}},
		{"bytes", `{"MESSAGE":[1,2,3]}`, false, agentapi.DNSQueryEntry{}},
	} {
		got, ok := parseJournalQuery([]byte(tc.line))
		if ok != tc.ok || (ok && got != tc.want) {
			t.Errorf("%s: got %+v %v, want %+v", tc.name, got, ok, tc.want)
		}
	}
}

func TestQueryFilter(t *testing.T) {
	e := agentapi.DNSQueryEntry{Client: "192.168.1.10", Name: "WWW.Example.com", Type: "A"}
	for _, tc := range []struct {
		filter fwconfig.DNSQueryLog
		want   bool
	}{
		{fwconfig.DNSQueryLog{}, true},
		{fwconfig.DNSQueryLog{Clients: []string{"192.168.1.0/24"}}, true},
		{fwconfig.DNSQueryLog{Clients: []string{"10.0.0.0/8", "fd00::/8"}}, false},
		{fwconfig.DNSQueryLog{Names: []string{"example.com."}}, true},
		{fwconfig.DNSQueryLog{Names: []string{"www.example.com"}}, true},
		{fwconfig.DNSQueryLog{Names: []string{"ample.com"}}, false},
		{fwconfig.DNSQueryLog{Types: []string{"AAAA", "A"}}, true},
		{fwconfig.DNSQueryLog{Types: []string{"MX"}}, false},
		{fwconfig.DNSQueryLog{Clients: []string{"192.168.1.0/24"}, Types: []string{"MX"}}, false},
	} {
		if got := newQueryFilter(tc.filter).match(e); got != tc.want {
			t.Errorf("%+v: got %v", tc.filter, got)
		}
	}
}

func TestQueryLogReconcileDryRun(t *testing.T) {
	q := newQueryLog(true)
	q.Reconcile(map[string]queryLogItem{"main": {unit: "portitor-named@main"}})
	if len(q.followers) != 0 {
		t.Errorf("dry run follows: %v", q.followers)
	}
	q.Stop()
}
