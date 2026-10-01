// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"slices"
	"testing"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/fwconfig"
)

func TestTraceArgs(t *testing.T) {
	in := &fwconfig.Instance{Name: "main", Interfaces: []fwconfig.Interface{{Name: "wan"}}}
	req := agentapi.TraceRequest{Instance: "main", Interface: "wan", Target: "2001:db8::1"}
	argv, err := traceArgs(in, &req)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"mtr", "--raw", "--no-dns", "--report-cycles", "10", "--interval", "1", "-6", "--interface", "wan", "--", "2001:db8::1"}
	if !slices.Equal(argv, want) {
		t.Errorf("argv %q", argv)
	}
	for _, bad := range []agentapi.TraceRequest{
		{Target: "example.com"},
		{Target: "-x"},
		{Target: "fe80::1%eth0"},
		{Target: "192.0.2.1", Interface: "nope"},
	} {
		if _, err := traceArgs(in, &bad); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
	big := agentapi.TraceRequest{Target: "192.0.2.1", Count: 1 << 20}
	if _, err := traceArgs(in, &big); err != nil || big.Count != agentapi.TraceMaxCount {
		t.Errorf("count %d, %v", big.Count, err)
	}
}

func TestParseMtrRaw(t *testing.T) {
	for line, want := range map[string]agentapi.TraceEvent{
		"x 0 33000":          {Type: "sent", Hop: 1, Seq: 33000},
		"h 2 192.0.2.1":      {Type: "host", Hop: 3, Addr: "192.0.2.1"},
		"p 2 1234 33002":     {Type: "reply", Hop: 3, RTTus: 1234, Seq: 33002},
		"d 2 router.example": {},
		"h 2 not-an-addr":    {},
		"x":                  {},
	} {
		got, ok := parseMtrRaw(line)
		if ok != (want.Type != "") || (ok && got != want) {
			t.Errorf("%q: %+v %v", line, got, ok)
		}
	}
}

func TestResolveTargetChecks(t *testing.T) {
	for _, bad := range []string{"-x", "a b", "a;b", "a..b", ".example"} {
		req := agentapi.TraceRequest{Target: bad}
		if err := resolveTarget(t.Context(), "", &req); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	req := agentapi.TraceRequest{Target: "192.0.2.1"}
	if err := resolveTarget(t.Context(), "", &req); err != nil || req.Target != "192.0.2.1" {
		t.Errorf("literal: %v %q", err, req.Target)
	}
}
