// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/builder"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/models"
)

func TestSyslogServers(t *testing.T) {
	env := newEnv(t)
	if err := env.srv.ensureDefaultInstance(); err != nil {
		t.Fatal(err)
	}
	var main models.Instance
	env.srv.db.Where("is_default = ?", true).First(&main)
	guest := env.create("/api/instances", map[string]any{"name": "guest"})

	server := func(inst uint, extra map[string]any) map[string]any {
		body := map[string]any{"instance_id": inst, "enabled": true, "address": "192.0.2.10", "port": 514, "protocol": "udp", "format": "rfc3164", "severity": "info"}
		for k, v := range extra {
			body[k] = v
		}
		return body
	}
	for what, body := range map[string]map[string]any{
		"virtual firewall": server(guest, nil),
		"host name":        server(main.ID, map[string]any{"address": "logs.example.com"}),
		"port":             server(main.ID, map[string]any{"port": 70000}),
		"protocol":         server(main.ID, map[string]any{"protocol": "tls"}),
		"format":           server(main.ID, map[string]any{"format": "json"}),
		"severity":         server(main.ID, map[string]any{"severity": "verbose"}),
	} {
		if rec := env.do("POST", "/api/syslog/servers", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s accepted: %d %s", what, rec.Code, rec.Body)
		}
	}
	id := env.create("/api/syslog/servers", server(main.ID, map[string]any{"port": 0}))
	if rec := env.do("POST", "/api/syslog/servers", server(main.ID, nil)); rec.Code != http.StatusBadRequest {
		t.Errorf("duplicate accepted: %d %s", rec.Code, rec.Body)
	}
	env.create("/api/syslog/servers", server(main.ID, map[string]any{"address": "2001:db8::10", "port": 6514, "protocol": "tcp", "format": "rfc5424", "severity": "warning"}))
	env.create("/api/syslog/servers", server(main.ID, map[string]any{"address": "192.0.2.11", "enabled": false}))
	// A server never moves to another instance.
	if rec := env.do("PUT", "/api/syslog/servers/"+itoa(id), map[string]any{"instance_id": guest, "description": "SIEM"}); rec.Code != http.StatusOK {
		t.Errorf("update: %d %s", rec.Code, rec.Body)
	}

	doc, err := builder.Build(env.srv.db, 1)
	if err != nil {
		t.Fatal(err)
	}
	if s := doc.Instance("guest").Syslog; s != nil {
		t.Errorf("guest syslog %+v", s)
	}
	s := doc.Instance(main.Name).Syslog
	want := []fwconfig.SyslogServer{
		{Address: "192.0.2.10", Port: 514, Protocol: "udp", Format: "rfc3164", Severity: "info"},
		{Address: "2001:db8::10", Port: 6514, Protocol: "tcp", Format: "rfc5424", Severity: "warning"},
	}
	if s == nil || len(s.Servers) != len(want) || s.Servers[0] != want[0] || s.Servers[1] != want[1] {
		t.Fatalf("syslog %+v", s)
	}
	if err := doc.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestAgentSyslogAndJournal(t *testing.T) {
	env := newEnv(t)
	if err := env.srv.ensureDefaultInstance(); err != nil {
		t.Fatal(err)
	}
	fake := &syslogAgent{}
	env.srv.newAgent = func(*models.Firewall) (agentAPI, error) { return fake, nil }
	if rec := env.do("GET", "/api/agent/syslog", nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"state":"active"`) {
		t.Errorf("syslog: %d %s", rec.Code, rec.Body)
	}
	rec := env.do("POST", "/api/agent/journal", map[string]any{"lines": 50})
	if rec.Code != http.StatusOK || rec.Body.String() != "line\n" || fake.req.Lines != 50 {
		t.Errorf("journal: %d %q %+v", rec.Code, rec.Body, fake.req)
	}
}

// syslogAgent answers the syslog state and a one-line journal.
type syslogAgent struct {
	agentAPI
	req agentapi.JournalRequest
}

func (f *syslogAgent) Syslog(context.Context) (*agentapi.SyslogStatus, error) {
	return &agentapi.SyslogStatus{Unit: "rsyslog.service", State: "active", Servers: []fwconfig.SyslogServer{}}, nil
}

func (f *syslogAgent) Journal(_ context.Context, req agentapi.JournalRequest) (io.ReadCloser, error) {
	f.req = req
	return io.NopCloser(strings.NewReader("line\n")), nil
}
