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
	"github.com/abundo/portitor/models"
)

func TestAgentProbe(t *testing.T) {
	env := newEnv(t)
	fake := &probeAgent{}
	env.srv.newAgent = func(*models.Firewall) (agentAPI, error) { return fake, nil }
	if err := env.srv.db.Create(&models.AddressObject{Name: "gw", Addresses: models.StringList{"192.0.2.1", "2001:db8::1"}}).Error; err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		body   map[string]any
		code   int
		target string
	}{
		{map[string]any{"instance": "main", "protocol": "icmp", "target": "198.51.100.7"}, http.StatusOK, "198.51.100.7"},
		{map[string]any{"instance": "main", "protocol": "tcp", "port": 443, "target": "gw", "family": "ipv6"}, http.StatusOK, "2001:db8::1"},
		{map[string]any{"instance": "main", "protocol": "udp", "port": 53, "target": "dns.example.com"}, http.StatusOK, "dns.example.com"},
		{map[string]any{"instance": "main", "protocol": "icmp", "target": "a b"}, http.StatusBadRequest, ""},
		{map[string]any{"instance": "main", "protocol": "sctp", "target": "192.0.2.1"}, http.StatusBadRequest, ""},
		{map[string]any{"instance": "main", "protocol": "icmp", "target": "192.0.2.1", "interface": "a;b"}, http.StatusBadRequest, ""},
	} {
		fake.req = agentapi.ProbeRequest{}
		rec := env.do("POST", "/api/agent/probe", c.body)
		if rec.Code != c.code {
			t.Errorf("%v: %d %s", c.body, rec.Code, rec.Body)
			continue
		}
		if c.code == http.StatusOK && (fake.req.Target != c.target || rec.Body.String() != "{}\n") {
			t.Errorf("%v: %+v %q", c.body, fake.req, rec.Body)
		}
	}
}

// probeAgent records the connectivity test's request and answers one
// empty event.
type probeAgent struct {
	agentAPI
	req agentapi.ProbeRequest
}

func (f *probeAgent) Probe(_ context.Context, req agentapi.ProbeRequest) (io.ReadCloser, error) {
	f.req = req
	return io.NopCloser(strings.NewReader("{}\n")), nil
}
