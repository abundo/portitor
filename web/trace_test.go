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

func TestAgentTrace(t *testing.T) {
	env := newEnv(t)
	fake := &traceAgent{}
	env.srv.newAgent = func(*models.Settings) (agentAPI, error) { return fake, nil }
	if err := env.srv.db.Create(&models.AddressObject{Name: "gw", Addresses: models.StringList{"192.0.2.1", "2001:db8::1"}}).Error; err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		body   map[string]any
		code   int
		target string
	}{
		{map[string]any{"instance": "main", "target": "198.51.100.7"}, http.StatusOK, "198.51.100.7"},
		{map[string]any{"instance": "main", "interface": "wan", "target": "gw"}, http.StatusOK, "192.0.2.1"},
		{map[string]any{"instance": "main", "target": "gw", "family": "ipv6"}, http.StatusOK, "2001:db8::1"},
		{map[string]any{"instance": "main", "target": "www.example.com", "family": "ipv6"}, http.StatusOK, "www.example.com"},
		{map[string]any{"instance": "main", "target": "a b"}, http.StatusBadRequest, ""},
		{map[string]any{"instance": "main", "target": "-x"}, http.StatusBadRequest, ""},
		{map[string]any{"instance": "main", "interface": "a;b", "target": "gw"}, http.StatusBadRequest, ""},
	} {
		fake.req = agentapi.TraceRequest{}
		rec := env.do("POST", "/api/agent/trace", c.body)
		if rec.Code != c.code {
			t.Errorf("%v: %d %s", c.body, rec.Code, rec.Body)
			continue
		}
		if c.code == http.StatusOK && (fake.req.Target != c.target || rec.Body.String() != "{}\n") {
			t.Errorf("%v: %+v %q", c.body, fake.req, rec.Body)
		}
	}
}

// traceAgent records the trace request and answers one empty event.
type traceAgent struct {
	agentAPI
	req agentapi.TraceRequest
}

func (f *traceAgent) Trace(_ context.Context, req agentapi.TraceRequest) (io.ReadCloser, error) {
	f.req = req
	return io.NopCloser(strings.NewReader("{}\n")), nil
}
