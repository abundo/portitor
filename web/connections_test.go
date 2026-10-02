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

func TestAgentConnections(t *testing.T) {
	env := newEnv(t)
	fake := &connectionsAgent{}
	env.srv.newAgent = func(*models.Settings) (agentAPI, error) { return fake, nil }
	rec := env.do("POST", "/api/agent/connections", map[string]any{"instance": "main", "interval_ms": 500, "max": 10})
	if rec.Code != http.StatusOK || rec.Body.String() != "{}\n" || fake.req.Instance != "main" || fake.req.Max != 10 {
		t.Errorf("%d %q %+v", rec.Code, rec.Body, fake.req)
	}
	if rec := env.do("POST", "/api/agent/connections", map[string]any{"instance": "a;b"}); rec.Code != http.StatusBadRequest {
		t.Errorf("bad name: %d", rec.Code)
	}
}

// connectionsAgent records the request and answers one empty snapshot.
type connectionsAgent struct {
	agentAPI
	req agentapi.ConnectionsRequest
}

func (f *connectionsAgent) Connections(_ context.Context, req agentapi.ConnectionsRequest) (io.ReadCloser, error) {
	f.req = req
	return io.NopCloser(strings.NewReader("{}\n")), nil
}
