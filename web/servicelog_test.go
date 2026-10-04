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

func TestAgentServiceLog(t *testing.T) {
	env := newEnv(t)
	fake := &serviceLogAgent{}
	env.srv.newAgent = func(*models.Settings) (agentAPI, error) { return fake, nil }
	for _, c := range []struct {
		body map[string]any
		code int
	}{
		{map[string]any{"instance": "main", "unit": "portitor-named@fw1.service"}, http.StatusOK},
		{map[string]any{"instance": "main", "unit": "named"}, http.StatusOK},
		{map[string]any{"instance": "main", "unit": "a b"}, http.StatusBadRequest},
		{map[string]any{"instance": "main", "unit": ""}, http.StatusBadRequest},
		{map[string]any{"instance": "a;b", "unit": "named"}, http.StatusBadRequest},
	} {
		fake.req = agentapi.ServiceLogRequest{}
		rec := env.do("POST", "/api/agent/servicelog", c.body)
		if rec.Code != c.code {
			t.Errorf("%v: %d %s", c.body, rec.Code, rec.Body)
			continue
		}
		if c.code == http.StatusOK && (fake.req.Unit != c.body["unit"] || rec.Body.String() != "line\n") {
			t.Errorf("%v: %+v %q", c.body, fake.req, rec.Body)
		}
	}
}

// serviceLogAgent records the request and answers one line.
type serviceLogAgent struct {
	agentAPI
	req agentapi.ServiceLogRequest
}

func (f *serviceLogAgent) ServiceLog(_ context.Context, req agentapi.ServiceLogRequest) (io.ReadCloser, error) {
	f.req = req
	return io.NopCloser(strings.NewReader("line\n")), nil
}
