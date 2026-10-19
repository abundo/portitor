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

func TestAgentCapture(t *testing.T) {
	env := newEnv(t)
	fake := &captureAgent{}
	env.srv.newAgent = func(*models.Firewall) (agentAPI, error) { return fake, nil }

	body := map[string]any{"instance": "main", "interface": "lan", "filter": "port 53", "rate_kbps": 0}
	rec := env.do("POST", "/api/agent/capture", body)
	if rec.Code != http.StatusOK || rec.Body.String() != "pcap" || rec.Header().Get("Content-Type") != "application/vnd.tcpdump.pcap" {
		t.Fatalf("capture: %d %q", rec.Code, rec.Body)
	}
	// The rate comes from Settings (default 1000), not the browser.
	if fake.req.RateKbps != agentapi.CaptureDefaultRateKbps || fake.req.Filter != "port 53" {
		t.Errorf("request: %+v", fake.req)
	}
	if rec := env.do("PUT", "/api/settings", map[string]any{"capture_rate_kbps": 64}); rec.Code != http.StatusOK {
		t.Fatalf("settings: %d %s", rec.Code, rec.Body)
	}
	env.do("POST", "/api/agent/capture", body)
	if fake.req.RateKbps != 64 {
		t.Errorf("rate from settings: %d", fake.req.RateKbps)
	}
	if rec := env.do("PUT", "/api/settings", map[string]any{"capture_rate_kbps": -1}); rec.Code != http.StatusBadRequest {
		t.Errorf("negative rate: %d", rec.Code)
	}
	body["interface"] = "lan;rm"
	if rec := env.do("POST", "/api/agent/capture", body); rec.Code != http.StatusBadRequest {
		t.Errorf("bad interface: %d", rec.Code)
	}
}

// captureAgent records the capture request and answers "pcap".
type captureAgent struct {
	agentAPI
	req agentapi.CaptureRequest
}

func (f *captureAgent) Capture(_ context.Context, req agentapi.CaptureRequest) (io.ReadCloser, error) {
	f.req = req
	return io.NopCloser(strings.NewReader("pcap")), nil
}

func TestCaptureWorkerCSP(t *testing.T) {
	env := newEnv(t)
	for path, eval := range map[string]bool{
		"/assets/capture.worker-abc123.js": true,
		"/assets/index-abc123.js":          false,
		"/capture":                         false,
	} {
		rec := env.do("GET", path, nil)
		csp := rec.Header().Get("Content-Security-Policy")
		if strings.Contains(csp, "unsafe-eval") != eval || csp == "" {
			t.Errorf("%s: %q", path, csp)
		}
	}
}
