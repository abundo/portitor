// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"regexp"
	"strings"
	"time"

	"github.com/labstack/echo/v5"

	"github.com/abundo/portitor/internal/agentapi"
)

// captureName is what an instance or interface name may look like here;
// the agent checks that it exists.
var captureName = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,32}$`)

// handleAgentCapture starts a packet capture on the agent and passes its
// pcap stream to the browser as it comes. The rate is the one in
// Settings, not the browser's to choose. The browser closing the request
// ends the capture on the agent.
func (s *Server) handleAgentCapture(c *echo.Context) error {
	var req agentapi.CaptureRequest
	if err := c.Bind(&req); err != nil {
		return errJSON(c, http.StatusBadRequest, "invalid request")
	}
	if !captureName.MatchString(req.Instance) || !captureName.MatchString(req.Interface) {
		return errJSON(c, http.StatusBadRequest, "invalid instance or interface name")
	}
	a, st, err := s.agent()
	if err != nil {
		return agentError(c, err)
	}
	req.RateKbps = st.CaptureRateKbps

	r := c.Request()
	body, err := a.Capture(r.Context(), req)
	if err != nil {
		return agentError(c, err)
	}
	defer body.Close()

	user := currentUser(c)
	slog.Info("capture started", "user", user.Username, "instance", req.Instance, "interface", req.Interface, "filter", req.Filter)
	w := c.Response()
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{}) // the server's timeout is for requests
	w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	buf := make([]byte, 32<<10)
	var sent int64
	for {
		n, rerr := body.Read(buf)
		if n > 0 {
			if _, err := w.Write(buf[:n]); err != nil {
				break
			}
			_ = rc.Flush()
			sent += int64(n)
		}
		if rerr != nil {
			break
		}
	}
	slog.Info("capture ended", "user", user.Username, "instance", req.Instance, "interface", req.Interface, "bytes", sent)
	return nil
}

// captureWorkerCSP relaxes the Content-Security-Policy for the packet
// capture's worker script only (a dedicated worker gets the policy its own
// script is served with). Wiregasm needs WebAssembly, and its Emscripten
// bindings build functions from strings; the pages keep the strict policy.
func captureWorkerCSP(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c *echo.Context) error {
		p := c.Request().URL.Path
		if strings.HasPrefix(p, "/assets/capture.worker-") && strings.HasSuffix(p, ".js") {
			c.Response().Header().Set(echo.HeaderContentSecurityPolicy,
				"default-src 'self'; script-src 'self' 'unsafe-eval' 'wasm-unsafe-eval'")
		}
		return next(c)
	}
}

// wiregasmFiles are what the capture worker loads from /wiregasm/.
var wiregasmFiles = []string{"wiregasm.js", "wiregasm.wasm.gz", "wiregasm.data.gz"}

// handleWiregasm serves Wiregasm from cfg.WiregasmDir. It is a separate
// program, installed next to portitor-web (install.py), never embedded.
func (s *Server) handleWiregasm(c *echo.Context) error {
	name := c.Param("*")
	if !slices.Contains(wiregasmFiles, name) {
		return c.String(http.StatusNotFound, "not found")
	}
	path := filepath.Join(s.cfg.WiregasmDir, name)
	if _, err := os.Stat(path); err != nil {
		return c.String(http.StatusNotFound, "Wiregasm is not installed in "+s.cfg.WiregasmDir+" (install.py installs it)")
	}
	if name != "wiregasm.js" {
		c.Response().Header().Set(echo.HeaderContentType, "application/octet-stream")
	}
	c.Response().Header().Set("Cache-Control", "public, max-age=86400")
	http.ServeFile(c.Response(), c.Request(), path)
	return nil
}
