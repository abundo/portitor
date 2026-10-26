// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/labstack/echo/v5"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/models"
)

// handleAgentProbe runs a connectivity test (ICMP echo, TCP connect or UDP)
// on the agent and passes its events (JSON lines) to the browser as they
// come. The target is an address, a named host or a DNS name, as for a
// traceroute. The browser closing the request stops it.
func (s *Server) handleAgentProbe(c *echo.Context) error {
	var req agentapi.ProbeRequest
	if err := c.Bind(&req); err != nil {
		return errJSON(c, http.StatusBadRequest, "invalid request")
	}
	if !captureName.MatchString(req.Instance) || (req.Interface != "" && !captureName.MatchString(req.Interface)) {
		return errJSON(c, http.StatusBadRequest, "invalid virtual firewall or interface name")
	}
	if req.Protocol != "icmp" && req.Protocol != "tcp" && req.Protocol != "udp" {
		return errJSON(c, http.StatusBadRequest, "protocol must be icmp, tcp or udp")
	}
	if !currentAccess(c).isAdmin() {
		var inst models.Instance
		if err := s.db.Where("name = ?", req.Instance).First(&inst).Error; err != nil {
			return errJSON(c, http.StatusNotFound, "no such virtual firewall")
		}
		if ok, err := allowInstance(c, inst.ID, true); !ok {
			return err
		}
	}
	target := req.Target
	addr, msg := s.traceTarget(req.Target, req.Family)
	if msg != "" {
		return errJSON(c, http.StatusBadRequest, msg)
	}
	req.Target = addr
	a, _, err := s.instanceAgent(req.Instance)
	if err != nil {
		return agentError(c, err)
	}
	r := c.Request()
	stream, err := a.Probe(r.Context(), req)
	if err != nil {
		return agentError(c, err)
	}
	defer stream.Close()

	user := currentUser(c)
	slog.Info("connectivity test started", "user", user.Username, "instance", req.Instance, "interface", req.Interface, "target", target, "protocol", req.Protocol, "port", req.Port)
	w := c.Response()
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{}) // the server's timeout is for requests
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	buf := make([]byte, 8<<10)
	for {
		n, rerr := stream.Read(buf)
		if n > 0 {
			if _, err := w.Write(buf[:n]); err != nil {
				break
			}
			_ = rc.Flush()
		}
		if rerr != nil {
			break
		}
	}
	return nil
}
