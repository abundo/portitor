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

// connectionsRequest is the browser's; the agent clamps the interval and
// the number of entries.
type connectionsRequest struct {
	Instance   string `json:"instance"`
	IntervalMs int    `json:"interval_ms"`
	Max        int    `json:"max"`
}

// handleAgentConnections streams the instance's conntrack table from the
// agent (JSON lines, one snapshot each) to the browser as it comes. The
// browser closing the request ends it.
func (s *Server) handleAgentConnections(c *echo.Context) error {
	var body connectionsRequest
	if err := c.Bind(&body); err != nil {
		return errJSON(c, http.StatusBadRequest, "invalid request")
	}
	if !captureName.MatchString(body.Instance) {
		return errJSON(c, http.StatusBadRequest, "invalid virtual firewall name")
	}
	if !currentAccess(c).isAdmin() {
		var inst models.Instance
		if err := s.db.Where("name = ?", body.Instance).First(&inst).Error; err != nil {
			return errJSON(c, http.StatusNotFound, "no such virtual firewall")
		}
		if ok, err := allowInstance(c, inst.ID, true); !ok {
			return err
		}
	}
	a, _, err := s.agent()
	if err != nil {
		return agentError(c, err)
	}
	r := c.Request()
	stream, err := a.Connections(r.Context(), agentapi.ConnectionsRequest{Instance: body.Instance, IntervalMs: body.IntervalMs, Max: body.Max})
	if err != nil {
		return agentError(c, err)
	}
	defer stream.Close()

	slog.Info("connections stream started", "user", currentUser(c).Username, "instance", body.Instance)
	w := c.Response()
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{}) // the server's timeout is for requests
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	buf := make([]byte, 32<<10)
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
