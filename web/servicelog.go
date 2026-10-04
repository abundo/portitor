// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"log/slog"
	"net/http"
	"regexp"
	"time"

	"github.com/labstack/echo/v5"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/models"
)

// unitName is a systemd unit name a service log may follow (the agent
// checks it is one of the instance's services).
var unitName = regexp.MustCompile(`^[A-Za-z0-9@._:-]{1,255}$`)

// handleAgentServiceLog follows a service's journal on the agent and
// passes the text to the browser as it comes. The browser closing the
// request stops it.
func (s *Server) handleAgentServiceLog(c *echo.Context) error {
	var body agentapi.ServiceLogRequest
	if err := c.Bind(&body); err != nil {
		return errJSON(c, http.StatusBadRequest, "invalid request")
	}
	if !captureName.MatchString(body.Instance) || !unitName.MatchString(body.Unit) {
		return errJSON(c, http.StatusBadRequest, "invalid virtual firewall or service name")
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
	stream, err := a.ServiceLog(r.Context(), body)
	if err != nil {
		return agentError(c, err)
	}
	defer stream.Close()

	slog.Info("service log started", "user", currentUser(c).Username, "instance", body.Instance, "unit", body.Unit)
	w := c.Response()
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{}) // the server's timeout is for requests
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
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
