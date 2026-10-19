// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"log/slog"
	"net/http"

	"github.com/labstack/echo/v5"

	"github.com/abundo/portitor/internal/agentapi"
)

// The system routes act on one firewall: ?firewall_id=, or the first.

// handleSystem passes on the firewall's operating system, its updates and
// the update jobs, for the Updates page.
func (s *Server) handleSystem(c *echo.Context) error {
	id, err := s.requestFirewall(c)
	if err != nil {
		return err
	}
	a, _, err := s.firewallAgent(id)
	if err != nil {
		return agentError(c, err)
	}
	st, err := a.System(c.Request().Context())
	if err != nil {
		return agentError(c, err)
	}
	return c.JSON(http.StatusOK, st)
}

// handleSystemJob starts an update job on the firewall: a check, a Debian
// upgrade, or the installation of a Portitor release.
func (s *Server) handleSystemJob(c *echo.Context) error {
	var req agentapi.SystemJobRequest
	if err := c.Bind(&req); err != nil {
		return errJSON(c, http.StatusBadRequest, "invalid request")
	}
	id, err := s.requestFirewall(c)
	if err != nil {
		return err
	}
	slog.Info("update job", "job", req.Job, "release", req.Release, "firewall", id, "user", currentUser(c).Username)
	return s.startOnAgent(c, id, req.Job, func(a agentAPI) error { return a.StartSystemJob(c.Request().Context(), req) })
}

func (s *Server) handleSystemReboot(c *echo.Context) error {
	id, err := s.requestFirewall(c)
	if err != nil {
		return err
	}
	slog.Warn("firewall reboot", "firewall", id, "user", currentUser(c).Username, "remote", c.RealIP())
	return s.startOnAgent(c, id, "reboot", func(a agentAPI) error { return a.Reboot(c.Request().Context()) })
}
