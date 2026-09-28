// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"log/slog"
	"net/http"

	"github.com/labstack/echo/v5"

	"github.com/abundo/portitor/internal/agentapi"
)

// handleSystem passes on the firewall's operating system, its updates and
// the update jobs, for the Updates page.
func (s *Server) handleSystem(c *echo.Context) error {
	a, _, err := s.agent()
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
	slog.Info("update job", "job", req.Job, "release", req.Release, "user", currentUser(c).Username)
	return s.startOnAgent(c, req.Job, func(a agentAPI) error { return a.StartSystemJob(c.Request().Context(), req) })
}

func (s *Server) handleSystemReboot(c *echo.Context) error {
	slog.Warn("firewall reboot", "user", currentUser(c).Username, "remote", c.RealIP())
	return s.startOnAgent(c, "reboot", func(a agentAPI) error { return a.Reboot(c.Request().Context()) })
}
