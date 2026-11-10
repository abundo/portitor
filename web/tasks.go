// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"fmt"
	"net/http"
	"time"

	"github.com/labstack/echo/v5"

	"github.com/abundo/portitor/internal/cron"
	"github.com/abundo/portitor/models"
)

// IP lists and scheduled tasks. Rules refer to a list as "@name" in their
// address lists, so renaming a list rewrites them, and a list that a rule
// or task uses cannot be deleted.

// handleTaskRun runs a task on the firewall now.
func (s *Server) handleTaskRun(c *echo.Context) error {
	var t models.Task
	if !s.loadByID(c, &t) {
		return nil
	}
	return s.startOnAgent(c, t.FirewallID, t.Name, func(a agentAPI) error { return a.RunTask(c.Request().Context(), t.Name) })
}

// handleIPListRefresh downloads an IP list on every firewall now.
func (s *Server) handleIPListRefresh(c *echo.Context) error {
	var l models.IpList
	if !s.loadByID(c, &l) {
		return nil
	}
	fws, err := s.firewalls()
	if err != nil {
		return err
	}
	for _, fw := range fws[1:] {
		a, _, err := s.firewallAgent(fw.ID)
		if err == nil {
			err = a.RefreshIPList(c.Request().Context(), l.Name)
		}
		if err != nil {
			return agentError(c, fmt.Errorf("firewall %s: %w", fw.Name, err))
		}
	}
	return s.startOnAgent(c, fws[0].ID, l.Name, func(a agentAPI) error { return a.RefreshIPList(c.Request().Context(), l.Name) })
}

// loadByID loads the row with the :id path parameter into dst, or answers
// 404 and returns false.
func (s *Server) loadByID(c *echo.Context, dst any) bool {
	id, err := echo.PathParam[uint](c, "id")
	if err != nil {
		_ = errJSON(c, http.StatusNotFound, "not found")
		return false
	}
	v, err := s.view(c.Request().Context())
	if err != nil {
		_ = errJSON(c, http.StatusInternalServerError, err.Error())
		return false
	}
	if !v.Load(dst, id) {
		_ = errJSON(c, http.StatusNotFound, "not found")
		return false
	}
	return true
}

// startOnAgent starts something on the firewall's agent.
func (s *Server) startOnAgent(c *echo.Context, firewallID uint, name string, start func(agentAPI) error) error {
	a, _, err := s.firewallAgent(firewallID)
	if err != nil {
		return agentError(c, err)
	}
	if err := start(a); err != nil {
		return agentError(c, err)
	}
	return c.JSON(http.StatusAccepted, map[string]any{"started": name})
}

// handleSchedulePreview parses ?schedule= and returns its next runs in
// portitor-web's time zone, for the task editor.
func (s *Server) handleSchedulePreview(c *echo.Context) error {
	sched, err := cron.Parse(c.QueryParam("schedule"))
	if err != nil {
		return c.JSON(http.StatusOK, map[string]any{"error": err.Error()})
	}
	next := []time.Time{}
	t := time.Now()
	for range 5 {
		if t = sched.Next(t); t.IsZero() {
			break
		}
		next = append(next, t)
	}
	return c.JSON(http.StatusOK, map[string]any{"next": next})
}
