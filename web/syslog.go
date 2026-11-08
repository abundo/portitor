// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"log/slog"
	"net/http"

	"github.com/labstack/echo/v5"

	"github.com/abundo/portitor/internal/agentapi"
)

// Syslog: the remote syslog servers rsyslog sends a firewall's journal to,
// rows of its default instance (the journal is the host's, with every
// virtual firewall's services in it), written by global admins only; and
// the journal itself, followed by global admins only.

// handleAgentSyslog passes on the state of rsyslog and the journal on the
// firewall in ?firewall_id= (the first by default).
func (s *Server) handleAgentSyslog(c *echo.Context) error {
	a, err := s.firewallFromRequest(c)
	if err != nil {
		return agentError(c, err)
	}
	st, err := a.Syslog(c.Request().Context())
	if err != nil {
		return agentError(c, err)
	}
	return c.JSON(http.StatusOK, st)
}

// handleAgentJournal follows the whole journal of a firewall (firewall_id,
// the first by default) and passes the text to the browser as it comes.
// The journal holds every virtual firewall's services, so it is a global
// admin's (a POST outside tenantWrites).
func (s *Server) handleAgentJournal(c *echo.Context) error {
	var body struct {
		FirewallID uint `json:"firewall_id"`
		Lines      int  `json:"lines"`
	}
	if err := c.Bind(&body); err != nil {
		return errJSON(c, http.StatusBadRequest, "invalid request")
	}
	if body.FirewallID == 0 {
		id, err := firstFirewallID(s.db)
		if err != nil {
			return agentError(c, err)
		}
		body.FirewallID = id
	}
	a, fw, err := s.firewallAgent(body.FirewallID)
	if err != nil {
		return agentError(c, err)
	}
	stream, err := a.Journal(c.Request().Context(), agentapi.JournalRequest{Lines: body.Lines})
	if err != nil {
		return agentError(c, err)
	}
	defer stream.Close()
	slog.Info("journal started", "user", currentUser(c).Username, "firewall", fw.Name)
	streamText(c, stream)
	return nil
}
