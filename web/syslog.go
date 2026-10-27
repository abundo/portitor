// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"

	"github.com/labstack/echo/v5"
	"gorm.io/gorm"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/models"
)

// Syslog: the remote syslog servers rsyslog sends a firewall's journal to,
// rows of its default instance (the journal is the host's, with every
// virtual firewall's services in it), written by global admins only; and
// the journal itself, followed by global admins only.

func prepareSyslogServer(tx *gorm.DB, s, old *models.SyslogServer) error {
	if old != nil {
		s.InstanceID = old.InstanceID
	}
	var in models.Instance
	if err := tx.Select("id", "is_default").First(&in, s.InstanceID).Error; err != nil {
		return bad("virtual firewall does not exist")
	}
	if !in.IsDefault {
		return bad("syslog servers are the firewall's: add them to its default virtual firewall")
	}
	s.Address = strings.TrimSpace(s.Address)
	if a, err := netip.ParseAddr(s.Address); err == nil {
		s.Address = a.Unmap().String()
	}
	if s.Port == 0 {
		s.Port = fwconfig.SyslogPort
	}
	if errs := fwconfig.CheckSyslogServer(s.Server()); len(errs) > 0 {
		return bad(fmt.Sprintf("syslog server %s: %s", s.Address, strings.Join(errs, "; ")))
	}
	var n int64
	if err := tx.Model(&models.SyslogServer{}).Where("instance_id = ? AND address = ? AND port = ? AND protocol = ? AND id <> ?",
		s.InstanceID, s.Address, s.Port, s.Protocol, s.ID).Count(&n).Error; err != nil {
		return err
	}
	if n > 0 {
		return bad(fmt.Sprintf("there is already a syslog server %s port %s/%d", s.Address, s.Protocol, s.Port))
	}
	return nil
}

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
