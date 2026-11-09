// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"net/http"

	"github.com/labstack/echo/v5"

	"github.com/abundo/portitor/models"
)

// handleDNSBlocklistRefresh downloads a blocklist again now, on its
// virtual firewall's firewall, and on that firewall's HA secondary when
// it answers.
func (s *Server) handleDNSBlocklistRefresh(c *echo.Context) error {
	var b models.DnsBlocklist
	if !s.loadByID(c, &b) {
		return nil
	}
	if ok, err := allowInstance(c, b.InstanceID, true); !ok {
		return err
	}
	in, err := s.instanceByID(c.Request().Context(), b.InstanceID)
	if err != nil || in == nil {
		return errJSON(c, http.StatusNotFound, "not found")
	}
	if !b.Enabled {
		return errJSON(c, http.StatusConflict, "the blocklist is off")
	}
	var secondaries []models.Firewall
	if err := s.db.Where("ha_primary_id = ?", in.FirewallID).Find(&secondaries).Error; err != nil {
		return err
	}
	for _, fw := range secondaries {
		if a, _, err := s.firewallAgent(fw.ID); err == nil {
			_ = a.RefreshDNSBlocklist(c.Request().Context(), in.Name, b.Name)
		}
	}
	return s.startOnAgent(c, in.FirewallID, b.Name, func(a agentAPI) error {
		return a.RefreshDNSBlocklist(c.Request().Context(), in.Name, b.Name)
	})
}
