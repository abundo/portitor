// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/labstack/echo/v5"

	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/models"
)

func presentDnsBlocklist(b *models.DnsBlocklist) {
	b.HasAuthKey = b.AuthKey != ""
	b.NewAuthKey, b.ClearAuthKey = "", false
}

// prepareBlocklistAllow normalises an instance's allowed names.
func prepareBlocklistAllow(in *models.Instance) error {
	in.DnsBlocklistAllow = cleanList(in.DnsBlocklistAllow)
	for i, n := range in.DnsBlocklistAllow {
		n = strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(n, "*."), "."))
		if !fwconfig.ValidDomain(n) {
			return bad(fmt.Sprintf("allowed names: %q is not a valid domain", n))
		}
		in.DnsBlocklistAllow[i] = n
	}
	return nil
}

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
	var in models.Instance
	if err := s.db.First(&in, b.InstanceID).Error; err != nil {
		return err
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
