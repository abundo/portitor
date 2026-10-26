// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/labstack/echo/v5"
	"gorm.io/gorm"

	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/models"
)

// prepareDnsBlocklist checks a DNS blocklist. Its key is write-only: a
// new one comes in through NewAuthKey, ClearAuthKey removes it.
func prepareDnsBlocklist(tx *gorm.DB, b, old *models.DnsBlocklist) error {
	if err := instanceExists(tx, b.InstanceID); err != nil {
		return err
	}
	if old != nil && old.InstanceID != b.InstanceID {
		return bad("a blocklist cannot move to another virtual firewall")
	}
	b.Name = strings.ToLower(strings.TrimSpace(b.Name))
	if !fwconfig.ValidBlocklistName(b.Name) {
		return bad("name: lowercase letters, digits and '-', at most 32 characters")
	}
	switch key := strings.TrimSpace(b.NewAuthKey); {
	case key != "":
		if !fwconfig.ValidBlocklistKey(key) {
			return bad("key: letters, digits and . _ ~ -, at most 256 characters")
		}
		b.AuthKey = key
	case b.ClearAuthKey:
		b.AuthKey = ""
	}
	b.NewAuthKey, b.ClearAuthKey = "", false
	b.Urls = cleanList(b.Urls)
	if len(b.Urls) == 0 || len(b.Urls) > fwconfig.MaxBlocklistURLs {
		return bad(fmt.Sprintf("urls: enter 1 to %d", fwconfig.MaxBlocklistURLs))
	}
	keyed := false
	for _, u := range b.Urls {
		if err := fwconfig.CheckBlocklistURL(u, b.AuthKey != ""); err != nil {
			return bad(fmt.Sprintf("url %s: %v", u, err))
		}
		keyed = keyed || strings.Contains(u, fwconfig.BlocklistKeyPlaceholder)
	}
	if b.AuthKey != "" && !keyed {
		return bad("key: put " + fwconfig.BlocklistKeyPlaceholder + " in the url where it goes")
	}
	if b.Action == "" {
		b.Action = fwconfig.BlocklistNXDomain
	}
	if err := oneOf("action", b.Action, fwconfig.BlocklistNXDomain, fwconfig.BlocklistNoData, fwconfig.BlocklistDrop, fwconfig.BlocklistLog); err != nil {
		return err
	}
	if b.Refresh == 0 {
		b.Refresh = fwconfig.DefaultBlocklistRefresh
	}
	if b.Refresh < 5 || b.Refresh > 10080 {
		return bad("refresh: 5 to 10080 minutes (a week)")
	}
	if old == nil {
		var n int64
		if err := tx.Model(&models.DnsBlocklist{}).Where("instance_id = ?", b.InstanceID).Count(&n).Error; err != nil {
			return err
		}
		if n >= fwconfig.MaxBlocklists {
			return bad(fmt.Sprintf("a virtual firewall has at most %d blocklists", fwconfig.MaxBlocklists))
		}
	}
	return nil
}

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
