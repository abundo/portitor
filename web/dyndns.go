// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/models"
)

func presentDyndnsClient(c *models.DyndnsClient) {
	c.HasTsigSecret = c.TsigSecret != ""
	c.NewTsigSecret = ""
	c.Settings, c.SecretsSet = map[string]string{}, []string{}
	p := fwconfig.FindDNSProvider(c.Provider)
	if p == nil {
		return
	}
	for _, f := range p.Fields {
		switch v := c.ProviderSettings[f.Key]; {
		case v == "":
		case f.Secret:
			c.SecretsSet = append(c.SecretsSet, f.Key)
		default:
			c.Settings[f.Key] = v
		}
	}
}
