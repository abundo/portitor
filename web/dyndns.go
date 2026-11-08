// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"gorm.io/gorm"

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

// refuseDyndnsIface refuses removing an interface from its instance while
// a dynamic DNS client uses it.
func refuseDyndnsIface(tx *gorm.DB, i *models.Interface) error {
	return usedBy(tx, i.Name, &models.DyndnsClient{}, "interface_id", i.ID, func() []string {
		var names []string
		tx.Model(&models.DyndnsClient{}).Where("interface_id = ?", i.ID).Order("name").Pluck("name", &names)
		for j := range names {
			names[j] = "DNS update " + names[j]
		}
		return names
	})
}
