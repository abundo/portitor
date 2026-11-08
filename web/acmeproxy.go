// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"strings"

	"gorm.io/gorm"

	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/models"
)

// The ACME proxy, per instance: the instance's acme_proxy_* fields
// (prepareInstanceACMEProxy), its interfaces' acme_proxy_serve, and its
// policies, each getting its names upstream by DNS-01 (a DNS update
// client) or HTTP-01 (an interface).

func prepareInstanceACMEProxy(tx *gorm.DB, in *models.Instance) error {
	if in.AcmeProxyPort == 0 {
		in.AcmeProxyPort = 8555
	}
	if in.AcmeProxyPort < 1 || in.AcmeProxyPort > 65535 {
		return bad("ACME proxy: port must be 1-65535")
	}
	in.AcmeProxyCa = strings.TrimSpace(in.AcmeProxyCa)
	if in.AcmeProxyCa == "" {
		in.AcmeProxyCa = fwconfig.ACMECAs[0].Name
	}
	if _, err := fwconfig.ACMEDirectory(in.AcmeProxyCa); err != nil {
		return bad("ACME proxy: " + err.Error())
	}
	in.AcmeProxyEmail = strings.TrimSpace(in.AcmeProxyEmail)
	if in.AcmeProxyEmail != "" && !fwconfig.ValidEmail(in.AcmeProxyEmail) {
		return bad("ACME proxy: invalid email")
	}
	if id := in.AcmeProxyCertificateID; id != nil {
		var c models.Certificate
		if tx.First(&c, *id).Error != nil || c.InstanceID != in.ID {
			return bad("ACME proxy: pick a certificate of this virtual firewall")
		}
		if err := refuseCA(&c, "ACME proxy"); err != nil {
			return err
		}
	}
	if in.AcmeProxyEnabled {
		var n int64
		if in.ID != 0 {
			if err := tx.Model(&models.AcmeProxyPolicy{}).Where("instance_id = ? AND enabled", in.ID).Count(&n).Error; err != nil {
				return err
			}
		}
		if n == 0 {
			return bad("ACME proxy: add a policy first")
		}
	}
	return nil
}

// refuseProxyIface refuses removing an interface from its instance while
// an ACME proxy policy answers HTTP-01 on it.
func refuseProxyIface(tx *gorm.DB, i *models.Interface) error {
	return usedBy(tx, i.Name, &models.AcmeProxyPolicy{}, "interface_id", i.ID, func() []string {
		var names []string
		tx.Model(&models.AcmeProxyPolicy{}).Where("interface_id = ?", i.ID).Order("name").Pluck("name", &names)
		for j := range names {
			names[j] = "ACME proxy policy " + names[j]
		}
		return names
	})
}
