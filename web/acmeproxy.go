// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"fmt"
	"slices"
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

func prepareAcmeProxyPolicy(tx *gorm.DB, p, old *models.AcmeProxyPolicy) error {
	if old != nil {
		p.InstanceID = old.InstanceID
	}
	if err := instanceExists(tx, p.InstanceID); err != nil {
		return err
	}
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" || len(p.Name) > 64 || strings.ContainsFunc(p.Name, func(c rune) bool { return c < 0x20 || c == 0x7f }) {
		return bad("name: 1-64 characters, one line")
	}
	var n int64
	if err := tx.Model(&models.AcmeProxyPolicy{}).Where("instance_id = ? AND name = ? AND id <> ?", p.InstanceID, p.Name, p.ID).Count(&n).Error; err != nil {
		return err
	}
	if n > 0 {
		return bad("there is already a policy " + p.Name)
	}
	domains := models.StringList{}
	for _, d := range p.Domains {
		if d = dnsName(d); d != "" && !slices.Contains(domains, d) {
			if err := fwconfig.ACMEProxyDomain(d); err != nil {
				return bad("domains: " + err.Error())
			}
			domains = append(domains, d)
		}
	}
	if len(domains) == 0 || len(domains) > 100 {
		return bad("domains: 1-100 names")
	}
	p.Domains = domains
	p.Sources = cleanList(p.Sources)
	if err := checkEntries(tx, "sources", p.Sources, entryCIDR); err != nil {
		return err
	}
	if p.Challenge == "" {
		p.Challenge = fwconfig.ChallengeDNS01
	}
	switch p.Challenge {
	case fwconfig.ChallengeHTTP01:
		p.DyndnsClientID = nil
		var ifc models.Interface
		if p.InterfaceID == nil || tx.First(&ifc, *p.InterfaceID).Error != nil || ifc.InstanceID != p.InstanceID {
			return bad("pick an interface of this virtual firewall")
		}
	case fwconfig.ChallengeDNS01:
		p.InterfaceID = nil
		var dc models.DyndnsClient
		if p.DyndnsClientID == nil || tx.First(&dc, *p.DyndnsClientID).Error != nil || dc.InstanceID != p.InstanceID {
			return bad("pick a DNS update client of this virtual firewall")
		}
	default:
		return bad("challenge: " + strings.Join(fwconfig.Challenges, " or "))
	}
	return nil
}

// deleteAcmeProxyPolicy refuses deleting the last enabled policy of a
// running proxy.
func deleteAcmeProxyPolicy(tx *gorm.DB, p *models.AcmeProxyPolicy) error {
	var in models.Instance
	if err := tx.First(&in, p.InstanceID).Error; err != nil || !in.AcmeProxyEnabled || !p.Enabled {
		return nil
	}
	var n int64
	if err := tx.Model(&models.AcmeProxyPolicy{}).Where("instance_id = ? AND enabled AND id <> ?", p.InstanceID, p.ID).Count(&n).Error; err != nil {
		return err
	}
	if n == 0 {
		return bad("the ACME proxy needs a policy: turn it off first")
	}
	return nil
}

// refuseProxyDyndns refuses deleting a DNS update client an ACME proxy
// policy uses.
func refuseProxyDyndns(tx *gorm.DB, dc *models.DyndnsClient) error {
	return usedBy(tx, "DNS update "+dc.Name, &models.AcmeProxyPolicy{}, "dyndns_client_id", dc.ID, func() []string {
		var names []string
		tx.Model(&models.AcmeProxyPolicy{}).Where("dyndns_client_id = ?", dc.ID).Order("name").Pluck("name", &names)
		for i := range names {
			names[i] = "ACME proxy policy " + names[i]
		}
		return names
	})
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

// deleteCertificate refuses deleting the certificate an ACME proxy
// presents.
func deleteCertificate(tx *gorm.DB, c *models.Certificate) error {
	var n int64
	if err := tx.Model(&models.Instance{}).Where("acme_proxy_certificate_id = ?", c.ID).Count(&n).Error; err != nil {
		return err
	}
	if n > 0 {
		return bad(fmt.Sprintf("certificate %s is used by the ACME proxy", c.Name))
	}
	return nil
}
