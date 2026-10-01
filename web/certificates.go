// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"fmt"
	"slices"
	"strings"

	"gorm.io/gorm"

	"github.com/abundo/portitor/internal/builder"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/models"
)

func prepareCertificate(tx *gorm.DB, c, _ *models.Certificate) error {
	if err := instanceExists(tx, c.InstanceID); err != nil {
		return err
	}
	c.Name = strings.TrimSpace(c.Name)
	if !fwconfig.ValidItemName(c.Name) {
		return bad("name: lowercase letters, digits, '.', '-' and '_', starting with a letter or digit, at most 63 characters")
	}
	var ifc models.Interface
	if tx.First(&ifc, c.InterfaceID).Error != nil || ifc.InstanceID != c.InstanceID {
		return bad("pick an interface of this instance")
	}
	domains := models.StringList{}
	for _, d := range c.Domains {
		if d = dnsName(d); d != "" && !slices.Contains(domains, d) {
			domains = append(domains, d)
		}
	}
	c.Domains = domains
	if len(c.Domains) == 0 {
		return bad("domains: at least one DNS name")
	}
	c.Email = strings.TrimSpace(c.Email)
	c.Ca = strings.TrimSpace(c.Ca)
	if c.Ca == "" {
		c.Ca = fwconfig.ACMECAs[0].Name
	}
	if c.KeyType == "" {
		c.KeyType = fwconfig.CertKeyTypes[0]
	}
	if c.Challenge == "" {
		c.Challenge = fwconfig.ChallengeHTTP01
	}
	return checkCertificate(builder.Certificate(c, ifc.Name))
}

// checkCertificate runs fwconfig's validation of a certificate, for a
// quick answer when an entry is saved.
func checkCertificate(cert fwconfig.Certificate) error {
	in := fwconfig.Instance{
		Name: "check", Default: true,
		Interfaces:   []fwconfig.Interface{{Name: cert.Interface, Kind: fwconfig.KindPhysical, Enabled: true, IPv4Mode: fwconfig.ModeNone}},
		Certificates: []fwconfig.Certificate{cert},
	}
	doc := fwconfig.Document{Version: fwconfig.Version, Instances: []fwconfig.Instance{in}}
	err := doc.Validate()
	if err == nil {
		return nil
	}
	ve, ok := err.(*fwconfig.ValidationError)
	if !ok {
		return err
	}
	prefix := fmt.Sprintf("instance check: certificate %q: ", cert.Name)
	msgs := make([]string, len(ve.Problems))
	for i, p := range ve.Problems {
		msgs[i] = strings.TrimPrefix(p, prefix)
	}
	return bad(strings.Join(msgs, "; "))
}

// refuseCertificateIface refuses removing an interface from its instance
// while a certificate uses it.
func refuseCertificateIface(tx *gorm.DB, i *models.Interface) error {
	return usedBy(tx, i.Name, &models.Certificate{}, "interface_id", i.ID, func() []string {
		var names []string
		tx.Model(&models.Certificate{}).Where("interface_id = ?", i.ID).Order("name").Pluck("name", &names)
		for j := range names {
			names[j] = "certificate " + names[j]
		}
		return names
	})
}
