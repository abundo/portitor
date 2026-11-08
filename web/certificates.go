// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/models"
)

// isCA says whether c is an imported certificate authority.
func isCA(c *models.Certificate) bool {
	leaf := fwconfig.ChainLeaf(c.FullChain)
	return c.Source == fwconfig.CertSourceImport && leaf != nil && leaf.IsCA
}

// refuseCA refuses a CA where a server certificate is needed (what, e.g.
// "the GUI's certificate").
func refuseCA(c *models.Certificate, what string) error {
	if isCA(c) {
		return bad(fmt.Sprintf("%s: %s is a certificate authority; pick a server certificate", what, c.Name))
	}
	return nil
}

// presentCertificate hides an imported certificate's key and shows what
// its chain says.
func presentCertificate(c *models.Certificate) {
	c.HasPrivKey, c.NewPrivKey = c.PrivKey != "", ""
	if c.Source != fwconfig.CertSourceImport {
		return
	}
	if leaf := fwconfig.ChainLeaf(c.FullChain); leaf != nil {
		c.IsCA, c.Issuer = leaf.IsCA, leaf.Issuer.CommonName
		c.Chain = fwconfig.ChainPath(c.FullChain)
		c.NotBefore, c.NotAfter = &leaf.NotBefore, &leaf.NotAfter
	}
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
