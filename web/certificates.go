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

func prepareCertificate(tx *gorm.DB, c, old *models.Certificate) error {
	if err := instanceExists(tx, c.InstanceID); err != nil {
		return err
	}
	c.Name = strings.TrimSpace(c.Name)
	if !fwconfig.ValidFileName(c.Name) {
		return bad("name: no control characters or /, not . or .., at most 255 bytes")
	}
	if c.Source == "" {
		c.Source = fwconfig.CertSourceACME
	}
	if old != nil && old.Source != c.Source {
		return bad("source: can't change; add a new certificate")
	}
	if c.Source == fwconfig.CertSourceImport {
		return prepareImported(c)
	}
	if c.Source != fwconfig.CertSourceACME {
		return bad("source: acme or import")
	}
	c.FullChain, c.PrivKey, c.NewPrivKey = "", "", ""
	var ifc models.Interface
	if c.InterfaceID == nil || tx.First(&ifc, *c.InterfaceID).Error != nil || ifc.InstanceID != c.InstanceID {
		return bad("pick an interface of this virtual firewall")
	}
	domains := models.StringList{}
	for _, d := range c.Domains {
		if d = dnsName(d); d != "" && !slices.Contains(domains, d) {
			domains = append(domains, d)
		}
	}
	c.Domains = domains
	if len(c.Domains) == 0 {
		return bad("subject alternative names: at least one DNS name")
	}
	// The CN must be one of the SANs: add it when it isn't.
	c.CommonName = dnsName(c.CommonName)
	if len(c.CommonName) > 64 {
		return bad("common name: at most 64 characters")
	}
	if c.CommonName != "" && !slices.Contains(c.Domains, c.CommonName) {
		c.Domains = slices.Insert(c.Domains, 0, c.CommonName)
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

// prepareImported checks an imported certificate's chain and key (a new
// key replaces the stored one, and a new chain must match the key) and
// takes its SANs from it.
func prepareImported(c *models.Certificate) error {
	if key := strings.TrimSpace(c.NewPrivKey); key != "" {
		c.PrivKey = key + "\n"
	}
	c.NewPrivKey = ""
	c.FullChain = strings.TrimSpace(c.FullChain) + "\n"
	leaf, err := fwconfig.ParseImported(c.FullChain, c.PrivKey)
	if err != nil {
		return bad("certificate and key: " + err.Error())
	}
	c.Domains = models.StringList(slices.Clone(leaf.DNSNames))
	for _, ip := range leaf.IPAddresses {
		c.Domains = append(c.Domains, ip.String())
	}
	c.CommonName = leaf.Subject.CommonName
	c.Email, c.Ca, c.KeyType, c.Challenge, c.InterfaceID = "", "", "", "", nil
	return checkCertificate(builder.Certificate(c, ""))
}

// presentCertificate hides an imported certificate's key.
func presentCertificate(c *models.Certificate) {
	c.HasPrivKey, c.NewPrivKey = c.PrivKey != "", ""
}

// checkCertificate runs fwconfig's validation of a certificate, for a
// quick answer when an entry is saved.
func checkCertificate(cert fwconfig.Certificate) error {
	in := fwconfig.Instance{Name: "check", Default: true, Certificates: []fwconfig.Certificate{cert}}
	if cert.Interface != "" {
		in.Interfaces = []fwconfig.Interface{{Name: cert.Interface, Kind: fwconfig.KindPhysical, Enabled: true, IPv4Mode: fwconfig.ModeNone}}
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
	prefix := fmt.Sprintf("virtual firewall check: certificate %q: ", cert.Name)
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
