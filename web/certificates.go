// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"gorm.io/gorm"

	"github.com/abundo/portitor/internal/acme"
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
		if g := c.Generate; g != nil {
			c.Generate = nil
			if err := generateCertificate(tx, c, g); err != nil {
				return err
			}
		}
		if err := prepareImported(c); err != nil {
			return err
		}
		return checkAuthority(tx, c, old)
	}
	if c.Source != fwconfig.CertSourceACME {
		return bad("source: acme or import")
	}
	c.FullChain, c.PrivKey, c.NewPrivKey = "", "", ""
	if c.Challenge == "" {
		c.Challenge = fwconfig.ChallengeHTTP01
	}
	var ifc models.Interface
	var dc models.DyndnsClient
	switch c.Challenge {
	case fwconfig.ChallengeHTTP01:
		c.DyndnsClientID = nil
		if c.InterfaceID == nil || tx.First(&ifc, *c.InterfaceID).Error != nil || ifc.InstanceID != c.InstanceID {
			return bad("pick an interface of this virtual firewall")
		}
	case fwconfig.ChallengeDNS01:
		c.InterfaceID = nil
		if c.DyndnsClientID == nil || tx.First(&dc, *c.DyndnsClientID).Error != nil || dc.InstanceID != c.InstanceID {
			return bad("pick a DNS update client of this virtual firewall")
		}
	default:
		return bad("challenge: " + strings.Join(fwconfig.Challenges, " or "))
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
	cert := builder.Certificate(c, ifc.Name)
	if c.Challenge == fwconfig.ChallengeDNS01 {
		cert.DNS01 = builder.DNS01(&dc)
	}
	return checkCertificate(cert)
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
	c.Email, c.Ca, c.KeyType, c.Challenge, c.InterfaceID, c.DyndnsClientID = "", "", "", "", nil, nil
	return checkCertificate(builder.Certificate(c, ""))
}

// generateCertificate puts a new certificate and key, made as g asks, in
// c's chain and new key: a CA, or a server certificate self-signed or
// signed by a CA of its firewall.
func generateCertificate(tx *gorm.DB, c *models.Certificate, g *models.CertGenerate) error {
	san := func(d string) bool {
		_, err := netip.ParseAddr(d)
		return err == nil || fwconfig.ValidDomain(strings.TrimPrefix(d, "*."))
	}
	var names []string
	for _, d := range g.Domains {
		d = dnsName(d)
		if a, err := netip.ParseAddr(d); err == nil {
			d = a.Unmap().WithZone("").String()
		} else if d != "" && !san(d) {
			return bad(fmt.Sprintf("subject alternative names: %q is neither a DNS name nor an IP address", d))
		}
		if d != "" && !slices.Contains(names, d) {
			names = append(names, d)
		}
	}
	cn := strings.TrimSpace(g.CommonName)
	if !g.CA {
		cn = dnsName(cn)
	}
	if len(cn) > 64 || strings.ContainsFunc(cn, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return bad("common name: at most 64 characters, no control characters")
	}
	req := acme.CertRequest{KeyType: g.KeyType, Days: g.Days, CA: g.CA}
	if g.CA {
		if g.CAID != nil {
			return bad("a CA here is self-signed: it signs server certificates, no other CA")
		}
		if len(names) > 0 {
			return bad("a CA has no subject alternative names")
		}
		if cn == "" {
			cn = c.Name
		}
	} else {
		if cn != "" && !slices.Contains(names, cn) && san(cn) {
			names = slices.Insert(names, 0, cn)
		}
		if len(names) == 0 || len(names) > 100 {
			return bad("subject alternative names: 1-100 DNS names or IP addresses")
		}
		if cn == "" {
			cn = names[0]
		}
	}
	req.CommonName, req.Names = cn, names
	if req.KeyType == "" {
		req.KeyType = fwconfig.CertKeyTypes[0]
	}
	if !slices.Contains(fwconfig.CertKeyTypes, req.KeyType) {
		return bad("key type: one of " + strings.Join(fwconfig.CertKeyTypes, ", "))
	}
	if g.Days < 1 || g.Days > 36500 {
		return bad("valid for: 1-36500 days")
	}
	if id := g.CAID; id != nil {
		ca, err := firewallCA(tx, *id, c.InstanceID)
		if err != nil {
			return err
		}
		req.IssuerChain, req.IssuerKey = ca.FullChain, ca.PrivKey
	}
	chain, key, err := acme.MakeCertificate(req)
	if err != nil {
		return bad(err.Error())
	}
	c.FullChain, c.NewPrivKey = chain, key
	return nil
}

// firewallCA is the CA certificate id, which must be on the host of the
// firewall instance is on.
func firewallCA(tx *gorm.DB, id, instance uint) (*models.Certificate, error) {
	var ca models.Certificate
	var host, in models.Instance
	if tx.First(&ca, id).Error != nil || ca.Source != fwconfig.CertSourceImport || !isCA(&ca) ||
		tx.First(&host, ca.InstanceID).Error != nil || tx.First(&in, instance).Error != nil ||
		!host.IsDefault || host.FirewallID != in.FirewallID {
		return nil, bad("signed by: pick a CA of this firewall")
	}
	return &ca, nil
}

// isCA says whether c is an imported certificate authority.
func isCA(c *models.Certificate) bool {
	leaf := fwconfig.ChainLeaf(c.FullChain)
	return c.Source == fwconfig.CertSourceImport && leaf != nil && leaf.IsCA
}

// checkAuthority keeps a CA, made or imported, on its firewall's host:
// it belongs to the firewall, not to a virtual firewall. A certificate
// stays what it was, a CA or not.
func checkAuthority(tx *gorm.DB, c, old *models.Certificate) error {
	ca := isCA(c)
	if old != nil && isCA(old) != ca {
		return bad("certificate: can't change between a CA and a server certificate; add a new one")
	}
	if !ca {
		return nil
	}
	var in models.Instance
	if err := tx.First(&in, c.InstanceID).Error; err != nil {
		return err
	}
	if !in.IsDefault {
		return bad("a CA belongs to the firewall: add it on the firewall's host, not in a virtual firewall")
	}
	return nil
}

// tenantCertificate refuses an instance admin signing with the firewall's
// CA, which global admins keep.
func tenantCertificate(c, _ *models.Certificate) error {
	if c != nil && c.Generate != nil && (c.Generate.CAID != nil || c.Generate.CA) {
		return bad("certificate authorities: global admins only")
	}
	return nil
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
		c.NotBefore, c.NotAfter = &leaf.NotBefore, &leaf.NotAfter
	}
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

// refuseCertificateDyndns refuses deleting a DNS update client while a
// certificate's DNS-01 challenge uses it.
func refuseCertificateDyndns(tx *gorm.DB, dc *models.DyndnsClient) error {
	return usedBy(tx, "DNS update "+dc.Name, &models.Certificate{}, "dyndns_client_id", dc.ID, func() []string {
		var names []string
		tx.Model(&models.Certificate{}).Where("dyndns_client_id = ?", dc.ID).Order("name").Pluck("name", &names)
		for j := range names {
			names[j] = "certificate " + names[j]
		}
		return names
	})
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
