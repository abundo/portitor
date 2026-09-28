// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"encoding/base64"
	"fmt"
	"strings"

	"gorm.io/gorm"

	"github.com/abundo/portitor/internal/builder"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/models"
)

// checkDynDNS runs fwconfig's validation of a client, for a quick answer
// when an entry is saved. A client without records yet is fine here.
func checkDynDNS(d fwconfig.DynDNS) error {
	in := fwconfig.Instance{
		Name: "check", Default: true,
		Interfaces: []fwconfig.Interface{{Name: d.Interface, Kind: fwconfig.KindPhysical, Enabled: true, IPv4Mode: fwconfig.ModeNone}},
		DynDNS:     []fwconfig.DynDNS{d},
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
	prefix := fmt.Sprintf("instance check: dynamic dns %q: ", d.Name)
	var msgs []string
	for _, p := range ve.Problems {
		if strings.HasSuffix(p, "needs at least one record") {
			continue
		}
		msgs = append(msgs, strings.TrimPrefix(p, prefix))
	}
	if len(msgs) == 0 {
		return nil
	}
	return bad(strings.Join(msgs, "; "))
}

func prepareDyndnsClient(tx *gorm.DB, c, _ *models.DyndnsClient) error {
	if err := instanceExists(tx, c.InstanceID); err != nil {
		return err
	}
	c.Name = strings.TrimSpace(c.Name)
	if !fwconfig.ValidZoneName(c.Name) {
		return bad("name: lowercase letters, digits and _, at most 24 characters")
	}
	var ifc models.Interface
	if tx.First(&ifc, c.InterfaceID).Error != nil || ifc.InstanceID != c.InstanceID {
		return bad("pick an interface of this instance")
	}
	c.Server = strings.TrimSpace(c.Server)
	if _, err := fwconfig.DynDNSServerAddr(c.Server); err != nil {
		return bad("server: the nameserver's IP address, optionally with a port (192.0.2.53 or [2001:db8::53]:53)")
	}
	c.Zone = dnsName(c.Zone)
	c.TsigName = dnsName(c.TsigName)
	if secret := strings.TrimSpace(c.NewTsigSecret); secret != "" {
		if _, err := base64.StdEncoding.DecodeString(secret); err != nil {
			return bad("TSIG secret must be base64, as in the key file")
		}
		c.TsigSecret = secret
	}
	c.NewTsigSecret = ""
	if c.TsigName == "" {
		c.TsigAlgorithm, c.TsigSecret = "", ""
	} else {
		if c.TsigAlgorithm == "" {
			c.TsigAlgorithm = fwconfig.TSIGAlgorithms[0]
		}
		if c.TsigSecret == "" {
			return bad("a TSIG key needs its secret")
		}
	}
	var records []models.DyndnsRecord
	if c.ID != 0 {
		if err := tx.Where("client_id = ?", c.ID).Order("id").Find(&records).Error; err != nil {
			return err
		}
	}
	return checkDynDNS(builder.DynDNS(c, ifc.Name, records))
}

func presentDyndnsClient(c *models.DyndnsClient) {
	c.HasTsigSecret = c.TsigSecret != ""
	c.NewTsigSecret = ""
}

func deleteDyndnsClient(tx *gorm.DB, c *models.DyndnsClient) error {
	return tx.Where("client_id = ?", c.ID).Delete(&models.DyndnsRecord{}).Error
}

func prepareDyndnsRecord(tx *gorm.DB, r, _ *models.DyndnsRecord) error {
	var c models.DyndnsClient
	if tx.First(&c, r.ClientID).Error != nil {
		return bad("dynamic DNS client does not exist")
	}
	r.Name = strings.TrimSpace(r.Name)
	r.Type = strings.ToUpper(strings.TrimSpace(r.Type))
	r.Value = strings.TrimSpace(r.Value)
	if r.Type == "A" || r.Type == "AAAA" {
		r.Value = strings.ToLower(r.Value)
	}
	if err := oneOf("type", r.Type, fwconfig.DynDNSRecordTypes...); err != nil {
		return err
	}
	if r.Type == "CNAME" && r.Value == "" {
		return bad("a CNAME needs its target")
	}
	// Checked with the client's other records: one record per name and
	// type, no CNAME next to other types.
	var records []models.DyndnsRecord
	if err := tx.Where("client_id = ? AND id <> ?", r.ClientID, r.ID).Order("id").Find(&records).Error; err != nil {
		return err
	}
	c.TsigName = "" // the key is checked with the client
	return checkDynDNS(builder.DynDNS(&c, "eth0", append(records, *r)))
}

// refuseDyndnsIface refuses removing an interface from its instance while
// a dynamic DNS client uses it.
func refuseDyndnsIface(tx *gorm.DB, i *models.Interface) error {
	return usedBy(tx, i.Name, &models.DyndnsClient{}, "interface_id", i.ID, func() []string {
		var names []string
		tx.Model(&models.DyndnsClient{}).Where("interface_id = ?", i.ID).Order("name").Pluck("name", &names)
		for j := range names {
			names[j] = "dynamic DNS " + names[j]
		}
		return names
	})
}
