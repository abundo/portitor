// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/labstack/echo/v5"
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
	prefix := fmt.Sprintf("virtual firewall check: dns update %q: ", d.Name)
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

func prepareDyndnsClient(tx *gorm.DB, c, old *models.DyndnsClient) error {
	if err := instanceExists(tx, c.InstanceID); err != nil {
		return err
	}
	c.Name = strings.TrimSpace(c.Name)
	if !fwconfig.ValidFileName(c.Name) {
		return bad("name: no control characters or /, not . or .., at most 255 bytes")
	}
	var ifc models.Interface
	if tx.First(&ifc, c.InterfaceID).Error != nil || ifc.InstanceID != c.InstanceID {
		return bad("pick an interface of this virtual firewall")
	}
	if c.Provider == "" {
		c.Provider = fwconfig.ProviderRFC2136
	}
	p := fwconfig.FindDNSProvider(c.Provider)
	if p == nil {
		return bad(fmt.Sprintf("unknown provider %q", c.Provider))
	}
	c.Zone = dnsName(c.Zone)
	if p.Name != fwconfig.ProviderRFC2136 {
		c.Server, c.TsigName, c.TsigAlgorithm, c.TsigSecret, c.NewTsigSecret = "", "", "", "", ""
		if err := mergeProviderSettings(p, c, old); err != nil {
			return err
		}
		return checkDynDNS(builder.DynDNS(c, ifc.Name, nil))
	}
	c.ProviderSettings = models.StringMap{}
	c.Server = strings.TrimSpace(c.Server)
	if _, err := fwconfig.DynDNSServer(c.Server); err != nil {
		return bad("server: the nameserver's IP address or DNS name, optionally with a port (192.0.2.53, [2001:db8::53]:53 or ns1.example.com)")
	}
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

// mergeProviderSettings stores the provider's settings c.Settings holds:
// the fields that are not secret as given, secrets when not empty (an empty
// one keeps the stored value). Without Settings (a PUT that leaves them
// out) the stored ones stay. A changed provider starts afresh.
func mergeProviderSettings(p *fwconfig.DNSProvider, c, old *models.DyndnsClient) error {
	stored := c.ProviderSettings
	if old != nil && old.Provider != c.Provider {
		stored = nil
	}
	if c.Settings == nil && stored != nil {
		c.Settings = map[string]string{}
		for k, v := range stored {
			if f := p.Field(k); f != nil && !f.Secret {
				c.Settings[k] = v
			}
		}
	}
	for k := range c.Settings {
		if p.Field(k) == nil {
			return bad(fmt.Sprintf("%s has no setting %q", p.Label, k))
		}
	}
	out := models.StringMap{}
	for _, f := range p.Fields {
		v := strings.TrimSpace(c.Settings[f.Key])
		if v == "" && f.Secret {
			v = stored[f.Key]
		}
		if v != "" {
			out[f.Key] = v
		}
	}
	c.ProviderSettings, c.Settings = out, nil
	return nil
}

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

func deleteDyndnsClient(tx *gorm.DB, c *models.DyndnsClient) error {
	return tx.Where("client_id = ?", c.ID).Delete(&models.DyndnsRecord{}).Error
}

func prepareDyndnsRecord(tx *gorm.DB, r, _ *models.DyndnsRecord) error {
	var c models.DyndnsClient
	if tx.First(&c, r.ClientID).Error != nil {
		return bad("DNS update client does not exist")
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
	// The key and provider settings are checked with the client.
	c.TsigName, c.Provider, c.Server = "", fwconfig.ProviderRFC2136, "192.0.2.53"
	return checkDynDNS(builder.DynDNS(&c, "eth0", append(records, *r)))
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

// handleDyndnsRecords is PUT /api/dyndns/clients/:id/records: the dynamic
// zone editor saves the whole grid, in order, replacing the client's records.
func (s *Server) handleDyndnsRecords(c *echo.Context) error {
	id, err := echo.PathParam[uint](c, "id")
	if err != nil {
		return errJSON(c, http.StatusNotFound, "not found")
	}
	var body []models.DyndnsRecord
	if err := json.NewDecoder(c.Request().Body).Decode(&body); err != nil {
		return errJSON(c, http.StatusBadRequest, "invalid JSON: "+err.Error())
	}
	var cl models.DyndnsClient
	if err := s.db.First(&cl, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return errJSON(c, http.StatusNotFound, "not found")
		}
		return err
	}
	if ok, err := allowInstance(c, cl.InstanceID, true); !ok {
		return err
	}
	for i := range body {
		r := &body[i]
		r.ID, r.ClientID = 0, cl.ID
		r.Name = strings.TrimSpace(r.Name)
		if r.Name == "" {
			r.Name = "@"
		}
		r.Type = strings.ToUpper(strings.TrimSpace(r.Type))
		r.Value = strings.TrimSpace(r.Value)
		if r.Type == "A" || r.Type == "AAAA" {
			r.Value = strings.ToLower(r.Value)
		}
		r.Description = strings.TrimSpace(r.Description)
		if r.Ttl < 0 {
			r.Ttl = 0
		}
		if err := oneOf("type", r.Type, fwconfig.DynDNSRecordTypes...); err != nil {
			return errJSON(c, http.StatusBadRequest, fmt.Sprintf("record %d: %v", i+1, err))
		}
		if r.Type == "CNAME" && r.Value == "" {
			return errJSON(c, http.StatusBadRequest, fmt.Sprintf("record %d: a CNAME needs its target", i+1))
		}
	}
	// Checked together, as prepareDyndnsRecord does; the key and provider
	// settings are checked with the client.
	check := cl
	check.TsigName, check.Provider, check.Server = "", fwconfig.ProviderRFC2136, "192.0.2.53"
	if err := checkDynDNS(builder.DynDNS(&check, "eth0", body)); err != nil {
		return errJSON(c, http.StatusBadRequest, err.Error())
	}
	err = s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("client_id = ?", cl.ID).Delete(&models.DyndnsRecord{}).Error; err != nil {
			return err
		}
		if len(body) == 0 {
			return nil
		}
		return tx.Create(&body).Error
	})
	if err != nil {
		return dbError(c, err)
	}
	out := []models.DyndnsRecord{}
	if err := s.db.Where("client_id = ?", cl.ID).Order("id").Find(&out).Error; err != nil {
		return err
	}
	return c.JSON(http.StatusOK, out)
}
