// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"errors"
	"net/http"

	"github.com/labstack/echo/v5"
	"gorm.io/gorm"

	"github.com/abundo/portitor/internal/nftimport"
	"github.com/abundo/portitor/models"
)

// Import of an nftables file into a virtual firewall: the agent reads the
// file with nft (in a network namespace of its own), nftimport maps it,
// and the rows are written as uncommitted changes, each through the same
// checks as the CRUD. A preview runs the same transaction and rolls it
// back. Hosts/prefixes and services are shared, so this is a global
// admin's (a POST not in tenantWrites).

type nftImportRequest struct {
	InstanceID uint   `json:"instance_id"`
	Text       string `json:"text"`
	// Rename maps the file's interface names to the virtual firewall's.
	Rename map[string]string `json:"rename"`
	// Replace deletes the virtual firewall's rules and NAT rules first.
	Replace bool `json:"replace"`
	// Apply writes the rows; without it the answer is a preview.
	Apply bool `json:"apply"`
}

// errPreview rolls a preview's transaction back.
var errPreview = errors.New("preview")

func (s *Server) handleImportNftables(c *echo.Context) error {
	var req nftImportRequest
	if err := c.Bind(&req); err != nil {
		return errJSON(c, http.StatusBadRequest, "bad request")
	}
	if err := instanceExists(s.db, req.InstanceID); err != nil {
		return errJSON(c, http.StatusBadRequest, "no such virtual firewall")
	}
	a, _, err := s.agent()
	if err != nil {
		return agentError(c, err)
	}
	parsed, err := a.ParseNftables(c.Request().Context(), req.Text)
	if err != nil {
		return agentError(c, err)
	}
	opt, err := s.importOptions(req)
	if err != nil {
		return err
	}
	res, err := nftimport.Import(parsed.JSON, parsed.Text, opt)
	if err != nil {
		return errJSON(c, http.StatusBadRequest, err.Error())
	}
	err = s.db.Transaction(func(tx *gorm.DB) error {
		if err := writeImport(tx, req, res); err != nil {
			return err
		}
		if !req.Apply {
			return errPreview
		}
		return nil
	})
	if err != nil && !errors.Is(err, errPreview) {
		return dbError(c, err)
	}
	return c.JSON(http.StatusOK, res)
}

func (s *Server) importOptions(req nftImportRequest) (nftimport.Options, error) {
	opt := nftimport.Options{Objects: map[string][]string{}, Services: map[string]models.Service{}, Rename: req.Rename}
	var objs []models.AddressObject
	if err := s.db.Find(&objs).Error; err != nil {
		return opt, err
	}
	for _, o := range objs {
		opt.Objects[o.Name] = o.Addresses
	}
	var svcs []models.Service
	if err := s.db.Find(&svcs).Error; err != nil {
		return opt, err
	}
	for _, sv := range svcs {
		opt.Services[sv.Name] = sv
	}
	names, err := ifaceNames(s.db, req.InstanceID)
	if err != nil {
		return opt, err
	}
	var zones []string
	if err := s.db.Model(&models.InterfaceZone{}).Where("instance_id = ?", req.InstanceID).Pluck("name", &zones).Error; err != nil {
		return opt, err
	}
	for _, z := range zones {
		names[z] = true
	}
	opt.Interfaces = names
	return opt, nil
}

// writeImport writes res's rows. A rule or NAT rule the checks refuse
// moves to res.Skipped; a host/prefix or service they refuse fails the
// import, since rules may name it.
func writeImport(tx *gorm.DB, req nftImportRequest, res *nftimport.Result) error {
	if req.Replace {
		if err := tx.Where("instance_id = ?", req.InstanceID).Delete(&models.Rule{}).Error; err != nil {
			return err
		}
		if err := tx.Where("instance_id = ?", req.InstanceID).Delete(&models.NatRule{}).Error; err != nil {
			return err
		}
	}
	for i := range res.Objects {
		o := &res.Objects[i]
		if err := prepareAddressObject(tx, o, nil); err != nil {
			return bad("host/prefix " + o.Name + ": " + err.Error())
		}
		if err := tx.Create(o).Error; err != nil {
			return err
		}
	}
	for i := range res.Services {
		sv := &res.Services[i]
		if err := prepareService(tx, sv, nil); err != nil {
			return bad("service " + sv.Name + ": " + err.Error())
		}
		if err := tx.Create(sv).Error; err != nil {
			return err
		}
	}
	rules := res.Rules[:0]
	for _, r := range res.Rules {
		r.InstanceID = req.InstanceID
		if err := prepareRule(tx, &r, nil); err != nil {
			res.Skipped = append(res.Skipped, refused(r.Chain, r.Description, err))
			continue
		}
		if err := tx.Create(&r).Error; err != nil {
			return err
		}
		rules = append(rules, r)
	}
	res.Rules = rules
	nat := res.NAT[:0]
	for _, n := range res.NAT {
		n.InstanceID = req.InstanceID
		if err := prepareNat(tx, &n, nil); err != nil {
			res.Skipped = append(res.Skipped, refused(n.Kind, n.Description, err))
			continue
		}
		if err := tx.Create(&n).Error; err != nil {
			return err
		}
		nat = append(nat, n)
	}
	res.NAT = nat
	return nil
}

func refused(where, text string, err error) nftimport.Skipped {
	return nftimport.Skipped{Where: where, Text: text, Reason: "Portitor refused it: " + err.Error()}
}
