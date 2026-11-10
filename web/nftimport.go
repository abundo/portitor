// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"errors"
	"net/http"
	"slices"

	"github.com/labstack/echo/v5"

	"github.com/abundo/portitor/internal/confview"
	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/nftimport"
	"github.com/abundo/portitor/models"
)

// Import of an nftables file into a virtual firewall: the agent reads the
// file with nft (in a network namespace of its own), nftimport maps it,
// and its entries are written into the candidate, each through the checks
// of an API edit (addChecked, userEdit). A preview makes the same edit and
// throws it away. Hosts/prefixes and services are shared, so this is a global
// admin's (a POST not in tenantWrites).

type nftImportRequest struct {
	// Instance is the virtual firewall's name.
	Instance string `json:"instance"`
	Text     string `json:"text"`
	// Rename maps the file's interface names to the virtual firewall's.
	Rename map[string]string `json:"rename"`
	// Replace deletes the virtual firewall's rules and NAT rules first.
	Replace bool `json:"replace"`
	// Apply keeps the edit; without it the answer is a preview.
	Apply bool `json:"apply"`
}

// errPreview throws a preview's edit away.
var errPreview = errors.New("preview")

func (s *Server) handleImportNftables(c *echo.Context) error {
	var req nftImportRequest
	if err := c.Bind(&req); err != nil {
		return errJSON(c, http.StatusBadRequest, "bad request")
	}
	ctx := c.Request().Context()
	v, err := s.view(ctx)
	if err != nil {
		return err
	}
	inst, err := s.namedInstance(c, req.Instance, true)
	if inst == nil {
		return err
	}
	a, _, err := s.firewallAgent(inst.FirewallID)
	if err != nil {
		return agentError(c, err)
	}
	parsed, err := a.ParseNftables(ctx, req.Text)
	if err != nil {
		return agentError(c, err)
	}
	res, err := nftimport.Import(parsed.JSON, parsed.Text, importOptions(v, inst.ID, req))
	if err != nil {
		return errJSON(c, http.StatusBadRequest, err.Error())
	}
	ws, err := s.userEdit(c, func(work *datastore.Tree) error {
		if err := s.writeImport(work, inst, req, res); err != nil {
			return err
		}
		if !req.Apply {
			return errPreview
		}
		return nil
	})
	if err != nil && !errors.Is(err, errPreview) {
		return editError(c, err)
	}
	warn(c, ws)
	return c.JSON(http.StatusOK, res)
}

func importOptions(v *confview.View, instanceID uint, req nftImportRequest) nftimport.Options {
	opt := nftimport.Options{Objects: map[string][]string{}, Services: map[string]models.Service{}, Rename: req.Rename}
	for _, o := range v.AddressObjects {
		opt.Objects[o.Name] = o.Addresses
	}
	// Address lists share the names; one with the same literals is used.
	for _, l := range v.AddressLists {
		opt.Objects[l.Name] = l.Entries
	}
	for _, sv := range v.Services {
		opt.Services[sv.Name] = sv
	}
	names := ifaceNamesIn(v, instanceID)
	for _, z := range v.InterfaceZones {
		if z.InstanceID == instanceID {
			names[z.Name] = true
		}
	}
	opt.Interfaces = names
	return opt
}

// writeImport adds res's entries to work. A rule or NAT rule the checks
// refuse moves to res.Skipped; a host/prefix or service they refuse fails
// the import, since rules may name it.
func (s *Server) writeImport(work *datastore.Tree, inst *models.Instance, req nftImportRequest, res *nftimport.Result) error {
	at := datastore.Path{{Name: "instance", Keys: []string{inst.Name}}}
	if req.Replace {
		for _, list := range []string{"rule", "nat-rule"} {
			if err := work.EditJSON(append(slices.Clone(at), datastore.Elem{Name: list}), datastore.EditReplace, []byte("[]")); err != nil {
				return err
			}
		}
	}
	w, err := s.rowWriter(work)
	if err != nil {
		return err
	}
	for i := range res.Objects {
		o := &res.Objects[i]
		if err := addChecked(w, o); err != nil {
			return bad("host/prefix " + o.Name + ": " + errText(err))
		}
	}
	for i := range res.Services {
		sv := &res.Services[i]
		if err := addChecked(w, sv); err != nil {
			return bad("service " + sv.Name + ": " + errText(err))
		}
	}
	rules := res.Rules[:0]
	for _, r := range res.Rules {
		r.InstanceID = inst.ID
		if err := addChecked(w, &r); err != nil {
			res.Skipped = append(res.Skipped, refused(r.Chain, r.Description, err))
			continue
		}
		rules = append(rules, r)
	}
	res.Rules = rules
	nat := res.NAT[:0]
	for _, n := range res.NAT {
		n.InstanceID = inst.ID
		if err := addChecked(w, &n); err != nil {
			res.Skipped = append(res.Skipped, refused(n.Kind, n.Description, err))
			continue
		}
		nat = append(nat, n)
	}
	res.NAT = nat
	return nil
}

func refused(where, text string, err error) nftimport.Skipped {
	return nftimport.Skipped{Where: where, Text: text, Reason: "Portitor refused it: " + errText(err)}
}
