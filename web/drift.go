// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"errors"
	"log/slog"
	"net/http"
	"sort"

	"github.com/labstack/echo/v5"

	"github.com/abundo/portitor/models"
)

// Drift compares the virtual firewalls of a firewall with portitor-config
// here and there, by InstanceHash. One changed there (break-glass) is
// settled by taking that version here, or overwriting it with this one;
// the next commit pushes the rest.

// Drift states.
const (
	driftSame     = "same"
	driftHere     = "changed here"     // pushed at the next commit
	driftThere    = "changed there"    // break-glass: take or overwrite
	driftNew      = "not pushed yet"   // pushed at the next commit
	driftGone     = "deleted here"     // deleted there at the next commit
	driftTheirs   = "the firewall's"   // its own, not managed
	driftConflict = "name taken there" // the firewall's own of a name here
)

type driftItem struct {
	Name     string `json:"name"`
	State    string `json:"state"`
	Here     string `json:"here,omitempty"`
	There    string `json:"there,omitempty"`
	Diverged bool   `json:"diverged,omitempty"`
}

func (s *Server) configFirewall(c *echo.Context) (*models.Firewall, configAPI, error) {
	id, err := echo.PathParam[uint](c, "id")
	if err != nil {
		return nil, nil, bad("not found")
	}
	var fw models.Firewall
	if err := s.db.First(&fw, id).Error; err != nil {
		return nil, nil, bad("no such firewall")
	}
	if fw.ConfigURL == "" {
		return nil, nil, bad("firewall " + fw.Name + " has no portitor-config")
	}
	cfg, err := s.newConfig(&fw)
	if err != nil {
		return nil, nil, bad(err.Error())
	}
	return &fw, cfg, nil
}

func (s *Server) handleDrift(c *echo.Context) error {
	fw, cfg, err := s.configFirewall(c)
	if err != nil {
		return dbError(c, err)
	}
	st, err := cfg.State(c.Request().Context())
	if err != nil {
		return agentError(c, err)
	}
	me := s.managerName()
	var mine []models.Instance
	if err := s.db.Where("firewall_id = ? AND NOT is_default", fw.ID).Find(&mine).Error; err != nil {
		return err
	}
	out := []driftItem{}
	seen := map[string]bool{}
	for _, in := range mine {
		h, err := InstanceHash(s.db, in.Name)
		if err != nil {
			return dbError(c, err)
		}
		it := driftItem{Name: in.Name, Here: h, State: driftNew}
		for _, t := range st.Instances {
			if t.Name != in.Name {
				continue
			}
			it.There, it.Diverged = t.Hash, t.Diverged
			switch {
			case t.ManagedBy != me:
				it.State = driftConflict
			case t.Diverged && t.Hash != h:
				it.State = driftThere
			case t.Hash != h:
				it.State = driftHere
			default:
				it.State = driftSame
			}
		}
		seen[in.Name] = true
		out = append(out, it)
	}
	for _, t := range st.Instances {
		if seen[t.Name] || t.Default {
			continue
		}
		it := driftItem{Name: t.Name, There: t.Hash, Diverged: t.Diverged, State: driftTheirs}
		if t.ManagedBy == me {
			it.State = driftGone
		}
		out = append(out, it)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return c.JSON(http.StatusOK, out)
}

// handleDriftSettle takes the firewall's version of a virtual firewall
// here (take), or puts this one there in its place (overwrite).
func (s *Server) handleDriftSettle(c *echo.Context) error {
	fw, cfg, err := s.configFirewall(c)
	if err != nil {
		return dbError(c, err)
	}
	var req struct {
		Action string `json:"action"`
	}
	_ = c.Bind(&req)
	name := c.Param("name")
	ctx := c.Request().Context()
	s.deployMu.Lock()
	defer s.deployMu.Unlock()
	var in models.Instance
	if err := s.db.Where("name = ? AND firewall_id = ? AND NOT is_default", name, fw.ID).First(&in).Error; err != nil {
		return errJSON(c, http.StatusNotFound, "no virtual firewall "+name+" on "+fw.Name+" here")
	}
	switch req.Action {
	case "take":
		b, err := cfg.Bundle(ctx, name)
		if err != nil {
			return agentError(c, err)
		}
		_, problems, err := importBundle(ctx, s.db, b, name, fw.ID, importOptions{ReplaceLocal: true})
		var conflict *bundleConflict
		switch {
		case errors.As(err, &conflict):
			return errJSON(c, http.StatusConflict, conflict.msg)
		case err != nil:
			return dbError(c, err)
		}
		// The same again there: no longer diverged.
		if err := s.pushOne(c, cfg, name); err != nil {
			return agentError(c, err)
		}
		slog.Info("drift: took the firewall's version", "firewall", fw.Name, "instance", name, "user", currentUser(c).Username)
		if problems == nil {
			problems = []string{}
		}
		return c.JSON(http.StatusOK, map[string]any{"taken": name, "problems": problems})
	case "overwrite":
		if err := s.pushOne(c, cfg, name); err != nil {
			return agentError(c, err)
		}
		slog.Info("drift: overwrote the firewall's version", "firewall", fw.Name, "instance", name, "user", currentUser(c).Username)
		return c.JSON(http.StatusOK, map[string]any{"overwritten": name})
	}
	return errJSON(c, http.StatusBadRequest, "action: take or overwrite")
}

// pushOne pushes this database's virtual firewall over the firewall's.
func (s *Server) pushOne(c *echo.Context, cfg configAPI, name string) error {
	var in models.Instance
	if err := s.db.Where("name = ?", name).First(&in).Error; err != nil {
		return err
	}
	b, err := ExportBundle(c.Request().Context(), s.db, in.ID)
	if err != nil {
		return err
	}
	_, err = cfg.Push(c.Request().Context(), name, s.managerName(), true, b)
	return err
}
