// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"unicode"

	"github.com/labstack/echo/v5"

	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/records"
	"github.com/abundo/portitor/models"
)

// instanceRolePrefix starts the name of each instance's role; a role made
// by hand can't use it.
const instanceRolePrefix = "vf-"

func instanceRoleName(instance string) string { return instanceRolePrefix + instance }

// instanceKeep are the names of the instances in the trees.
func instanceKeep(trees ...*datastore.Tree) []string {
	keep := []string{}
	for _, t := range trees {
		for _, in := range t.Root.Lists["instance"] {
			keep = append(keep, in.Leaf("name"))
		}
	}
	return keep
}

// dropInstanceRoles removes the roles and grants of the instances that
// neither running nor the candidate has, after a commit: until then a
// delete can be taken back without losing the members.
func (s *Server) dropInstanceRoles(trees ...*datastore.Tree) error {
	return s.rec.DropInstanceRoles(instanceKeep(trees...))
}

type roleRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Members     []struct {
		UserID uint   `json:"user_id"`
		Level  string `json:"level"`
	} `json:"members"`
	// Instances: the instances a role made by hand grants, by name.
	Instances []string `json:"instances"`
}

func (s *Server) handleListRoles(c *echo.Context) error {
	roles, err := s.rec.Roles()
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, roles)
}

func (s *Server) handleCreateRole(c *echo.Context) error {
	return s.saveRole(c, nil)
}

func (s *Server) handleUpdateRole(c *echo.Context) error {
	id, err := echo.PathParam[uint](c, "id")
	if err != nil {
		return errJSON(c, http.StatusNotFound, "not found")
	}
	r, err := s.rec.Role(id)
	if err != nil {
		return errJSON(c, http.StatusNotFound, "not found")
	}
	return s.saveRole(c, r)
}

// saveRole creates a role (old nil) or updates one, and replaces its
// members. An instance's role keeps its name.
func (s *Server) saveRole(c *echo.Context, old *models.Role) error {
	var req roleRequest
	if err := json.NewDecoder(c.Request().Body).Decode(&req); err != nil {
		return errJSON(c, http.StatusBadRequest, "invalid JSON: "+err.Error())
	}
	r := models.Role{}
	if old != nil {
		r = *old
	}
	req.Name = strings.TrimSpace(req.Name)
	if r.Instance == nil {
		if !fwconfig.ValidName(req.Name) {
			return errJSON(c, http.StatusBadRequest, "name: not empty, no control characters")
		}
		if strings.HasPrefix(req.Name, instanceRolePrefix) {
			return errJSON(c, http.StatusBadRequest, "name: "+instanceRolePrefix+"… is reserved for the virtual firewalls' roles")
		}
		r.Name = req.Name
	}
	r.Description = strings.TrimSpace(req.Description)
	if strings.ContainsFunc(r.Description, unicode.IsControl) {
		return errJSON(c, http.StatusBadRequest, "description: no control characters")
	}
	seen := map[uint]bool{}
	for _, m := range req.Members {
		if !validLevel(m.Level) {
			return errJSON(c, http.StatusBadRequest, "member level must be admin or viewer")
		}
		if seen[m.UserID] {
			return errJSON(c, http.StatusBadRequest, "a user is listed twice")
		}
		seen[m.UserID] = true
	}
	if r.Instance != nil {
		req.Instances = nil // its instance, always
	}
	slices.Sort(req.Instances)
	req.Instances = slices.Compact(req.Instances)
	if len(req.Instances) > 0 {
		known, err := s.instanceNamesKnown(c.Request().Context())
		if err != nil {
			return err
		}
		for _, name := range req.Instances {
			if !known[name] {
				return errJSON(c, http.StatusBadRequest, "no such virtual firewall: "+name)
			}
		}
	}
	members := make([]models.RoleMember, len(req.Members))
	for i, m := range req.Members {
		members[i] = models.RoleMember{UserID: m.UserID, Level: m.Level}
	}
	err := s.rec.SaveRole(&r, members, req.Instances)
	if errors.Is(err, records.ErrNoSuchUser) {
		err = bad("no such user")
	}
	if err != nil {
		return writeError(c, err)
	}
	status := http.StatusOK
	if old == nil {
		status = http.StatusCreated
	}
	return c.JSON(status, r)
}

func (s *Server) handleDeleteRole(c *echo.Context) error {
	id, err := echo.PathParam[uint](c, "id")
	if err != nil {
		return errJSON(c, http.StatusNotFound, "not found")
	}
	r, err := s.rec.Role(id)
	if errors.Is(err, records.ErrNotFound) {
		return errJSON(c, http.StatusNotFound, "not found")
	}
	if err != nil {
		return err
	}
	if r.Instance != nil {
		return errJSON(c, http.StatusBadRequest, "a virtual firewall's role goes away with the virtual firewall")
	}
	if err := s.refuseOpenVPNRole(c.Request().Context(), r); err != nil {
		return writeError(c, err)
	}
	if err := s.rec.DeleteRole(r.ID); err != nil {
		return err
	}
	return c.NoContent(http.StatusNoContent)
}

// instanceNamesKnown is the set of the instances' names, of the candidate
// and of running: a role may grant an instance not yet committed, or one
// deleted in the candidate.
func (s *Server) instanceNamesKnown(ctx context.Context) (map[string]bool, error) {
	t, err := s.tree()
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	cand, err := t.store.Candidate(ctx)
	if err != nil {
		return nil, err
	}
	run, err := t.store.Running(ctx)
	if err != nil {
		return nil, err
	}
	// The virtual firewalls: the host is global admins' alone, no role's.
	for _, tr := range []*datastore.Tree{cand, run} {
		for _, in := range tr.Root.Lists["instance"] {
			out[in.Leaf("name")] = true
		}
	}
	return out, nil
}
