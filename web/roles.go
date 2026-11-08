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
	"gorm.io/gorm"

	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/models"
)

// instanceRolePrefix starts the name of each instance's role; a role made
// by hand can't use it.
const instanceRolePrefix = "vf-"

func instanceRoleName(instance string) string { return instanceRolePrefix + instance }

// createInstanceRole adds the role of a new instance, unless it has one
// (a role outlives its instance until the commit that leaves it out). The
// default instance, the host itself, has none: only global admins manage
// it.
func createInstanceRole(tx *gorm.DB, in *models.Instance) error {
	if in.IsDefault {
		return nil
	}
	return ensureInstanceRole(tx, in.Name)
}

func ensureInstanceRole(tx *gorm.DB, name string) error {
	var n int64
	if err := tx.Model(&models.Role{}).Where("instance = ?", name).Count(&n).Error; err != nil || n > 0 {
		return err
	}
	return tx.Create(&models.Role{
		Name: instanceRoleName(name), Description: "Users of virtual firewall " + name, Instance: &name,
	}).Error
}

// renameInstanceRole follows an instance's new name.
func renameInstanceRole(tx *gorm.DB, in, old *models.Instance) error {
	if old == nil || old.Name == in.Name {
		return nil
	}
	return renameInstanceRoles(tx, old.Name, in.Name)
}

// renameInstanceRoles makes the roles that name the instance old name new:
// its own role, and the grants of the roles made by hand.
func renameInstanceRoles(tx *gorm.DB, old, new string) error {
	if err := tx.Model(&models.Role{}).Where("instance = ?", old).
		Updates(map[string]any{"name": instanceRoleName(new), "instance": new}).Error; err != nil {
		return err
	}
	return tx.Model(&models.RoleInstance{}).Where("instance = ?", old).Update("instance", new).Error
}

// syncInstanceRoles gives every virtual firewall of the candidate its role.
func syncInstanceRoles(tx *gorm.DB, tree *datastore.Tree) error {
	for _, in := range tree.Root.Lists["instance"] {
		if in.Leaf("is-default") == "true" {
			continue
		}
		if err := ensureInstanceRole(tx, in.Leaf("name")); err != nil {
			return err
		}
	}
	return nil
}

// dropInstanceRoles removes the roles and grants of the instances that
// neither running nor the candidate has, after a commit: until then a
// delete can be taken back without losing the members.
func dropInstanceRoles(tx *gorm.DB, trees ...*datastore.Tree) error {
	keep := []string{}
	for _, t := range trees {
		for _, in := range t.Root.Lists["instance"] {
			keep = append(keep, in.Leaf("name"))
		}
	}
	if err := tx.Where("instance IS NOT NULL AND instance NOT IN ?", keep).Delete(&models.Role{}).Error; err != nil {
		return err
	}
	return tx.Where("instance NOT IN ?", keep).Delete(&models.RoleInstance{}).Error
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
	roles := []models.Role{}
	if err := s.db.Order("instance IS NULL, name").Find(&roles).Error; err != nil {
		return err
	}
	var members []models.RoleMember
	if err := s.db.Order("id").Find(&members).Error; err != nil {
		return err
	}
	var grants []models.RoleInstance
	if err := s.db.Order("instance").Find(&grants).Error; err != nil {
		return err
	}
	byRole := map[uint][]models.RoleMember{}
	for _, m := range members {
		byRole[m.RoleID] = append(byRole[m.RoleID], m)
	}
	instances := map[uint][]string{}
	for _, g := range grants {
		instances[g.RoleID] = append(instances[g.RoleID], g.Instance)
	}
	for i := range roles {
		r := &roles[i]
		r.Members = byRole[r.ID]
		if r.Members == nil {
			r.Members = []models.RoleMember{}
		}
		switch {
		case r.Instance != nil:
			r.Instances = []string{*r.Instance}
		case instances[r.ID] != nil:
			r.Instances = instances[r.ID]
		default:
			r.Instances = []string{}
		}
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
	var r models.Role
	if err := s.db.First(&r, id).Error; err != nil {
		return errJSON(c, http.StatusNotFound, "not found")
	}
	return s.saveRole(c, &r)
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
	err := s.db.Transaction(func(tx *gorm.DB) error {
		if old == nil {
			if err := tx.Create(&r).Error; err != nil {
				return err
			}
		} else if err := tx.Save(&r).Error; err != nil {
			return err
		}
		if err := tx.Where("role_id = ?", r.ID).Delete(&models.RoleMember{}).Error; err != nil {
			return err
		}
		r.Members = []models.RoleMember{}
		for _, m := range req.Members {
			rm := models.RoleMember{RoleID: r.ID, UserID: m.UserID, Level: m.Level}
			if err := tx.Create(&rm).Error; err != nil {
				if strings.Contains(err.Error(), "FOREIGN KEY constraint") {
					return bad("no such user")
				}
				return err
			}
			r.Members = append(r.Members, rm)
		}
		if r.Instance != nil {
			r.Instances = []string{*r.Instance}
			return nil
		}
		if err := tx.Where("role_id = ?", r.ID).Delete(&models.RoleInstance{}).Error; err != nil {
			return err
		}
		r.Instances = []string{}
		for _, name := range req.Instances {
			if err := tx.Create(&models.RoleInstance{RoleID: r.ID, Instance: name}).Error; err != nil {
				return err
			}
			r.Instances = append(r.Instances, name)
		}
		return nil
	})
	if err != nil {
		return dbError(c, err)
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
	var r models.Role
	if err := s.db.First(&r, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return errJSON(c, http.StatusNotFound, "not found")
		}
		return err
	}
	if r.Instance != nil {
		return errJSON(c, http.StatusBadRequest, "a virtual firewall's role goes away with the virtual firewall")
	}
	if err := refuseOpenVPNRole(s.db, &r); err != nil {
		return dbError(c, err)
	}
	if err := s.db.Delete(&r).Error; err != nil {
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
	for _, tr := range []*datastore.Tree{cand, run} {
		for _, in := range tr.Root.Lists["instance"] {
			out[in.Leaf("name")] = true
		}
	}
	return out, nil
}
