// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"unicode"

	"github.com/labstack/echo/v5"
	"gorm.io/gorm"

	"github.com/abundo/portitor/models"
)

// instanceRolePrefix starts the name of each instance's role; a role made
// by hand can't use it.
const instanceRolePrefix = "instance-"

func instanceRoleName(instance string) string { return instanceRolePrefix + instance }

// createInstanceRole adds the role of a new instance.
func createInstanceRole(tx *gorm.DB, in *models.Instance) error {
	id := in.ID
	return tx.Create(&models.Role{
		Name: instanceRoleName(in.Name), Description: "Users of instance " + in.Name, InstanceID: &id,
	}).Error
}

// renameInstanceRole follows an instance's new name. Deleting the instance
// removes its role and memberships (ON DELETE CASCADE).
func renameInstanceRole(tx *gorm.DB, in, old *models.Instance) error {
	if old == nil || old.Name == in.Name {
		return nil
	}
	return tx.Model(&models.Role{}).Where("instance_id = ?", in.ID).
		Update("name", instanceRoleName(in.Name)).Error
}

type roleRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Members     []struct {
		UserID uint   `json:"user_id"`
		Level  string `json:"level"`
	} `json:"members"`
	// InstanceIDs: the instances a role made by hand grants.
	InstanceIDs []uint `json:"instance_ids"`
}

func (s *Server) handleListRoles(c *echo.Context) error {
	roles := []models.Role{}
	if err := s.db.Order("instance_id IS NULL, name").Find(&roles).Error; err != nil {
		return err
	}
	var members []models.RoleMember
	if err := s.db.Order("id").Find(&members).Error; err != nil {
		return err
	}
	var grants []models.RoleInstance
	if err := s.db.Order("instance_id").Find(&grants).Error; err != nil {
		return err
	}
	byRole := map[uint][]models.RoleMember{}
	for _, m := range members {
		byRole[m.RoleID] = append(byRole[m.RoleID], m)
	}
	instances := map[uint][]uint{}
	for _, g := range grants {
		instances[g.RoleID] = append(instances[g.RoleID], g.InstanceID)
	}
	for i := range roles {
		r := &roles[i]
		r.Members = byRole[r.ID]
		if r.Members == nil {
			r.Members = []models.RoleMember{}
		}
		switch {
		case r.InstanceID != nil:
			r.InstanceIDs = []uint{*r.InstanceID}
		case instances[r.ID] != nil:
			r.InstanceIDs = instances[r.ID]
		default:
			r.InstanceIDs = []uint{}
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
	if r.InstanceID == nil {
		if req.Name == "" || len(req.Name) > 64 || strings.ContainsFunc(req.Name, unicode.IsControl) {
			return errJSON(c, http.StatusBadRequest, "name: 1 to 64 characters, no control characters")
		}
		if strings.HasPrefix(req.Name, instanceRolePrefix) {
			return errJSON(c, http.StatusBadRequest, "name: "+instanceRolePrefix+"… is reserved for the instances' roles")
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
	if r.InstanceID != nil {
		req.InstanceIDs = nil // its instance, always
	}
	slices.Sort(req.InstanceIDs)
	req.InstanceIDs = slices.Compact(req.InstanceIDs)
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
		if r.InstanceID != nil {
			r.InstanceIDs = []uint{*r.InstanceID}
			return nil
		}
		if err := tx.Where("role_id = ?", r.ID).Delete(&models.RoleInstance{}).Error; err != nil {
			return err
		}
		r.InstanceIDs = []uint{}
		for _, id := range req.InstanceIDs {
			if err := tx.Create(&models.RoleInstance{RoleID: r.ID, InstanceID: id}).Error; err != nil {
				if strings.Contains(err.Error(), "FOREIGN KEY constraint") {
					return bad("no such instance")
				}
				return err
			}
			r.InstanceIDs = append(r.InstanceIDs, id)
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
	if r.InstanceID != nil {
		return errJSON(c, http.StatusBadRequest, "an instance's role goes away with the instance")
	}
	if err := s.db.Delete(&r).Error; err != nil {
		return err
	}
	return c.NoContent(http.StatusNoContent)
}
