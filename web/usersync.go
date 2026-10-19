// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/labstack/echo/v5"
	"gorm.io/gorm"

	"github.com/abundo/portitor/models"
)

// Users on a firewall with portitor-config are its own and its manager's:
// at each commit the manager pushes its users (password hashes included)
// and their memberships of the roles of the virtual firewalls it pushed.
// They are managed by it there: changed there only (password too), gone
// when it no longer has them. A local user of the same name stays local;
// the push leaves it alone and says so. Local users' memberships are not
// touched.

// ManagedUsers is a manager's users push (PUT /manager/v1/users).
type ManagedUsers struct {
	Manager string        `json:"manager"`
	Users   []ManagedUser `json:"users"`
	// Members are the users' memberships of the virtual firewalls' roles,
	// by instance name.
	Members []ManagedMember `json:"members"`
}

type ManagedUser struct {
	Username     string `json:"username"`
	FullName     string `json:"full_name"`
	Email        string `json:"email"`
	Role         string `json:"role"`
	PasswordHash string `json:"password_hash"`
}

type ManagedMember struct {
	Instance string `json:"instance"`
	Username string `json:"username"`
	Level    string `json:"level"`
}

// managedUsers is what this portitor-web pushes to the portitor-config of
// a firewall: all its users, and their memberships of that firewall's
// virtual firewalls' roles.
func (s *Server) managedUsers(firewallID uint) (*ManagedUsers, error) {
	out := &ManagedUsers{Manager: s.managerName(), Users: []ManagedUser{}, Members: []ManagedMember{}}
	var users []models.User
	if err := s.db.Find(&users).Error; err != nil {
		return nil, err
	}
	name := map[uint]string{}
	for _, u := range users {
		name[u.ID] = u.Username
		out.Users = append(out.Users, ManagedUser{Username: u.Username, FullName: u.FullName, Email: u.Email, Role: u.Role, PasswordHash: u.PasswordHash})
	}
	var rows []struct {
		Instance string
		UserID   uint
		Level    string
	}
	err := s.db.Table("role_members").Select("instances.name AS instance, role_members.user_id, role_members.level").
		Joins("JOIN roles ON roles.id = role_members.role_id").
		Joins("JOIN instances ON instances.id = roles.instance_id").
		Where("instances.firewall_id = ? AND NOT instances.is_default", firewallID).Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		out.Members = append(out.Members, ManagedMember{Instance: r.Instance, Username: name[r.UserID], Level: r.Level})
	}
	return out, nil
}

// handleManagerUsers takes a manager's users and memberships.
func (s *Server) handleManagerUsers(c *echo.Context) error {
	var req ManagedUsers
	if err := c.Bind(&req); err != nil || !managerNameRe.MatchString(req.Manager) {
		return errJSON(c, http.StatusBadRequest, "manager (lowercase name) and users are required")
	}
	var skipped []string
	err := s.db.Transaction(func(tx *gorm.DB) error {
		var err error
		skipped, err = syncUsers(tx, &req)
		return err
	})
	if err != nil {
		return dbError(c, err)
	}
	if skipped == nil {
		skipped = []string{}
	}
	return c.JSON(http.StatusOK, map[string]any{"skipped": skipped})
}

func syncUsers(tx *gorm.DB, req *ManagedUsers) ([]string, error) {
	var skipped []string
	keep := map[string]bool{}
	for _, mu := range req.Users {
		if !validRole(mu.Role) || mu.Username == "" {
			return nil, bad(fmt.Sprintf("user %q: invalid", mu.Username))
		}
		var u models.User
		err := tx.Where("username = ?", mu.Username).First(&u).Error
		switch {
		case err == nil && u.ManagedBy != req.Manager:
			// A local user (or another manager's) of that name stays.
			skipped = append(skipped, mu.Username)
			continue
		case err != nil && !errors.Is(err, gorm.ErrRecordNotFound):
			return nil, err
		}
		keep[mu.Username] = true
		changed := u.ID == 0 || u.Role != mu.Role || u.PasswordHash != mu.PasswordHash
		u.Username, u.FullName, u.Email, u.Role, u.PasswordHash, u.ManagedBy = mu.Username, mu.FullName, mu.Email, mu.Role, mu.PasswordHash, req.Manager
		if u.DateFormat == "" {
			u.DateFormat = "locale"
		}
		if changed && u.ID != 0 {
			// A new password or role there ends the sessions here too.
			u.TokenVersion++
		}
		if err := tx.Save(&u).Error; err != nil {
			return nil, err
		}
	}
	var gone []models.User
	if err := tx.Where("managed_by = ?", req.Manager).Find(&gone).Error; err != nil {
		return nil, err
	}
	for _, u := range gone {
		if !keep[u.Username] {
			if err := tx.Delete(&u).Error; err != nil {
				return nil, err
			}
			slog.Info("manager users: removed", "manager", req.Manager, "user", u.Username)
		}
	}
	// The memberships of the manager's users in the roles of the virtual
	// firewalls it pushed are its own.
	mine := tx.Model(&models.User{}).Select("id").Where("managed_by = ?", req.Manager)
	roles := tx.Model(&models.Role{}).Select("id").Where("instance_id IN (?)",
		tx.Model(&models.Instance{}).Select("id").Where("managed_by = ?", req.Manager))
	if err := tx.Where("user_id IN (?) AND role_id IN (?)", mine, roles).Delete(&models.RoleMember{}).Error; err != nil {
		return nil, err
	}
	for _, m := range req.Members {
		var role models.Role
		err := tx.Where("instance_id IN (?)", tx.Model(&models.Instance{}).Select("id").Where("name = ? AND managed_by = ?", m.Instance, req.Manager)).First(&role).Error
		if err != nil {
			continue // not one of its virtual firewalls here
		}
		var u models.User
		if err := tx.Where("username = ? AND managed_by = ?", m.Username, req.Manager).First(&u).Error; err != nil {
			continue
		}
		if err := tx.Create(&models.RoleMember{RoleID: role.ID, UserID: u.ID, Level: m.Level}).Error; err != nil {
			return nil, err
		}
	}
	return skipped, nil
}

// pushUsers sends this portitor-web's users to a firewall's
// portitor-config.
func (s *Server) pushUsers(ctx context.Context, fw *models.Firewall, cfg configAPI) error {
	mu, err := s.managedUsers(fw.ID)
	if err != nil {
		return err
	}
	skipped, err := cfg.PushUsers(ctx, mu)
	if err != nil {
		return fmt.Errorf("firewall %s: pushing users: %w", fw.Name, err)
	}
	if len(skipped) > 0 {
		slog.Warn("users not pushed: the firewall has local ones of the name", "firewall", fw.Name, "users", skipped)
	}
	return nil
}
