// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"net/http"
	"slices"

	"github.com/labstack/echo/v5"

	"github.com/abundo/portitor/models"
)

// Multi-tenancy. A user's own role is global: an admin does everything, a
// viewer reads everything, and "none" gets only what their roles grant.
// A role grants its members, at their level (admin or viewer), an
// instance: an instance's own role that instance, a role made by hand the
// instances it lists. The highest level wins.
//
// An instance admin changes the instance's rows (interfaces, rules, NAT,
// routes, IPAM, DNS, DHCP, dynamic DNS, WireGuard) and deploys it. Shared
// data (named hosts, services, IP lists, DNS templates, tasks, links) is
// read by everyone and changed by global admins only.

const ctxAccess = "access"

// access is what one user may do, by instance name. ids names the
// instances by their ids (config_ids), for the handlers that take them.
type access struct {
	global string
	levels map[string]string
	ids    map[uint]string
}

// accessOf works out the user's levels from their roles.
func (s *Server) accessOf(u *models.User) (*access, error) {
	db := s.db
	a := &access{global: u.Role, levels: map[string]string{}, ids: map[uint]string{}}
	if u.Role == models.RoleAdmin {
		return a, nil
	}
	var rows []struct {
		Instance string
		Level    string
	}
	err := db.Raw(`
		SELECT r.instance AS instance, m.level AS level
		  FROM role_members m JOIN roles r ON r.id = m.role_id
		 WHERE m.user_id = ? AND r.instance IS NOT NULL
		UNION ALL
		SELECT ri.instance, m.level
		  FROM role_members m JOIN role_instances ri ON ri.role_id = m.role_id
		 WHERE m.user_id = ?`, u.ID, u.ID).Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		if a.levels[r.Instance] != models.RoleAdmin {
			a.levels[r.Instance] = r.Level
		}
	}
	if len(a.levels) > 0 {
		v, err := s.view(context.Background())
		if err != nil {
			return nil, err
		}
		for _, in := range v.Instances {
			a.ids[in.ID] = in.Name
		}
	}
	return a, nil
}

// isAdmin: a global admin.
func (a *access) isAdmin() bool { return a.global == models.RoleAdmin }

// readsAll: a global admin or viewer.
func (a *access) readsAll() bool { return a.isAdmin() || a.global == models.RoleViewer }

func (a *access) canRead(id uint) bool { return a.readsAll() || a.levels[a.ids[id]] != "" }

func (a *access) canWrite(id uint) bool {
	return a.isAdmin() || a.levels[a.ids[id]] == models.RoleAdmin
}

// canReadAny: a row of several instances (a link) is seen from either end.
func (a *access) canReadAny(ids []uint) bool { return slices.ContainsFunc(ids, a.canRead) }

// readableNames lists the names of the instances the user reads;
// meaningless if readsAll.
func (a *access) readableNames() map[string]bool {
	out := map[string]bool{}
	for name := range a.levels {
		out[name] = true
	}
	return out
}

// writableNames lists the names of the instances the user changes; nil for
// a global admin.
func (a *access) writableNames() map[string]bool {
	if a.isAdmin() {
		return nil
	}
	out := map[string]bool{}
	for name, l := range a.levels {
		if l == models.RoleAdmin {
			out[name] = true
		}
	}
	return out
}

// readable lists the rows of the instances the user reads; meaningless if
// readsAll.
func (a *access) readable() []uint {
	ids := []uint{}
	for id, name := range a.ids {
		if a.levels[name] != "" {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	return ids
}

// writesAny: a global admin or the admin of an instance.
func (a *access) writesAny() bool { return a.isAdmin() || len(a.writableNames()) > 0 }

// currentAccess is the request's access, set by requireRole.
func currentAccess(c *echo.Context) *access {
	a, _ := c.Get(ctxAccess).(*access)
	if a == nil {
		return &access{levels: map[string]string{}, ids: map[uint]string{}}
	}
	return a
}

// readableInstanceNames is nil when the user reads every instance.
func (s *Server) readableInstanceNames(c *echo.Context) (map[string]bool, error) {
	a := currentAccess(c)
	if a.readsAll() {
		return nil, nil
	}
	return a.readableNames(), nil
}

// allowInstance tells whether the user may write (or, with write false,
// read) the instance; when not, it has answered 404 or 403 and the
// handler returns the error.
func allowInstance(c *echo.Context, id uint, write bool) (bool, error) {
	a := currentAccess(c)
	switch {
	case write && a.canWrite(id), !write && a.canRead(id):
		return true, nil
	case !a.canRead(id):
		return false, errJSON(c, http.StatusNotFound, "not found")
	}
	return false, errJSON(c, http.StatusForbidden, "you can't change this virtual firewall")
}
