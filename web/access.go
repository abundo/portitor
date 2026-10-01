// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"errors"
	"net/http"
	"reflect"
	"slices"

	"github.com/labstack/echo/v5"
	"gorm.io/gorm"

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

// access is what one user may do, by instance id.
type access struct {
	global string
	levels map[uint]string
}

// accessOf works out the user's levels from their roles.
func accessOf(db *gorm.DB, u *models.User) (*access, error) {
	a := &access{global: u.Role, levels: map[uint]string{}}
	if u.Role == models.RoleAdmin {
		return a, nil
	}
	var rows []struct {
		InstanceID uint
		Level      string
	}
	err := db.Raw(`
		SELECT r.instance_id AS instance_id, m.level AS level
		  FROM role_members m JOIN roles r ON r.id = m.role_id
		 WHERE m.user_id = ? AND r.instance_id IS NOT NULL
		UNION ALL
		SELECT ri.instance_id, m.level
		  FROM role_members m JOIN role_instances ri ON ri.role_id = m.role_id
		 WHERE m.user_id = ?`, u.ID, u.ID).Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		if a.levels[r.InstanceID] != models.RoleAdmin {
			a.levels[r.InstanceID] = r.Level
		}
	}
	return a, nil
}

// isAdmin: a global admin.
func (a *access) isAdmin() bool { return a.global == models.RoleAdmin }

// readsAll: a global admin or viewer.
func (a *access) readsAll() bool { return a.isAdmin() || a.global == models.RoleViewer }

func (a *access) canRead(id uint) bool { return a.readsAll() || a.levels[id] != "" }

func (a *access) canWrite(id uint) bool { return a.isAdmin() || a.levels[id] == models.RoleAdmin }

// canReadAny: a row of several instances (a link) is seen from either end.
func (a *access) canReadAny(ids []uint) bool { return slices.ContainsFunc(ids, a.canRead) }

func (a *access) canWriteAll(ids []uint) bool {
	for _, id := range ids {
		if !a.canWrite(id) {
			return false
		}
	}
	return true
}

// readable lists the instances the user reads; meaningless if readsAll.
func (a *access) readable() []uint {
	ids := []uint{}
	for id := range a.levels {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

// writable lists the instances the user changes; nil for a global admin.
func (a *access) writable() []uint {
	if a.isAdmin() {
		return nil
	}
	ids := []uint{}
	for id, l := range a.levels {
		if l == models.RoleAdmin {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	return ids
}

// writesAny: a global admin or the admin of an instance.
func (a *access) writesAny() bool { return a.isAdmin() || len(a.writable()) > 0 }

// currentAccess is the request's access, set by requireRole.
func currentAccess(c *echo.Context) *access {
	a, _ := c.Get(ctxAccess).(*access)
	if a == nil {
		return &access{levels: map[uint]string{}}
	}
	return a
}

// readableNames lists the names of the instances the user reads.
func (s *Server) instanceNames(ids []uint) (map[string]bool, error) {
	var names []string
	if err := s.db.Model(&models.Instance{}).Where("id IN ?", ids).Pluck("name", &names).Error; err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, n := range names {
		out[n] = true
	}
	return out, nil
}

// readableInstanceNames is nil when the user reads every instance.
func (s *Server) readableInstanceNames(c *echo.Context) (map[string]bool, error) {
	a := currentAccess(c)
	if a.readsAll() {
		return nil, nil
	}
	return s.instanceNames(a.readable())
}

// instanceOf looks up the instance a row of table belongs to.
func instanceOf(tx *gorm.DB, table string, id uint) (uint, error) {
	var out struct{ InstanceID uint }
	err := tx.Table(table).Select("instance_id").Where("id = ?", id).Take(&out).Error
	return out.InstanceID, err
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
	return false, errJSON(c, http.StatusForbidden, "you can't change this instance")
}

// allowRow is allowInstance for the row id of table (with an instance_id).
func allowRow(c *echo.Context, tx *gorm.DB, table string, id uint, write bool) (bool, error) {
	inst, err := instanceOf(tx, table, id)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return false, errJSON(c, http.StatusNotFound, "not found")
	} else if err != nil {
		return false, err
	}
	return allowInstance(c, inst, write)
}

// scope tells which instances a row belongs to.
type scope struct {
	// of returns the row's instances.
	of func(tx *gorm.DB, item any) ([]uint, error)
	// list narrows a list to rows of the given instances.
	list func(q *gorm.DB, ids []uint) *gorm.DB
}

func uintField(item any, name string) uint {
	return uint(reflect.ValueOf(item).Elem().FieldByName(name).Uint())
}

// byField: the row has the instance id in a column (field).
func byField(field, column string) *scope {
	return &scope{
		of: func(_ *gorm.DB, item any) ([]uint, error) { return []uint{uintField(item, field)}, nil },
		list: func(q *gorm.DB, ids []uint) *gorm.DB {
			return q.Where(column+" IN ?", ids) // column is a constant
		},
	}
}

// byParent: the row belongs to a row of table (through field/column),
// which has the instance id.
func byParent(field, column, table string) *scope {
	return &scope{
		of: func(tx *gorm.DB, item any) ([]uint, error) {
			id, err := instanceOf(tx, table, uintField(item, field))
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, bad(column + ": no such entry")
			}
			return []uint{id}, err
		},
		list: func(q *gorm.DB, ids []uint) *gorm.DB {
			return q.Where(column+" IN (SELECT id FROM "+table+" WHERE instance_id IN ?)", ids)
		},
	}
}

// linkScope: a link belongs to the instances at both ends.
var linkScope = &scope{
	of: func(_ *gorm.DB, item any) ([]uint, error) {
		return []uint{uintField(item, "InstanceAID"), uintField(item, "InstanceBID")}, nil
	},
	list: func(q *gorm.DB, ids []uint) *gorm.DB {
		return q.Where("instance_a_id IN ? OR instance_b_id IN ?", ids, ids)
	},
}

// instanceScope: an instance is its own.
var instanceScope = &scope{
	of:   func(_ *gorm.DB, item any) ([]uint, error) { return []uint{uintField(item, "ID")}, nil },
	list: func(q *gorm.DB, ids []uint) *gorm.DB { return q.Where("id IN ?", ids) },
}
