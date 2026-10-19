// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"fmt"
	"log/slog"
	"net/http"
	"reflect"

	"github.com/labstack/echo/v5"
	"gorm.io/gorm"

	"github.com/abundo/portitor/models"
)

// Managed rows (portitor-config): what a manager pushed is its own. An
// instance it pushed, with every row of it, and a shared object it pushed
// are read-only here, until a global admin breaks glass on the instance
// (Diverged), which the manager then sees. ManagedBy and Diverged change
// only through the manager API and break-glass.

// errManaged is a write to a managed row.
type errManaged struct{ msg string }

func (e *errManaged) Error() string { return e.msg }

// keepManaged puts back the stored ManagedBy and Diverged (none on a new
// row): no request body sets them.
func keepManaged(item, old any) {
	for _, f := range []string{"ManagedBy", "Diverged"} {
		v := reflect.ValueOf(item).Elem().FieldByName(f)
		if !v.IsValid() {
			continue
		}
		if old == nil || reflect.ValueOf(old).IsNil() {
			v.SetZero()
			continue
		}
		v.Set(reflect.ValueOf(old).Elem().FieldByName(f))
	}
}

// refuseManaged refuses a write to a row a manager owns: a shared object
// it pushed, or a row of an instance it pushed that has not diverged.
func refuseManaged(tx *gorm.DB, sc *scope, rows ...any) error {
	for _, row := range rows {
		if row == nil || reflect.ValueOf(row).IsNil() {
			continue
		}
		if _, isInst := row.(*models.Instance); !isInst {
			if v := reflect.ValueOf(row).Elem().FieldByName("ManagedBy"); v.IsValid() && v.String() != "" {
				return &errManaged{fmt.Sprintf("managed by %s: change it there", v.String())}
			}
		}
		if sc == nil {
			continue
		}
		ids, err := sc.of(tx, row)
		if err != nil {
			return err
		}
		var managed []models.Instance
		if err := tx.Select("name", "managed_by").Where("id IN ? AND managed_by != '' AND NOT diverged", ids).Find(&managed).Error; err != nil {
			return err
		}
		if len(managed) > 0 {
			return &errManaged{fmt.Sprintf("virtual firewall %s is managed by %s: change it there, or break glass to edit it here", managed[0].Name, managed[0].ManagedBy)}
		}
		// On a manager, the host of a firewall with portitor-config is
		// that portitor-config's own.
		var hosts []models.Instance
		if err := tx.Select("name").Where("id IN ? AND is_default AND firewall_id IN (?)", ids,
			tx.Model(&models.Firewall{}).Select("id").Where("config_url != ''")).Find(&hosts).Error; err != nil {
			return err
		}
		if len(hosts) > 0 {
			return &errManaged{fmt.Sprintf("virtual firewall %s is its firewall's host, which its portitor-config owns: change it there", hosts[0].Name)}
		}
	}
	return nil
}

// handleBreakGlass lets a managed instance be edited here (a global
// admin): it is diverged from its manager until the manager takes this
// version or overwrites it.
func (s *Server) handleBreakGlass(c *echo.Context) error {
	id, err := echo.PathParam[uint](c, "id")
	if err != nil {
		return errJSON(c, http.StatusNotFound, "not found")
	}
	var in models.Instance
	if err := s.db.First(&in, id).Error; err != nil {
		return errJSON(c, http.StatusNotFound, "not found")
	}
	if in.ManagedBy == "" {
		return errJSON(c, http.StatusConflict, "this virtual firewall is not managed")
	}
	if err := s.db.Model(&in).Update("diverged", true).Error; err != nil {
		return err
	}
	slog.Warn("break-glass: managed virtual firewall edited locally", "instance", in.Name, "manager", in.ManagedBy, "user", currentUser(c).Username)
	return c.JSON(http.StatusOK, map[string]any{"diverged": true})
}
