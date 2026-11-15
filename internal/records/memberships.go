// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package records

import (
	"github.com/abundo/portitor/internal/ldapauth"
	"github.com/abundo/portitor/models"
)

// Memberships is what a directory login changes in a user's role
// memberships.
type Memberships struct {
	// Add are the memberships to create, Level the level of the ones to
	// change (by membership id), Remove the ones to delete.
	Add    []models.RoleMember
	Level  map[uint]string
	Remove []uint
}

// PlanMemberships makes a directory user a member of the roles their groups
// map to, at the highest level mapped, and no member of the other roles any
// group maps to. Roles no group maps to are left as an admin set them. It
// is pure, shared by every implementation of Directory.
func PlanMemberships(userID uint, mappings []models.LdapRoleMapping, have []models.RoleMember, groups []string) Memberships {
	mapped := map[uint]bool{}
	want := map[uint]string{}
	for _, m := range mappings {
		mapped[m.RoleID] = true
		if ldapauth.InGroups(groups, []string{m.GroupDn}) && want[m.RoleID] != models.RoleAdmin {
			want[m.RoleID] = m.Level
		}
	}
	out := Memberships{Level: map[uint]string{}}
	for _, m := range have {
		if !mapped[m.RoleID] {
			continue
		}
		level, ok := want[m.RoleID]
		switch {
		case !ok:
			out.Remove = append(out.Remove, m.ID)
		case level != m.Level:
			out.Level[m.ID] = level
		}
		delete(want, m.RoleID)
	}
	for roleID, level := range want {
		out.Add = append(out.Add, models.RoleMember{RoleID: roleID, UserID: userID, Level: level})
	}
	return out
}
