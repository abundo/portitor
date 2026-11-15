// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package confcheck

import (
	"strings"

	"github.com/abundo/portitor/internal/datastore"
)

// bcryptHash tells whether s looks like a bcrypt hash of a local password.
func bcryptHash(s string) bool {
	return len(s) == 60 && (strings.HasPrefix(s, "$2a$") || strings.HasPrefix(s, "$2b$") || strings.HasPrefix(s, "$2y$"))
}

// checkAccess is what the users must be, whoever writes them (the API, the
// CLI, NETCONF): a password hash is a bcrypt hash or the directory's, and once
// there are users one of them is an admin who can log in with a local password,
// or a bad edit would lock everyone out.
func checkAccess(t *datastore.Tree) []error {
	users := t.Root.Lists["user"]
	if len(users) == 0 {
		return nil
	}
	var errs []error
	admin := false
	for _, u := range users {
		h := u.Leaf("password-hash")
		if h != "" && h != "@LDAP" && !bcryptHash(h) {
			errs = append(errs, &datastore.Error{Path: datastore.PathOf(u).String(t.Root.S) + "/password-hash", Msg: "not a bcrypt hash"})
		}
		if u.Leaf("role") == "admin" && bcryptHash(h) {
			admin = true
		}
	}
	if !admin {
		errs = append(errs, &datastore.Error{Path: "/user", Msg: "there must be a user with the role admin and a local password"})
	}
	return errs
}
