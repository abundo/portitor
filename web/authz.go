// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"net/http"
)

// The API's authorization by route is declared here, in one table, keyed by
// the route pattern ("GET /api/users"): requireRole matches the pattern, so
// it cannot be dodged with another spelling of the path. Deny by default: a
// route not in the table is a plain read for every user and a write for a
// global admin alone (global admins pass everything). /api/config's access
// by path is `treeAccess`, not here, and so is the replica's list of writes
// it takes (`readOnlyAllowed`: a rule about the host's role, not the user's).
// TestRoutePolicy checks that every entry is a registered route.

// routeLevel says who may use a route beyond what its method gives them.
type routeLevel uint8

const (
	// globalOnly: a GET only a global admin may make (it hands out a root
	// shell, or the user, role and directory lists).
	globalOnly routeLevel = iota + 1
	// readsEverything: a GET for users that read every instance (global
	// admins and viewers); a user without a global role (RoleNone) sees
	// one instance, not the whole firewall.
	readsEverything
	// anyUser: a write open to every user, the viewer's own profile and
	// the deploy preview, which changes nothing.
	anyUser
	// instanceAdmin: a write for the admin of an instance too; the handler
	// checks the instance (`allowInstance`, `tenantTreeCheck`).
	instanceAdmin
)

// routePolicy is the table; a route's TOTP setup flag is in totpSetup.
var routePolicy = map[string]routeLevel{
	// Reads.
	"GET /api/users":                        globalOnly,
	"GET /api/roles":                        globalOnly,
	"GET /api/agent/console":                globalOnly,
	"GET /api/directory/servers":            globalOnly,
	"GET /api/directory/servers/:id":        globalOnly,
	"GET /api/directory/servers/:id/browse": globalOnly,
	"GET /api/directory/mappings":           globalOnly,
	"GET /api/directory/mappings/:id":       globalOnly,
	"GET /api/settings":                     readsEverything,
	"GET /api/system":                       readsEverything,
	"GET /api/agent/logs":                   readsEverything,
	"GET /api/agent/syslog":                 readsEverything,
	"GET /api/firewalls":                    readsEverything,
	"GET /api/firewalls/:id":                readsEverything,
	"GET /api/firewalls/:id/witness":        readsEverything,

	// Writes every user makes: their own profile and password.
	"PUT /api/me":                      anyUser,
	"POST /api/me/password":            anyUser,
	"POST /api/me/totp/setup":          anyUser,
	"POST /api/me/totp/enable":         anyUser,
	"POST /api/me/totp/disable":        anyUser,
	"POST /api/me/totp/recovery-codes": anyUser,
	"POST /api/deploy/preview":         anyUser,

	// Writes an instance admin makes too.
	"POST /api/wg/import":               instanceAdmin,
	"POST /api/agent/capture":           instanceAdmin,
	"POST /api/agent/trace":             instanceAdmin,
	"POST /api/agent/iperf":             instanceAdmin,
	"POST /api/agent/probe":             instanceAdmin,
	"POST /api/agent/servicelog":        instanceAdmin,
	"POST /api/agent/connections":       instanceAdmin,
	"POST /api/agent/connections/flush": instanceAdmin,
	"POST /api/agent/dhcp/renew":        instanceAdmin,
	"POST /api/deploy/apply":            instanceAdmin,
	"POST /api/deploy/confirm":          instanceAdmin,
	"POST /api/deploy/rollback":         instanceAdmin,
	"PUT /api/config/*":                 instanceAdmin,
	"PATCH /api/config/*":               instanceAdmin,
	"POST /api/config/*":                instanceAdmin,
	"DELETE /api/config/*":              instanceAdmin,
}

// totpSetup are all a user who must use two-factor login may do before they
// have set it up.
var totpSetup = map[string]bool{
	"GET /api/me":              true,
	"PUT /api/me":              true,
	"GET /api/me/totp":         true,
	"POST /api/me/totp/setup":  true,
	"POST /api/me/totp/enable": true,
}

// routeKey is the table's key for a request: HEAD is a GET.
func routeKey(method, pattern string) string {
	if method == http.MethodHead {
		method = http.MethodGet
	}
	return method + " " + pattern
}

// permitted tells whether a user with access a may use the route.
func permitted(a *access, method, pattern string) bool {
	if a.isAdmin() {
		return true
	}
	lv := routePolicy[routeKey(method, pattern)]
	if method == http.MethodGet || method == http.MethodHead {
		return lv != globalOnly && (lv != readsEverything || a.readsAll())
	}
	return lv == anyUser || lv == instanceAdmin && a.writesAny()
}

// routeLevelOf is for the tests that sweep the routes.
func routeLevelOf(method, pattern string) routeLevel {
	return routePolicy[routeKey(method, pattern)]
}
