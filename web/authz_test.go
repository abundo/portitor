// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import "testing"

// Every entry of routePolicy and totpSetup names a registered route, so a
// route renamed or removed can't leave a stale grant behind.
func TestRoutePolicy(t *testing.T) {
	env := newEnv(t)
	have := map[string]bool{}
	for _, r := range env.e.Router().Routes() {
		have[r.Method+" "+r.Path] = true
	}
	for k := range routePolicy {
		if !have[k] {
			t.Errorf("routePolicy: %q is not a registered route", k)
		}
	}
	for k := range totpSetup {
		if !have[k] {
			t.Errorf("totpSetup: %q is not a registered route", k)
		}
	}
}
