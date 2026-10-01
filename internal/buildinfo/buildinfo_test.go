// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package buildinfo

import "testing"

func TestMismatch(t *testing.T) {
	defer func(v string) { Version = v }(Version)
	for _, tc := range []struct {
		web, agent string
		want       bool
	}{
		{"1.2.3", "1.2.3", false},
		{"v1.2.3", "1.2.3", false},
		{"1.2.3", "v1.2.3", false},
		{"1.2.3", "1.2.4", true},
		{"dev", "1.2.3", false},
		{"1.2.3", "dev", false},
		{"1.2.3", "", false},
	} {
		Version = tc.web
		if got := Mismatch(tc.agent) != ""; got != tc.want {
			t.Errorf("web %q agent %q: mismatch %v, want %v", tc.web, tc.agent, got, tc.want)
		}
	}
}
