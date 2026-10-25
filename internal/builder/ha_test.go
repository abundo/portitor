// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package builder

import "testing"

func TestConfigPort(t *testing.T) {
	for in, want := range map[string]int{
		"":                          0,
		"https://192.0.2.1:8444":    8444,
		"https://fw.example":        443,
		"https://[2001:db8::1]:443": 443,
		"http://192.0.2.1:8080":     0,
		"https://192.0.2.1:99999":   0,
	} {
		if got := configPort(in); got != want {
			t.Errorf("%q: %d, want %d", in, got, want)
		}
	}
}
