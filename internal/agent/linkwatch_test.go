// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestCarrierCame(t *testing.T) {
	lower := uint32(unix.IFF_UP | unix.IFF_LOWER_UP)
	for _, tc := range []struct {
		name      string
		known, up bool
		flags     uint32
		want      bool
	}{
		{"down to up", true, false, lower, true},
		{"still up", true, true, lower, false},
		{"up without carrier", true, false, unix.IFF_UP, false},
		{"going down", true, true, unix.IFF_UP, false},
		{"appears with carrier", false, false, lower, true},
		{"appears without", false, false, 0, false},
	} {
		if got := carrierCame(tc.known, tc.up, tc.flags); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}
