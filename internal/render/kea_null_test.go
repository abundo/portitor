// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package render

import (
	"strings"
	"testing"

	"github.com/abundo/portitor/internal/fwconfig"
)

// An instance without DHCP subnets renders empty lists, never null,
// which Kea refuses.
func TestKeaNoSubnetsNoNull(t *testing.T) {
	in := &fwconfig.Instance{Name: "main"}
	for _, conf := range []string{KeaDhcp4Conf(in, Paths{}), KeaDhcp6Conf(in, Paths{})} {
		if strings.Contains(conf, "null") {
			t.Errorf("config contains null:\n%s", conf)
		}
	}
}
