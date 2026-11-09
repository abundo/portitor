// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"fmt"
	"strings"

	"gorm.io/gorm"

	"github.com/abundo/portitor/models"
)

// Entry-time checks. They cover shape and references; the full semantic
// check is fwconfig.Validate at deploy time (see builder.Build), which also
// runs again on the agent.

// presentInterface hides the tunnel broker update key.
func presentInterface(i *models.Interface) {
	i.HasHeUpdateKey = i.HeUpdateKey != ""
	i.NewHeUpdateKey = ""
}

func presentWgPeer(p *models.WgPeer) {
	p.HasPresharedKey = p.PresharedKey != ""
	p.HasClientKey = p.ClientPrivateKey != ""
}

// dnsName trims a host name entered with or without the trailing dot.
func dnsName(s string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
}

// usedBy refuses a delete while rows of model still refer to id through
// column, naming them.
func usedBy(tx *gorm.DB, what string, model any, column string, id uint, name func() []string) error {
	var n int64
	if err := tx.Model(model).Where(column+" = ?", id).Count(&n).Error; err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	names := name()
	if len(names) > 5 {
		names = append(names[:5], "...")
	}
	return bad(fmt.Sprintf("%s is used by %s", what, strings.Join(names, ", ")))
}
