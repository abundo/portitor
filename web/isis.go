// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"github.com/abundo/portitor/models"
)

// IS-IS, per instance: the configuration, and the interfaces it runs on.
// Interfaces are referred to by name (renaming one rewrites them, deleting
// one in use is refused, web/ifzones.go), route maps as BGP does
// (eachRoutingRef).

func presentIsisInterface(i *models.IsisInterface) {
	i.HasPassword = i.Password != ""
	i.NewPassword, i.ClearPassword = "", false
}
