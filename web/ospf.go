// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"github.com/abundo/portitor/models"
)

// OSPF, per instance and version (2: OSPFv2, IPv4; 3: OSPFv3, IPv6): the
// configuration, and the interfaces it runs on. Interfaces are referred to
// by name (renaming one rewrites them, deleting one in use is refused,
// web/ifzones.go), route maps as BGP does (eachRoutingRef).

func presentOspfInterface(i *models.OspfInterface) {
	i.HasAuthKey = i.AuthKey != ""
	i.NewAuthKey, i.ClearAuthKey = "", false
}
