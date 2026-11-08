// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"github.com/abundo/portitor/models"
)

// Routing policy objects (prefix lists, AS path lists, community lists,
// route maps) and BGP, per instance. They refer to each other by name:
// renaming an object rewrites the references to it, deleting one in use
// is refused, and a row can't move to another instance.

// Kinds of routing references.
const (
	refPrefixList = "prefix list"
	refASPath     = "as path list"
	refCommunity  = "community list"
	refRouteMap   = "route map"
	refPeerGroup  = "peer group"
)

func presentPeerGroup(g *models.BgpPeerGroup) { presentPeerSettings(&g.BgpPeerSettings) }
func presentNeighbor(n *models.BgpNeighbor)   { presentPeerSettings(&n.BgpPeerSettings) }

func presentPeerSettings(s *models.BgpPeerSettings) {
	s.HasPassword = s.Password != ""
	s.NewPassword, s.ClearPassword = "", false
}

// routingObjects are the names of an instance's routing objects.
type routingObjects struct {
	prefixLists map[string]string // name -> family
	names       map[string]map[string]bool
}
