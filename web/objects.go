// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"github.com/abundo/portitor/internal/confview"
	"github.com/abundo/portitor/internal/netobj"
)

// Named hosts and prefixes, and address lists, which share their names.

// nameSet resolves every host and address list of v.
func nameSet(v *confview.View) netobj.Set {
	return netobj.New(v.AddressObjects, v.AddressLists...)
}
