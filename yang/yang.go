// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package yang holds Portitor's YANG modules, the source of the
// configuration's schema (internal/schema compiles them).
package yang

import "embed"

// Files are the modules: portitor.yang, its submodules and
// portitor-extensions.yang.
//
//go:embed *.yang
var Files embed.FS
