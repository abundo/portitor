// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !release

// Dev build: the frontend is read from disk (web/static, relative to the
// working directory), so `npm run build` takes effect without a Go rebuild.
package web

import (
	"io/fs"
	"os"
)

func staticFS() fs.FS { return os.DirFS("web/static") }
