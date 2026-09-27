// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build release

// Release build (`go build -tags release`): the frontend in web/static,
// built by `npm run build`, is embedded, so the binary is self-contained.
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:static
var rawStatic embed.FS

func staticFS() fs.FS {
	sub, err := fs.Sub(rawStatic, "static")
	if err != nil {
		panic(err)
	}
	return sub
}
