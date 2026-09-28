// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package buildinfo holds version information set at link time
// (see LDFLAGS in the Makefile, and .goreleaser.yaml).
package buildinfo

import "runtime"

var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	Date      string `json:"date"`
	GoVersion string `json:"go_version"`
}

func Get() Info {
	return Info{Version: Version, Commit: Commit, Date: Date, GoVersion: runtime.Version()}
}
