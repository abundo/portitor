// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package buildinfo holds version information set at link time
// (see LDFLAGS in the Makefile, and .goreleaser.yaml).
package buildinfo

import (
	"fmt"
	"runtime"
	"strings"
)

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

// Mismatch says how the agent's version differs from this program's, or ""
// when they match. portitor-web and the agent are released together and
// should run the same version; a dev build (Version "dev") is not
// compared. A leading v is ignored: goreleaser stamps 1.2.3, the Makefile
// `git describe` v1.2.3.
func Mismatch(agent string) string {
	web, agent := strings.TrimPrefix(Version, "v"), strings.TrimPrefix(agent, "v")
	if web == "dev" || agent == "dev" || agent == "" || web == agent {
		return ""
	}
	return fmt.Sprintf("portitor-web is version %s but the agent is %s; update both to the same version (the agent first)", web, agent)
}
