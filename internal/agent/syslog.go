// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"encoding/json"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/fwconfig"
)

// The journal's directories: persistent, and volatile (journald's
// Storage=auto keeps it there when the first doesn't exist).
var journalDirs = []string{"/var/log/journal", "/run/log/journal"}

// Syslog reports rsyslog, which sends the journal to the default
// instance's syslog servers, and the journal.
func (a *Agent) Syslog(ctx context.Context) *agentapi.SyslogStatus {
	st := &agentapi.SyslogStatus{Servers: []fwconfig.SyslogServer{}, Unit: a.cfg.Units.Rsyslog()}
	a.mu.Lock()
	doc := a.applied
	a.mu.Unlock()
	if doc != nil {
		for i := range doc.Instances {
			if in := &doc.Instances[i]; in.Default && in.Syslog != nil {
				st.Servers = in.Syslog.Servers
			}
		}
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if out, err := a.bg.Run(cctx, "", "systemctl", "show", st.Unit, "--property=ActiveState,ActiveEnterTimestamp", "--timestamp=unix"); err == nil {
		st.State, st.Since = parseUnitActive(string(out))
	}
	if out, err := a.bg.Run(cctx, "", "journalctl", "--list-boots", "--output=json", "--no-pager"); err == nil {
		st.JournalSince = parseFirstEntry(out)
	}
	if fi, err := os.Stat(journalDirs[0]); err == nil && fi.IsDir() {
		st.JournalPersistent = true
	}
	for _, d := range journalDirs {
		st.JournalBytes += dirSize(d)
	}
	return st
}

// parseUnitActive reads systemctl show's ActiveState and
// ActiveEnterTimestamp (--timestamp=unix: "@<seconds>"; empty when it never
// was).
func parseUnitActive(out string) (string, *time.Time) {
	var state string
	var since *time.Time
	for _, line := range strings.Split(out, "\n") {
		k, v, _ := strings.Cut(strings.TrimSpace(line), "=")
		switch k {
		case "ActiveState":
			state = v
		case "ActiveEnterTimestamp":
			if n, err := strconv.ParseInt(strings.TrimPrefix(v, "@"), 10, 64); err == nil && n > 0 {
				t := time.Unix(n, 0).UTC()
				since = &t
			}
		}
	}
	if state != "active" {
		since = nil
	}
	return state, since
}

// parseFirstEntry reads the oldest entry's time from journalctl
// --list-boots --output=json (first_entry in microseconds).
func parseFirstEntry(out []byte) *time.Time {
	var boots []struct {
		FirstEntry int64 `json:"first_entry"`
	}
	if json.Unmarshal(out, &boots) != nil {
		return nil
	}
	var first int64
	for _, b := range boots {
		if b.FirstEntry > 0 && (first == 0 || b.FirstEntry < first) {
			first = b.FirstEntry
		}
	}
	if first == 0 {
		return nil
	}
	t := time.UnixMicro(first).UTC()
	return &t
}

// dirSize is the size of the regular files under dir (0 when it doesn't
// exist).
func dirSize(dir string) int64 {
	var n int64
	_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.Type().IsRegular() {
			if fi, err := d.Info(); err == nil {
				n += fi.Size()
			}
		}
		return nil
	})
	return n
}

// handleJournal streams the host's whole journal as text.
func (a *Agent) handleJournal(w http.ResponseWriter, r *http.Request) {
	var req agentapi.JournalRequest
	if !decode(w, r, &req) {
		return
	}
	lines := req.Lines
	if lines <= 0 {
		lines = agentapi.JournalLines
	}
	a.followJournal(w, r, min(lines, agentapi.JournalMaxLines), "journal")
}
