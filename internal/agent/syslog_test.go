// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseUnitActive(t *testing.T) {
	state, since := parseUnitActive("ActiveState=active\nActiveEnterTimestamp=@1761555600\n")
	if state != "active" || since == nil || !since.Equal(time.Unix(1761555600, 0)) {
		t.Errorf("active: %q %v", state, since)
	}
	if state, since := parseUnitActive("ActiveState=failed\nActiveEnterTimestamp=@1761555600\n"); state != "failed" || since != nil {
		t.Errorf("failed: %q %v", state, since)
	}
	if state, since := parseUnitActive("ActiveState=inactive\nActiveEnterTimestamp=\n"); state != "inactive" || since != nil {
		t.Errorf("inactive: %q %v", state, since)
	}
}

func TestParseFirstEntry(t *testing.T) {
	out := `[{"index":-1,"boot_id":"a","first_entry":1761469200000000,"last_entry":1761469300000000},` +
		`{"index":0,"boot_id":"b","first_entry":1761555600000000,"last_entry":1761555700000000}]`
	if got := parseFirstEntry([]byte(out)); got == nil || !got.Equal(time.Unix(1761469200, 0)) {
		t.Errorf("got %v", got)
	}
	if got := parseFirstEntry([]byte("No journal boot entry found.")); got != nil {
		t.Errorf("not JSON: %v", got)
	}
}

func TestDirSize(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "m"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, n := range map[string]int{"m/system.journal": 100, "m/user-1000.journal": 20} {
		if err := os.WriteFile(filepath.Join(dir, name), make([]byte, n), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if got := dirSize(dir); got != 120 {
		t.Errorf("got %d", got)
	}
	if got := dirSize(filepath.Join(dir, "none")); got != 0 {
		t.Errorf("missing: %d", got)
	}
}
