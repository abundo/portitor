// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"io"
	"log/slog"
	"testing"
)

func TestLogRing(t *testing.T) {
	r := NewLogRing(3)
	log := slog.New(r.Handler(slog.NewTextHandler(io.Discard, nil))).With("instance", "fw1")
	log.Info("one")
	log.WithGroup("g").Warn("two", "k", "v")
	log.Debug("hidden")
	log.Info("three")
	log.Info("four")

	all := r.After(0)
	if len(all) != 3 || all[0].Message != "two" || all[2].Message != "four" {
		t.Fatalf("ring = %+v", all)
	}
	if all[0].Level != "WARN" || all[0].Attrs["g.k"] != "v" || all[0].Attrs["instance"] != "fw1" {
		t.Errorf("entry = %+v", all[0])
	}
	if got := r.After(all[1].ID); len(got) != 1 || got[0].Message != "four" {
		t.Errorf("after = %+v", got)
	}
	if got := r.After(all[2].ID); len(got) != 0 {
		t.Errorf("after newest = %+v", got)
	}
	if got := r.After(all[2].ID + 1000); len(got) != 3 {
		t.Errorf("after future id = %d entries, want all", len(got))
	}
}
