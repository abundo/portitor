// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package cron

import (
	"testing"
	"time"
)

func TestNext(t *testing.T) {
	from := time.Date(2026, 9, 28, 10, 7, 30, 0, time.UTC) // a Monday
	for _, c := range []struct {
		spec string
		want string
	}{
		{"* * * * *", "2026-09-28 10:08"},
		{"*/15 * * * *", "2026-09-28 10:15"},
		{"5 * * * *", "2026-09-28 11:05"},
		{"0 3 * * *", "2026-09-29 03:00"},
		{"@daily", "2026-09-29 00:00"},
		{"@hourly", "2026-09-28 11:00"},
		{"@weekly", "2026-10-04 00:00"},
		{"@monthly", "2026-10-01 00:00"},
		{"@yearly", "2027-01-01 00:00"},
		{"30 8 * * mon-fri", "2026-09-29 08:30"},
		{"0 12 * * 7", "2026-10-04 12:00"},
		{"0 12 * * sun", "2026-10-04 12:00"},
		{"0 0 1 jan,jul *", "2027-01-01 00:00"},
		{"10-20/5 10 * * *", "2026-09-28 10:10"},
		{"5/20 * * * *", "2026-09-28 10:25"},
		// Both day fields restricted: either matches (the 1st, or a Friday).
		{"0 0 1 * fri", "2026-10-01 00:00"},
		{"0 0 13 * fri", "2026-10-02 00:00"},
		// A step on a day field counts as "*": both must match.
		{"0 0 */2 * fri", "2026-10-09 00:00"},
		{"0 0 29 2 *", "2028-02-29 00:00"},
	} {
		s, err := Parse(c.spec)
		if err != nil {
			t.Errorf("%q: %v", c.spec, err)
			continue
		}
		if got := s.Next(from).Format("2006-01-02 15:04"); got != c.want {
			t.Errorf("%q: next %s, want %s", c.spec, got, c.want)
		}
	}
}

func TestNever(t *testing.T) {
	s, err := Parse("0 0 30 2 *")
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Next(time.Now()); !got.IsZero() {
		t.Errorf("Feb 30 fires at %s", got)
	}
}

func TestDaylightSaving(t *testing.T) {
	loc, err := time.LoadLocation("Europe/Stockholm")
	if err != nil {
		t.Skip(err)
	}
	// 2026-03-29 02:00 does not exist; 2026-10-25 02:00-03:00 happens twice.
	s, _ := Parse("30 2 * * *")
	got := s.Next(time.Date(2026, 3, 28, 12, 0, 0, 0, loc))
	if got.Day() != 30 || got.Hour() != 2 {
		t.Errorf("spring forward: %s", got)
	}
	s, _ = Parse("0 * * * *")
	first := time.Date(2026, 10, 25, 2, 0, 0, 0, loc) // first 02:00 (CEST)
	next := s.Next(first)
	if !next.After(first) || next.Sub(first) != time.Hour {
		t.Errorf("fall back: after %s comes %s", first, next)
	}
}

func TestParseErrors(t *testing.T) {
	for _, spec := range []string{
		"", "* * * *", "* * * * * *", "60 * * * *", "* 24 * * *", "* * 0 * *",
		"* * * 13 *", "* * * * 8", "*/0 * * * *", "5-1 * * * *", "a * * * *",
		"@every 5m", "1,,2 * * * *", "- * * * *",
	} {
		if _, err := Parse(spec); err == nil {
			t.Errorf("%q: no error", spec)
		}
	}
}
