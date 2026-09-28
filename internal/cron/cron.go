// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package cron parses crontab(5) schedules and computes when they fire.
//
// A schedule has five fields, minute hour day-of-month month day-of-week,
// each "*", a number, a range "a-b", a step "*/n" or "a-b/n", or a comma
// list of those. Months and weekdays may be written by name (jan, mon); 0
// and 7 are both Sunday. As in cron, when both day fields are restricted a
// day matches if either does. The macros @yearly (@annually), @monthly,
// @weekly, @daily (@midnight) and @hourly stand for their usual schedules.
package cron

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Schedule is a parsed schedule. Each field is a bit set of the values it
// matches.
type Schedule struct {
	minute, hour, dom, month, dow uint64
	// domStar/dowStar: the day field was "*" (or a "*/n" step), so the
	// other day field alone decides.
	domStar, dowStar bool
}

var macros = map[string]string{
	"@yearly":   "0 0 1 1 *",
	"@annually": "0 0 1 1 *",
	"@monthly":  "0 0 1 * *",
	"@weekly":   "0 0 * * 0",
	"@daily":    "0 0 * * *",
	"@midnight": "0 0 * * *",
	"@hourly":   "0 * * * *",
}

var (
	monthNames = []string{"jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"}
	dayNames   = []string{"sun", "mon", "tue", "wed", "thu", "fri", "sat"}
)

type field struct {
	name     string
	min, max int
	names    []string // names[i] is min+i
}

var fields = []field{
	{"minute", 0, 59, nil},
	{"hour", 0, 23, nil},
	{"day of month", 1, 31, nil},
	{"month", 1, 12, monthNames},
	{"day of week", 0, 7, dayNames},
}

// Parse parses a schedule.
func Parse(spec string) (*Schedule, error) {
	spec = strings.TrimSpace(spec)
	if len(spec) > 200 {
		return nil, errors.New("schedule is too long")
	}
	if m, ok := macros[strings.ToLower(spec)]; ok {
		spec = m
	} else if strings.HasPrefix(spec, "@") {
		return nil, fmt.Errorf("unknown macro %q", spec)
	}
	parts := strings.Fields(spec)
	if len(parts) != 5 {
		return nil, fmt.Errorf("want 5 fields (minute hour day-of-month month day-of-week), got %d", len(parts))
	}
	var bits [5]uint64
	var star [5]bool
	for i, f := range fields {
		b, s, err := f.parse(parts[i])
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f.name, err)
		}
		bits[i], star[i] = b, s
	}
	// Sunday is 0 and 7.
	if bits[4]&(1<<7) != 0 {
		bits[4] = bits[4]&^(1<<7) | 1
	}
	return &Schedule{
		minute: bits[0], hour: bits[1], dom: bits[2], month: bits[3], dow: bits[4],
		domStar: star[2], dowStar: star[4],
	}, nil
}

// parse returns the values a field matches, and whether it starts with
// "*" (which matters for the day fields).
func (f field) parse(s string) (uint64, bool, error) {
	var bits uint64
	star := strings.HasPrefix(s, "*")
	for _, item := range strings.Split(s, ",") {
		rng, stepStr, hasStep := strings.Cut(item, "/")
		step := 1
		if hasStep {
			n, err := strconv.Atoi(stepStr)
			if err != nil || n < 1 || n > f.max {
				return 0, false, fmt.Errorf("invalid step %q", stepStr)
			}
			step = n
		}
		var lo, hi int
		switch {
		case rng == "*":
			lo, hi = f.min, f.max
			if f.max == 7 {
				hi = 6 // "*" for weekdays is 0-6; 7 would repeat Sunday
			}
		case strings.Contains(rng, "-"):
			a, b, _ := strings.Cut(rng, "-")
			var err error
			if lo, err = f.value(a); err != nil {
				return 0, false, err
			}
			if hi, err = f.value(b); err != nil {
				return 0, false, err
			}
			if lo > hi {
				return 0, false, fmt.Errorf("range %q runs backwards", rng)
			}
		default:
			v, err := f.value(rng)
			if err != nil {
				return 0, false, err
			}
			lo, hi = v, v
			if hasStep {
				hi = f.max // "5/15" is 5-max/15, as in Vixie cron
			}
		}
		for v := lo; v <= hi; v += step {
			bits |= 1 << uint(v)
		}
	}
	return bits, star, nil
}

func (f field) value(s string) (int, error) {
	if s == "" {
		return 0, errors.New("empty value")
	}
	for i, n := range f.names {
		if strings.EqualFold(s, n) {
			return f.min + i, nil
		}
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid value %q", s)
	}
	if v < f.min || v > f.max {
		return 0, fmt.Errorf("%d is outside %d-%d", v, f.min, f.max)
	}
	return v, nil
}

// maxYears bounds the search for the next time: a schedule such as
// "0 0 30 2 *" never fires.
const maxYears = 5

// Next returns the first time after t that the schedule fires, in t's
// location, or the zero time if it never does.
func (s *Schedule) Next(t time.Time) time.Time {
	loc := t.Location()
	// Start at the next whole minute.
	t = t.Truncate(time.Minute).Add(time.Minute)
	limit := t.AddDate(maxYears, 0, 0)
	for t.Before(limit) {
		if s.month&(1<<uint(t.Month())) == 0 {
			t = time.Date(t.Year(), t.Month()+1, 1, 0, 0, 0, 0, loc)
			continue
		}
		if !s.dayMatches(t) {
			t = time.Date(t.Year(), t.Month(), t.Day()+1, 0, 0, 0, 0, loc)
			continue
		}
		if s.hour&(1<<uint(t.Hour())) == 0 {
			next := time.Date(t.Year(), t.Month(), t.Day(), t.Hour()+1, 0, 0, 0, loc)
			if !next.After(t) {
				// A daylight saving fold repeats the hour: go on
				// from the absolute time instead.
				next = t.Truncate(time.Hour).Add(time.Hour)
			}
			t = next
			continue
		}
		if s.minute&(1<<uint(t.Minute())) == 0 {
			t = t.Add(time.Minute)
			continue
		}
		return t
	}
	return time.Time{}
}

func (s *Schedule) dayMatches(t time.Time) bool {
	dom := s.dom&(1<<uint(t.Day())) != 0
	dow := s.dow&(1<<uint(t.Weekday())) != 0
	if s.domStar || s.dowStar {
		return dom && dow
	}
	return dom || dow
}
