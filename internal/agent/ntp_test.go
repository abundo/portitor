// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"errors"
	"strings"
	"testing"
)

func TestNTPInstance(t *testing.T) {
	answers := map[string]string{
		"-c -n sources": "^,*,194.58.202.20,1,10,377,27,0.000206198,0.000205614,0.001016516\n" +
			"^,?,2001:db8::1,0,6,0,-,0.000000000,0.000000000,0.000000000\n",
		"-c -n sourcestats":        "194.58.202.20,27,15,23278,-0.000,0.015,-0.000003893,0.000136919\n",
		"-c -n authdata":           "194.58.202.20,NTS,1,15,256,33,0,0,8,64\n2001:db8::1,-,0,0,0,0,0,0,0,0\n",
		"tracking":                 "Reference ID    : C23ACA14 (194.58.202.20)\nStratum         : 2\n",
		"serverstats":              "NTP packets received       : 12\n",
		"sourcename 194.58.202.20": "2.debian.pool.ntp.org\n",
		"sourcename 2001:db8::1":   "2001:db8::1\n",
	}
	chronyc := func(args ...string) ([]byte, error) {
		return []byte(answers[strings.Join(args, " ")]), nil
	}
	ni := ntpInstance("main", chronyc)
	if ni.Error != "" || len(ni.Sources) != 2 {
		t.Fatalf("%+v", ni)
	}
	s := ni.Sources[0]
	if s.Mode != "server" || s.State != "selected" || s.Stratum != 1 || s.Poll != 1024 || s.Reach != 0o377 ||
		s.LastRx != 27 || s.Offset != 0.000206198 || s.Samples != 27 || s.Span != 23278 || s.StdDev != 0.000136919 || s.Auth != "NTS" || s.Name != "2.debian.pool.ntp.org" {
		t.Errorf("source %+v", s)
	}
	if u := ni.Sources[1]; u.State != "unusable" || u.Reach != 0 || u.Auth != "" || u.Name != "" {
		t.Errorf("unusable %+v", u)
	}
	if len(ni.Tracking) != 2 || ni.Tracking[0].Name != "Reference ID" || ni.Tracking[0].Value != "C23ACA14 (194.58.202.20)" {
		t.Errorf("tracking %+v", ni.Tracking)
	}
	if len(ni.ServerStats) != 1 || ni.ServerStats[0].Value != "12" {
		t.Errorf("serverstats %+v", ni.ServerStats)
	}

	down := ntpInstance("vf", func(...string) ([]byte, error) {
		return []byte("506 Cannot talk to daemon\n"), errors.New("exit status 1")
	})
	if down.Error != "506 Cannot talk to daemon" {
		t.Errorf("down %+v", down)
	}
}
