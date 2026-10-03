// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package netobj

import (
	"strings"
	"testing"

	"github.com/abundo/portitor/models"
)

func TestNames(t *testing.T) {
	for _, s := range []string{"nas", "web-1", "Office_LAN", "a.b", "1host", "a b", "x/y", "Kontor Göteborg", "be.ef"} {
		if !ValidName(s) || !IsName(s) {
			t.Errorf("%q should be a name", s)
		}
	}
	for _, s := range []string{"", "default", "any", "fd00::1", "10.0.0.0/8", "10.0.0.256", "@list", " a", "a\tb"} {
		if ValidName(s) {
			t.Errorf("%q should not be a valid name", s)
		}
	}
	// Hex-only words are names: without ':' they are no IPv6 address.
	if !IsName("cafe") || IsName("fd00::1") || IsName("192.168.1.1") {
		t.Error("IsName misclassifies")
	}
}

func TestExpand(t *testing.T) {
	s := New([]models.AddressObject{
		{Name: "nas", Addresses: models.StringList{"192.168.1.10", "fd00::10"}},
		{Name: "lan", Addresses: models.StringList{"192.168.1.0/24", "fd00::/64"}},
		{Name: "twice", Addresses: models.StringList{"10.0.0.1", "10.0.0.2"}},
	})
	got, err := s.Expand([]string{"nas", "10.0.0.0/8", "nas"})
	if err != nil || strings.Join(got, " ") != "192.168.1.10 fd00::10 10.0.0.0/8" {
		t.Errorf("Expand: %v %v", got, err)
	}
	if got, _ := s.Prefixes([]string{"nas"}); strings.Join(got, " ") != "192.168.1.10/32 fd00::10/128" {
		t.Errorf("Prefixes: %v", got)
	}
	if _, err := s.Hosts([]string{"lan"}); err == nil || !strings.Contains(err.Error(), "not a host") {
		t.Errorf("Hosts(lan): %v", err)
	}
	if got, err := s.Host("nas"); err != nil || len(got) != 2 {
		t.Errorf("Host(nas): %v %v", got, err)
	}
	if _, err := s.Host("twice"); err == nil {
		t.Error("Host needs at most one address per version")
	}
	if got, _ := s.Host("192.0.2.1"); len(got) != 1 || got[0] != "192.0.2.1" {
		t.Errorf("Host literal: %v", got)
	}
	if _, err := s.Expand([]string{"ghost"}); err == nil {
		t.Error("unknown name must fail")
	}
}
