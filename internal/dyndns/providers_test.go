// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package dyndns

import (
	"context"
	"log/slog"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libdns/libdns"

	"github.com/abundo/portitor/internal/fwconfig"
)

// Every provider in the document's list can be made, and each of its
// settings is a JSON field of the libdns provider.
func TestProvidersMatchFwconfig(t *testing.T) {
	for _, p := range fwconfig.DNSProviders {
		if p.Name == fwconfig.ProviderRFC2136 {
			continue
		}
		mk := providers[p.Name]
		if mk == nil {
			t.Errorf("%s: no libdns provider", p.Name)
			continue
		}
		var tags []string
		typ := reflect.TypeOf(mk()).Elem()
		for i := range typ.NumField() {
			tags = append(tags, strings.Split(typ.Field(i).Tag.Get("json"), ",")[0])
		}
		settings := map[string]string{}
		for _, f := range p.Fields {
			if !slices.Contains(tags, f.Key) {
				t.Errorf("%s: %s is not a field of the provider (%v)", p.Name, f.Key, tags)
			}
			settings[f.Key] = "x"
		}
		got, err := NewProvider(p.Name, settings)
		if err != nil {
			t.Fatalf("%s: %v", p.Name, err)
		}
		v := reflect.ValueOf(got).Elem()
		for i := range typ.NumField() {
			tag := strings.Split(typ.Field(i).Tag.Get("json"), ",")[0]
			if settings[tag] != "" && v.Field(i).String() != "x" {
				t.Errorf("%s: %s not set", p.Name, tag)
			}
		}
	}
	for name := range providers {
		if fwconfig.FindDNSProvider(name) == nil {
			t.Errorf("%s is not in fwconfig.DNSProviders", name)
		}
	}
}

// fakeProvider is a DNS hosting provider in memory with libdns semantics:
// SetRecords replaces the RRsets of the names and types it is given.
type fakeProvider struct {
	mu    sync.Mutex
	recs  []libdns.Record
	lists int
	sets  int
}

func (f *fakeProvider) GetRecords(_ context.Context, zone string) ([]libdns.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if zone != "example.com." {
		return nil, context.DeadlineExceeded
	}
	f.lists++
	return slices.Clone(f.recs), nil
}

func (f *fakeProvider) SetRecords(_ context.Context, _ string, recs []libdns.Record) ([]libdns.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sets++
	for _, r := range recs {
		f.recs = slices.DeleteFunc(f.recs, func(o libdns.Record) bool {
			return o.RR().Name == r.RR().Name && o.RR().Type == r.RR().Type
		})
	}
	f.recs = append(f.recs, recs...)
	return recs, nil
}

func TestProviderSync(t *testing.T) {
	cfg, err := NewConfig(fwconfig.DynDNS{Name: "t", Interface: "eth0", Provider: "cloudflare", Zone: "example.com",
		Records: []fwconfig.DynDNSRecord{
			{Name: "home", Type: "A", TTL: 60},
			{Name: "@", Type: "AAAA"},
			{Name: "www", Type: "CNAME", Value: "home"},
			{Name: "home", Type: "TXT"},
		}})
	if err != nil {
		t.Fatal(err)
	}
	p := &fakeProvider{recs: []libdns.Record{
		libdns.Address{Name: "home", TTL: time.Minute, IP: netip.MustParseAddr("198.51.100.1")},
		libdns.Address{Name: "other", TTL: time.Minute, IP: netip.MustParseAddr("198.51.100.9")},
	}}
	ifc := &iface{}
	ifc.set("198.51.100.7", "2001:db8::7")
	now := fixedNow
	c, err := New(cfg, Env{
		Addrs: ifc.addrs, Provider: p, Log: slog.New(slog.DiscardHandler),
		Now: func() time.Time { return now }, VerifyDelay: -1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Sync(t.Context(), false); err != nil {
		t.Fatal(err)
	}
	if p.sets != 1 {
		t.Fatalf("SetRecords calls = %d, want 1", p.sets)
	}
	var got []string
	for _, r := range p.recs {
		rr := r.RR()
		got = append(got, rr.Name+" "+rr.Type+" "+rr.Data)
	}
	slices.Sort(got)
	want := []string{
		"@ AAAA 2001:db8::7",
		"home A 198.51.100.7",
		"home TXT 2026-09-28T12:00:00Z",
		"other A 198.51.100.9",
		"www CNAME home.example.com.",
	}
	if !slices.Equal(got, want) {
		t.Errorf("records =\n%v\nwant\n%v", got, want)
	}

	// One listing before the update and one to verify it.
	if p.lists != 2 {
		t.Errorf("lists = %d, want 2", p.lists)
	}
	// Now correct: one listing checks every record, no update.
	now = now.Add(time.Minute)
	if err := c.Sync(t.Context(), false); err != nil {
		t.Fatal(err)
	}
	if p.sets != 1 || p.lists != 3 {
		t.Errorf("sets = %d, lists = %d after a matching sync, want 1, 3", p.sets, p.lists)
	}
}

func TestNewProviderUnknown(t *testing.T) {
	if _, err := NewProvider("nope", nil); err == nil {
		t.Fatal("unknown provider made")
	}
	cfg, err := NewConfig(fwconfig.DynDNS{Provider: "hetzner", Zone: "example.com", Records: []fwconfig.DynDNSRecord{{Name: "home", Type: "A"}}})
	if err != nil || cfg.Server != "" {
		t.Fatalf("cfg = %+v, err = %v", cfg, err)
	}
}
