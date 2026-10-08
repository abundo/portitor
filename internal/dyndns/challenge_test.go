// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package dyndns

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/libdns/libdns"
	"github.com/miekg/dns"

	"github.com/abundo/portitor/internal/fwconfig"
)

// Two values at one name (example.com and *.example.com) are both there
// until each is removed; other TXT records at the name stay.
func TestTXTUpdaterRFC2136(t *testing.T) {
	ns := newFakeNS()
	ns.set(`_acme-challenge.www.acme.example.net. 60 IN TXT "keep"`)
	u, err := NewTXTUpdater(fwconfig.DNS01{
		Client: "acme", Server: "192.0.2.53", Zone: "Acme.Example.net",
		TSIG: &fwconfig.TSIG{Name: "acme-key", Algorithm: "hmac-sha256", Secret: "c2VjcmV0"},
	}, Env{Exchange: ns.exchange})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	name := "_acme-challenge.www.acme.example.net."
	for _, v := range []string{"one", "two"} {
		if err := u.Add(ctx, name, v); err != nil {
			t.Fatal(err)
		}
	}
	if got := ns.get(name, dns.TypeTXT); !slices.Equal(got, []string{`"keep"`, `"one"`, `"two"`}) {
		t.Errorf("after adding: %q", got)
	}
	if err := u.Remove(ctx, name, "one"); err != nil {
		t.Fatal(err)
	}
	if got := ns.get(name, dns.TypeTXT); !slices.Equal(got, []string{`"keep"`, `"two"`}) {
		t.Errorf("after removing: %q", got)
	}
	m := ns.updates[0]
	if m.Question[0].Name != "acme.example.net." || m.IsTsig() == nil || m.IsTsig().Hdr.Name != "acme-key." {
		t.Errorf("UPDATE: %v", m)
	}
	if err := u.Add(ctx, "_acme-challenge.www.example.com.", "x"); err == nil || !strings.Contains(err.Error(), "not in zone acme.example.net.") {
		t.Errorf("outside the zone: %v", err)
	}
	if n := ns.updateCount(); n != 3 {
		t.Errorf("%d UPDATEs, want 3", n)
	}
}

// txtFake is a provider that appends and deletes records.
type txtFake struct {
	fakeProvider
	zones []string
}

func (f *txtFake) AppendRecords(_ context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.zones = append(f.zones, zone)
	f.recs = append(f.recs, recs...)
	return recs, nil
}

func (f *txtFake) DeleteRecords(_ context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.zones = append(f.zones, zone)
	for _, r := range recs {
		f.recs = slices.DeleteFunc(f.recs, func(o libdns.Record) bool { return o.RR() == r.RR() })
	}
	return recs, nil
}

func TestTXTUpdaterProvider(t *testing.T) {
	p := &txtFake{}
	u, err := NewTXTUpdater(fwconfig.DNS01{Client: "acme", Provider: "cloudflare", Zone: "acme.example.net"}, Env{Provider: p})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := u.Add(ctx, "_acme-challenge.WWW.acme.example.net.", "one"); err != nil {
		t.Fatal(err)
	}
	if err := u.Add(ctx, "_acme-challenge.www.acme.example.net", "two"); err != nil {
		t.Fatal(err)
	}
	if err := u.Remove(ctx, "_acme-challenge.www.acme.example.net.", "one"); err != nil {
		t.Fatal(err)
	}
	if len(p.recs) != 1 {
		t.Fatalf("records: %+v", p.recs)
	}
	if rr := p.recs[0].RR(); rr.Name != "_acme-challenge.www" || rr.Type != "TXT" || rr.Data != "two" {
		t.Errorf("record: %+v", rr)
	}
	if !slices.Equal(p.zones, []string{"acme.example.net.", "acme.example.net.", "acme.example.net."}) {
		t.Errorf("zones: %q", p.zones)
	}
	// A provider that can only replace RRsets can't keep two values.
	if _, err := NewTXTUpdater(fwconfig.DNS01{Provider: "cloudflare", Zone: "example.net"}, Env{Provider: &fakeProvider{}}); err == nil {
		t.Error("a provider without append and delete accepted")
	}
}
