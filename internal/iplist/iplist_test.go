// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package iplist

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/abundo/portitor/internal/fwconfig"
)

func prefixes(res *Result) string {
	var out []string
	for _, p := range res.Prefixes {
		out = append(out, p.String())
	}
	return strings.Join(out, " ")
}

func TestParseText(t *testing.T) {
	res, err := ParseText(strings.NewReader(`; Spamhaus DROP List
# comment
192.0.2.0/24 ; SBL1
198.51.100.7
198.51.100.7
198.51.100.0/25 extra words
10.1.2.3/8
2001:db8::1
2001:db8::/32
::ffff:203.0.113.9
fe80::1%eth0
not-an-address
	   
`))
	if err != nil {
		t.Fatal(err)
	}
	want := "10.0.0.0/8 192.0.2.0/24 198.51.100.0/25 203.0.113.9/32 2001:db8::/32"
	if got := prefixes(res); got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
	if res.Skipped != 2 {
		t.Errorf("skipped %d, want 2", res.Skipped)
	}
}

func TestNormalizeNested(t *testing.T) {
	var in []netip.Prefix
	for _, s := range []string{"10.0.0.0/24", "10.0.0.128/25", "10.0.1.0/24", "10.0.0.0/16", "11.0.0.1/32", "::/0", "2001:db8::/32", "0.0.0.0/0"} {
		in = append(in, netip.MustParsePrefix(s))
	}
	got := Normalize(in)
	var out []string
	for _, p := range got {
		out = append(out, p.String())
	}
	if strings.Join(out, " ") != "0.0.0.0/0 ::/0" {
		t.Errorf("got %v", out)
	}
}

func TestFetchCrowdSec(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/decisions/stream" || r.URL.Query().Get("startup") != "true" || r.URL.Query().Get("scopes") != "ip,range" {
			http.Error(w, "bad request "+r.URL.String(), http.StatusBadRequest)
			return
		}
		if r.Header.Get("X-Api-Key") != "secret" {
			http.Error(w, `{"message":"access forbidden"}`, http.StatusForbidden)
			return
		}
		fmt.Fprint(w, `{"new":[
			{"duration":"3h","origin":"CAPI","scenario":"ssh-bf","scope":"Ip","type":"ban","value":"192.0.2.1"},
			{"scope":"Range","type":"ban","value":"198.51.100.0/24"},
			{"scope":"Ip","type":"captcha","value":"192.0.2.2"},
			{"scope":"Country","type":"ban","value":"XX"},
			{"scope":"ip","type":"ban","value":"2001:db8::7"}
		],"deleted":null}`)
	}))
	defer srv.Close()
	l := fwconfig.IPList{Name: "cs", Source: fwconfig.IPListCrowdSec, URL: srv.URL + "/", APIKey: "secret"}
	res, err := Fetch(context.Background(), srv.Client(), l, "test")
	if err != nil {
		t.Fatal(err)
	}
	if got := prefixes(res); got != "192.0.2.1/32 198.51.100.0/24 2001:db8::7/128" || res.Skipped != 2 {
		t.Errorf("got %s, skipped %d", got, res.Skipped)
	}

	l.APIKey = "wrong"
	if _, err := Fetch(context.Background(), srv.Client(), l, "test"); err == nil || !strings.Contains(err.Error(), "403 Forbidden") {
		t.Errorf("wrong key: %v", err)
	}
}

func TestFetchURLBasicAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "user" || p != "pw" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, "192.0.2.1\n192.0.2.0/24\n")
	}))
	defer srv.Close()
	l := fwconfig.IPList{Name: "bl", Source: fwconfig.IPListURL, URL: srv.URL, Username: "user", Password: "pw"}
	res, err := Fetch(context.Background(), srv.Client(), l, "test")
	if err != nil {
		t.Fatal(err)
	}
	if got := prefixes(res); got != "192.0.2.0/24" {
		t.Errorf("got %s", got)
	}
	l.Password = ""
	if _, err := Fetch(context.Background(), srv.Client(), l, "test"); err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("no password: %v", err)
	}
}

func TestFetchTooLarge(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		line := []byte(strings.Repeat("#", 1023) + "\n")
		for range MaxBody/len(line) + 1 {
			if _, err := w.Write(line); err != nil {
				return
			}
		}
	}))
	defer srv.Close()
	l := fwconfig.IPList{Name: "bl", Source: fwconfig.IPListURL, URL: srv.URL}
	if _, err := Fetch(context.Background(), srv.Client(), l, "test"); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("got %v", err)
	}
}
