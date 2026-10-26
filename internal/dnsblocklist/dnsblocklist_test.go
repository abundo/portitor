// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package dnsblocklist

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/abundo/portitor/internal/fwconfig"
)

func parse(t *testing.T, in string) (string, *Result) {
	t.Helper()
	var out bytes.Buffer
	w := bufio.NewWriter(&out)
	res := &Result{}
	if err := Parse(strings.NewReader(in), w, res); err != nil {
		t.Fatal(err)
	}
	w.Flush()
	return out.String(), res
}

func TestParseRPZ(t *testing.T) {
	// As Hagezi's and OISD's files start.
	in := `$TTL 3600
@ SOA localhost. root.localhost. 1792964700 28800 3600 259200 3600
  NS  localhost.
;
; Title: HaGeZi's Threat Intelligence Feeds
;
60347.ac CNAME .
*.60347.ac CNAME .
Bad.Example 300 IN CNAME *.
good.example CNAME rpz-passthru.
redirect.example CNAME evil.example.
32.1.2.0.192.rpz-ip CNAME .
host.example A 192.0.2.1
$INCLUDE /etc/shadow
`
	out, res := parse(t, in)
	want := "60347.ac CNAME .\n*.60347.ac CNAME .\nbad.example CNAME .\n"
	if out != want {
		t.Errorf("got\n%s\nwant\n%s", out, want)
	}
	if res.Names != 3 || res.Skipped != 5 {
		t.Errorf("names %d skipped %d, want 3 and 5", res.Names, res.Skipped)
	}
}

func TestParseRPZOrigin(t *testing.T) {
	in := `$ORIGIN rpz.example.
@ IN SOA ns. root. (
	1 3600 600
	86400 300 )
bad.example.rpz.example. CNAME .
other.example.elsewhere. CNAME .
`
	out, res := parse(t, in)
	if out != "bad.example CNAME .\n" || res.Skipped != 1 {
		t.Errorf("got %q, skipped %d", out, res.Skipped)
	}
}

func TestParseDomainLists(t *testing.T) {
	in := `# a list of domains
bad.example
||ads.example^
*.wild.example
0.0.0.0 one.example two.example
127.0.0.1 localhost
nodot
bad"quote.example
<html>
`
	out, res := parse(t, in)
	want := strings.Join([]string{
		"bad.example", "*.bad.example", "ads.example", "*.ads.example", "*.wild.example",
		"one.example", "*.one.example", "two.example", "*.two.example",
	}, " CNAME .\n") + " CNAME .\n"
	if out != want {
		t.Errorf("got\n%s\nwant\n%s", out, want)
	}
	if res.Skipped != 4 {
		t.Errorf("skipped %d, want 4", res.Skipped)
	}
}

func TestFetch(t *testing.T) {
	etag := `"v1"`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/secret-key/list.zip":
			w.Header().Set("ETag", etag)
			if r.Header.Get("If-None-Match") == etag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			zw := zip.NewWriter(w)
			f, _ := zw.Create("urlhaus.rpz")
			f.Write([]byte("zipped.example CNAME .\n"))
			zw.Close()
		case "/plain":
			w.Header().Set("Last-Modified", "Mon, 26 Oct 2026 10:00:00 GMT")
			if r.Header.Get("If-Modified-Since") != "" {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Write([]byte("plain.example\n"))
		case "/html":
			w.Write([]byte("<html><body>log in</body></html>\n"))
		default:
			http.Error(w, "no such file secret-key", http.StatusNotFound)
		}
	}))
	defer srv.Close()
	b := fwconfig.DNSBlocklist{Name: "x", URLs: []string{srv.URL + "/{key}/list.zip", srv.URL + "/plain"}, Key: "secret-key"}
	ctx := context.Background()
	client := NewClient(0)

	var out bytes.Buffer
	res, err := Fetch(ctx, client, b, nil, "test", t.TempDir(), &out)
	if err != nil {
		t.Fatal(err)
	}
	if want := "zipped.example CNAME .\nplain.example CNAME .\n*.plain.example CNAME .\n"; out.String() != want || res.Names != 3 {
		t.Errorf("got %q (%d names)", out.String(), res.Names)
	}

	// Both unchanged: nothing written.
	out.Reset()
	again, err := Fetch(ctx, client, b, res.Validators, "test", t.TempDir(), &out)
	if err != nil || !again.NotModified || out.Len() != 0 {
		t.Errorf("unchanged: %+v, %v, %q", again, err, out.String())
	}

	// One changed: the other is downloaded again in full.
	etag = `"v2"`
	out.Reset()
	changed, err := Fetch(ctx, client, b, res.Validators, "test", t.TempDir(), &out)
	if err != nil || changed.NotModified || changed.Names != 3 {
		t.Errorf("one changed: %+v, %v", changed, err)
	}

	// The key is never in an error.
	b.URLs = []string{srv.URL + "/{key}/missing"}
	if _, err := Fetch(ctx, client, b, nil, "test", t.TempDir(), &out); err == nil || strings.Contains(err.Error(), "secret-key") {
		t.Errorf("error %v shows the key, or none", err)
	}

	// A page that is not a blocklist fails.
	b.URLs, b.Key = []string{srv.URL + "/html"}, ""
	if _, err := Fetch(ctx, client, b, nil, "test", t.TempDir(), &out); err == nil || !strings.Contains(err.Error(), "not a blocklist") {
		t.Errorf("html: %v", err)
	}
}
