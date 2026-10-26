// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/dnsblocklist"
	"github.com/abundo/portitor/internal/fwconfig"
)

// fakeBlocklists serves each list as its URL's last path element, a
// name; "fail" in the URL fails, and a list with validators is unchanged.
type fakeBlocklists struct {
	mu    sync.Mutex
	calls map[string]int
}

func (f *fakeBlocklists) fetch(_ context.Context, b fwconfig.DNSBlocklist, prev []dnsblocklist.Validator, _ string, w io.Writer) (*dnsblocklist.Result, error) {
	f.mu.Lock()
	f.calls[b.Name]++
	f.mu.Unlock()
	u := b.FetchURLs()[0]
	if strings.Contains(u, "fail") {
		return nil, errors.New("503 Service Unavailable")
	}
	v := []dnsblocklist.Validator{{ETag: `"1"`}}
	if prev != nil {
		return &dnsblocklist.Result{NotModified: true, Validators: v}, nil
	}
	io.WriteString(w, u[strings.LastIndex(u, "/")+1:]+" CNAME .\n")
	return &dnsblocklist.Result{Names: 1, Skipped: 2, Validators: v}, nil
}

func (f *fakeBlocklists) count(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[name]
}

func waitBlocklist(t *testing.T, a *Agent, name, state string, fetches func() int, want int) DNSBlocklistStatus {
	t.Helper()
	for range 400 {
		for _, s := range a.blocklists.Status() {
			if s.Name == name && s.State == state && (fetches == nil || fetches() == want) {
				return s
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("dns blocklist %s never got state %s: %+v", name, state, a.blocklists.Status())
	return DNSBlocklistStatus{}
}

func TestDNSBlocklistsFollowApply(t *testing.T) {
	a, h := testAgent(t)
	fb := &fakeBlocklists{calls: map[string]int{}}
	a.blocklists.fetch = fb.fetch
	doc := fwconfig.SampleDocument()
	in := &doc.Instances[0]
	in.DNS.Blocklists = []fwconfig.DNSBlocklist{{Name: "tif", URLs: []string{"https://example.com/bad.example"}, Action: fwconfig.BlocklistNXDomain}}
	ctx := context.Background()
	// In a dry run the zone files are in the agent's state.
	zone := filepath.Join(a.cfg.Paths.StateDir, "dnsblocklists", in.Name, "tif.db")

	if _, err := a.Apply(ctx, doc, 0); err != nil {
		t.Fatal(err)
	}
	st := waitBlocklist(t, a, "tif", "ok", nil, 0)
	if st.Instance != in.Name || st.Names != 1 || st.Skipped != 2 || st.Updated == nil || st.Next == nil || st.LastError != "" {
		t.Errorf("status %+v", st)
	}
	if data, err := os.ReadFile(zone); err != nil || !strings.HasPrefix(string(data), "; dns blocklist tif.") || !strings.HasSuffix(string(data), "\nbad.example CNAME .\n") {
		t.Errorf("zone file: %q %v", data, err)
	}

	// Applying again downloads nothing; neither does a restart, which
	// finds the last download on disk and waits for its refresh.
	if _, err := a.Apply(ctx, doc, 0); err != nil {
		t.Fatal(err)
	}
	a2 := New(a.cfg)
	t.Cleanup(a2.Stop)
	a2.blocklists.fetch = fb.fetch
	if err := a2.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if st := waitBlocklist(t, a2, "tif", "ok", nil, 0); st.Names != 1 || st.Next.Before(time.Now().Add(11*time.Hour)) {
		t.Errorf("after restart: %+v", st)
	}
	a2.Stop()
	if n := fb.count("tif"); n != 1 {
		t.Errorf("downloaded %d times, want 1", n)
	}

	// Download now, through the API: unchanged, the zone stays.
	if rec := call(t, h, "POST", "/v1/dns/blocklists/refresh", testToken, agentapi.DNSBlocklistRequest{Instance: in.Name, Name: "tif"}); rec.Code != http.StatusAccepted {
		t.Errorf("refresh: %d %s", rec.Code, rec.Body)
	}
	if st := waitBlocklist(t, a, "tif", "ok", func() int { return fb.count("tif") }, 2); st.Names != 1 {
		t.Errorf("unchanged: %+v", st)
	}
	if rec := call(t, h, "POST", "/v1/dns/blocklists/refresh", testToken, agentapi.DNSBlocklistRequest{Instance: in.Name, Name: "nope"}); rec.Code != http.StatusNotFound {
		t.Errorf("unknown list: %d", rec.Code)
	}

	// New URLs download again; a failed download keeps the last zone.
	in.DNS.Blocklists[0].URLs = []string{"https://fail/other.example"}
	if _, err := a.Apply(ctx, doc, 0); err != nil {
		t.Fatal(err)
	}
	if st := waitBlocklist(t, a, "tif", "error", nil, 0); st.LastError != "503 Service Unavailable" || st.Names != 1 || st.Next.After(time.Now().Add(dnsBlocklistRetry)) {
		t.Errorf("failed download: %+v", st)
	}
	if data, _ := os.ReadFile(zone); !strings.Contains(string(data), "bad.example") {
		t.Errorf("zone after a failed download: %s", data)
	}

	// A removed list loses its files.
	in.DNS.Blocklists = nil
	if _, err := a.Apply(ctx, doc, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(zone); !os.IsNotExist(err) {
		t.Errorf("zone file still there: %v", err)
	}
	if n := len(a.blocklists.Status()); n != 0 {
		t.Errorf("%d lists left", n)
	}
}
