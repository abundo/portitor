// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/iplist"
)

// fakeFetch serves each list as its URL's last path element, an address;
// "fail" in the URL fails.
type fakeFetch struct {
	mu    sync.Mutex
	calls map[string]int
}

func (f *fakeFetch) fetch(_ context.Context, l fwconfig.IPList) (*iplist.Result, error) {
	f.mu.Lock()
	f.calls[l.Name]++
	f.mu.Unlock()
	if strings.Contains(l.URL, "fail") {
		return nil, errors.New("503 Service Unavailable")
	}
	addr := l.URL[strings.LastIndex(l.URL, "/")+1:]
	return &iplist.Result{Prefixes: []netip.Prefix{netip.MustParsePrefix(addr + "/32")}, Skipped: 1}, nil
}

func (f *fakeFetch) count(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[name]
}

func waitList(t *testing.T, a *Agent, name, state string) IPListStatus {
	t.Helper()
	for range 400 {
		for _, s := range a.lists.Status() {
			if s.Name == name && s.State == state {
				return s
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("ip list %s never got state %s: %+v", name, state, a.lists.Status())
	return IPListStatus{}
}

func TestIPListsFollowApply(t *testing.T) {
	a, h := testAgent(t)
	ff := &fakeFetch{calls: map[string]int{}}
	a.lists.fetch = ff.fetch
	doc := fwconfig.SampleDocument()
	doc.IPLists[0].URL = "http://lapi/192.0.2.1"
	doc.IPLists[1].URL = "https://lists/198.51.100.7"
	ctx := context.Background()

	if _, err := a.Apply(ctx, doc, 0); err != nil {
		t.Fatal(err)
	}
	st := waitList(t, a, "crowdsec", "ok")
	if st.IPv4 != 1 || st.IPv6 != 0 || st.Skipped != 1 || st.Updated == nil || st.LastError != "" {
		t.Errorf("status %+v", st)
	}
	waitList(t, a, "drop", "ok")
	data, err := os.ReadFile(a.cfg.Paths.IPListFile("crowdsec"))
	if err != nil || !strings.Contains(string(data), "add element inet firewall crowdsec_v4 { 192.0.2.1 }\n") {
		t.Errorf("elements file: %q %v", data, err)
	}

	// Applying the same lists again downloads nothing; neither does a
	// restart, which finds the last download on disk.
	if _, err := a.Apply(ctx, doc, 0); err != nil {
		t.Fatal(err)
	}
	a2 := New(a.cfg)
	t.Cleanup(a2.Stop)
	a2.lists.fetch = ff.fetch
	if err := a2.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if st := waitList(t, a2, "crowdsec", "ok"); st.IPv4 != 1 {
		t.Errorf("after restart: %+v", st)
	}
	if n := ff.count("crowdsec"); n != 1 {
		t.Errorf("downloaded %d times, want 1", n)
	}

	// A changed list is downloaded again; a failed download keeps the
	// last good elements.
	doc.IPLists[1].URL = "https://fail/198.51.100.8"
	if _, err := a.Apply(ctx, doc, 0); err != nil {
		t.Fatal(err)
	}
	if st := waitList(t, a, "drop", "error"); st.LastError != "503 Service Unavailable" || st.IPv4 != 1 {
		t.Errorf("failed download: %+v", st)
	}
	if data, _ := os.ReadFile(a.cfg.Paths.IPListFile("drop")); !strings.Contains(string(data), "198.51.100.7") {
		t.Errorf("elements after a failed download: %s", data)
	}

	// Download now, through the API.
	if rec := call(t, h, "POST", "/v1/iplists/refresh", testToken, agentapi.RunRequest{Name: "crowdsec"}); rec.Code != http.StatusAccepted {
		t.Errorf("refresh: %d %s", rec.Code, rec.Body)
	}
	waitList(t, a, "crowdsec", "ok")
	if n := ff.count("crowdsec"); n != 2 {
		t.Errorf("downloaded %d times, want 2", n)
	}
	if rec := call(t, h, "POST", "/v1/iplists/refresh", testToken, agentapi.RunRequest{Name: "nope"}); rec.Code != http.StatusNotFound {
		t.Errorf("unknown list: %d", rec.Code)
	}
	if rec := call(t, h, "POST", "/v1/tasks/run", testToken, agentapi.RunRequest{Name: "nope"}); rec.Code != http.StatusNotFound {
		t.Errorf("unknown task: %d", rec.Code)
	}

	// A task downloads its list and reports the result.
	if rec := call(t, h, "POST", "/v1/tasks/run", testToken, agentapi.RunRequest{Name: "drop"}); rec.Code != http.StatusAccepted {
		t.Errorf("run task: %d %s", rec.Code, rec.Body)
	}
	var task TaskStatus
	for i := 0; i < 400 && task.LastResult == ""; i++ {
		time.Sleep(5 * time.Millisecond)
		for _, s := range a.tasks.Status() {
			if s.Name == "drop" {
				task = s
			}
		}
	}
	if task.LastResult != "error" || task.LastError != "503 Service Unavailable" {
		t.Errorf("task status %+v", task)
	}

	// A removed list loses its files.
	doc.IPLists = doc.IPLists[:1]
	doc.Tasks = doc.Tasks[:1]
	in := &doc.Instances[0]
	in.Rules = in.Rules[:len(in.Rules)-1]
	in.Rules[len(in.Rules)-1].SrcAddrs = []string{"@crowdsec"}
	if _, err := a.Apply(ctx, doc, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(a.cfg.Paths.IPListFile("drop")); !os.IsNotExist(err) {
		t.Errorf("elements file of a removed list: %v", err)
	}
	if st := a.lists.Status(); len(st) != 1 || st[0].Name != "crowdsec" {
		t.Errorf("status after removal: %+v", st)
	}
}
