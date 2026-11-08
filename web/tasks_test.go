// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"strings"
	"testing"

	"github.com/abundo/portitor/internal/agentclient"
	"github.com/abundo/portitor/internal/builder"
	"github.com/abundo/portitor/models"
)

func TestIPListsAndTasks(t *testing.T) {
	env := newEnv(t)
	env.host("main")
	env.put("instance=main/interface=wan", map[string]any{"kind": "physical", "ipv4-mode": "dhcp", "enabled": true})
	fw := firstFirewall(t, env).Name

	const key = "bouncer-key-0123456789"
	cs := map[string]any{"source": "crowdsec", "url": "http://127.0.0.1:8080", "api-key": key}
	for field, v := range map[string]any{
		"source":  "file",
		"url":     "ftp://example.com/list",
		"api-key": nil,
	} {
		c := maps.Clone(cs)
		c[field] = v
		if rec := env.cfg("PUT", "ip-list=crowdsec", c); rec.Code != http.StatusBadRequest {
			t.Errorf("bad %s accepted: %d %s", field, rec.Code, rec.Body)
		}
	}
	if rec := env.cfg("PUT", "ip-list=Crowd%0ASec", cs); rec.Code != http.StatusBadRequest {
		t.Errorf("bad name accepted: %d %s", rec.Code, rec.Body)
	}
	// A key or password over http:// only to a loopback address.
	for _, c := range []map[string]any{
		{"source": "crowdsec", "url": "http://192.0.2.10:8080", "api-key": key},
		{"url": "http://lists.example/drop.txt", "username": "u", "password": "p"},
	} {
		if rec := env.cfg("PUT", "ip-list=remote", c); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "unencrypted") {
			t.Errorf("credentials over http accepted: %v: %d %s", c["url"], rec.Code, rec.Body)
		}
	}
	for i, c := range []map[string]any{
		{"source": "crowdsec", "url": "https://192.0.2.10:8080", "api-key": key},
		{"source": "crowdsec", "url": "http://localhost:8080", "api-key": key},
		{"source": "crowdsec", "url": "http://[::1]:8080", "api-key": key},
		{"url": "http://lists.example/drop.txt"}, // no credentials
	} {
		path := fmt.Sprintf("ip-list=ok%d", i)
		env.put(path, c)
		env.mustCfg("DELETE", path, nil)
	}

	// A country list: codes upper-cased and deduplicated, no URL kept.
	for _, c := range []map[string]any{
		{"source": "country"},
		{"source": "country", "countries": []string{"Sweden"}},
	} {
		if rec := env.cfg("PUT", "ip-list=geo", c); rec.Code != http.StatusBadRequest {
			t.Errorf("bad country list %v accepted: %d %s", c, rec.Code, rec.Body)
		}
	}
	env.put("ip-list=geo", map[string]any{"source": "country", "url": "https://example.com/x", "countries": []string{"se", " NO", "SE"}})
	if g := env.node("ip-list=geo"); g.Leaf("url") != "" || strings.Join(g.LeafLists["countries"], " ") != "SE NO" {
		t.Errorf("country list stored as %q %v", g.Leaf("url"), g.LeafLists["countries"])
	}
	env.mustCfg("DELETE", "ip-list=geo", nil)

	env.put("ip-list=crowdsec", cs)
	if rec := env.do("GET", "/api/config/candidate/ip-list", nil); strings.Contains(rec.Body.String(), key) {
		t.Errorf("the key read back: %s", rec.Body)
	}
	env.put("ip-list=drop", map[string]any{"url": "https://example.com/drop.txt", "username": "u", "password": "p"})

	// Rules take IP lists; NAT rules and other address fields don't.
	rule := env.post("instance=main/rule", map[string]any{"chain": "input", "in-interfaces": []string{"wan"}, "src-addrs": []string{"@crowdsec", "@drop", "192.0.2.0/24"}, "action": "drop"})
	if rec := env.cfg("POST", "instance=main/rule", map[string]any{"chain": "input", "src-addrs": []string{"@nope"}, "action": "drop"}); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "no IP list nope") {
		t.Errorf("unknown list: %d %s", rec.Code, rec.Body)
	}
	if rec := env.cfg("POST", "instance=main/nat-rule", map[string]any{"kind": "masquerade", "out-interfaces": []string{"wan"}, "src-addrs": []string{"@drop"}}); rec.Code != http.StatusBadRequest {
		t.Errorf("list in NAT: %d %s", rec.Code, rec.Body)
	}

	// Tasks.
	for _, bad := range []map[string]any{
		{"schedule": "every hour", "kind": "iplist", "ip-list": "drop"},
		{"schedule": "@hourly", "kind": "iplist"},
		{"schedule": "@hourly", "kind": "command", "command": " "},
		{"schedule": "@hourly", "kind": "command", "command": "ls", "timeout": 100000},
		{"schedule": "@hourly", "kind": "reboot"},
	} {
		bad["firewall"] = fw
		if rec := env.cfg("PUT", "task=t", bad); rec.Code != http.StatusBadRequest {
			t.Errorf("bad task %v accepted: %d %s", bad, rec.Code, rec.Body)
		}
	}
	env.put("task=crowdsec", map[string]any{"schedule": " */5  * * * * ", "kind": "iplist", "ip-list": "crowdsec", "command": "ignored", "enabled": true, "firewall": fw})
	env.put("task=backup", map[string]any{"schedule": "30 3 * * *", "kind": "command", "command": "tar czf /tmp/x.tgz /etc", "timeout": 60, "enabled": true, "firewall": fw})
	env.put("task=off", map[string]any{"schedule": "@daily", "kind": "command", "command": "true", "enabled": false, "firewall": fw})

	// Renaming a list rewrites the rules and tasks; deleting one in use is
	// refused.
	env.mustCfg("POST", "ip-list=crowdsec?action=rename", map[string]any{"keys": []string{"cs"}})
	if got := env.node("instance=main/rule=" + rule).LeafLists["src-addrs"]; strings.Join(got, " ") != "@cs @drop 192.0.2.0/24" {
		t.Errorf("rule after rename: %v", got)
	}
	if rec := env.cfg("DELETE", "ip-list=cs", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("delete in use: %d %s", rec.Code, rec.Body)
	}

	doc, err := builder.Build(env.input(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.IPLists) != 2 || doc.IPLists[0].Name != "cs" || doc.IPLists[0].APIKey != key || doc.IPLists[1].Password != "p" {
		t.Errorf("lists: %+v", doc.IPLists)
	}
	if len(doc.Tasks) != 2 || doc.Tasks[0].Name != "backup" || doc.Tasks[1].IPList != "cs" || doc.Tasks[1].Schedule != "*/5 * * * *" || doc.Tasks[1].Command != "" {
		t.Errorf("tasks: %+v", doc.Tasks)
	}
	if got := doc.Instances[0].Rules[1].SrcAddrs; strings.Join(got, " ") != "@cs @drop 192.0.2.0/24" {
		t.Errorf("rule addresses: %v", got)
	}
	red := redactDoc(*doc)
	if red.IPLists[0].APIKey != "<redacted>" || red.IPLists[1].Password != "<redacted>" || doc.IPLists[0].APIKey != key {
		t.Errorf("redaction: %+v / %+v", red.IPLists, doc.IPLists)
	}

	// Run now goes to the agent by name.
	fake := &runAgent{}
	env.srv.newAgent = func(*models.Firewall) (agentAPI, error) { return fake, nil }
	if rec := env.do("POST", "/api/config/candidate/task=backup?action=run", map[string]any{}); rec.Code != http.StatusAccepted || fake.ran != "backup" {
		t.Errorf("run: %d %s %q", rec.Code, rec.Body, fake.ran)
	}
	if rec := env.do("POST", "/api/config/candidate/ip-list=drop?action=refresh", map[string]any{}); rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "not deployed") {
		t.Errorf("refresh error: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("POST", "/api/config/candidate/task=nope?action=run", map[string]any{}); rec.Code != http.StatusNotFound {
		t.Errorf("unknown task: %d", rec.Code)
	}
	// A viewer runs neither.
	env.create("/api/users", map[string]string{"username": "vic", "password": "a long password", "role": "viewer"})
	env.login("vic", "a long password")
	for _, p := range []string{"ip-list=drop?action=refresh", "task=backup?action=run"} {
		if rec := env.do("POST", "/api/config/candidate/"+p, map[string]any{}); rec.Code != http.StatusForbidden {
			t.Errorf("a viewer's %s: %d %s", p, rec.Code, rec.Body)
		}
	}
}

// runAgent records RunTask and fails RefreshIPList.
type runAgent struct {
	agentAPI
	ran string
}

func (f *runAgent) RunTask(_ context.Context, name string) error {
	f.ran = name
	return nil
}

func (f *runAgent) RefreshIPList(context.Context, string) error {
	return &agentclient.Error{Status: http.StatusNotFound, Message: "not deployed"}
}

func TestSchedulePreview(t *testing.T) {
	env := newEnv(t)
	var got struct {
		Next  []string `json:"next"`
		Error string   `json:"error"`
	}
	rec := env.do("GET", "/api/schedule/preview?schedule=%40hourly", nil)
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if rec.Code != http.StatusOK || len(got.Next) != 5 || !strings.Contains(got.Next[0], ":00:00") {
		t.Errorf("hourly: %d %s", rec.Code, rec.Body)
	}
	got.Next = nil
	rec = env.do("GET", "/api/schedule/preview?schedule=61+*+*+*+*", nil)
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if !strings.Contains(got.Error, "minute: 61 is outside 0-59") || len(got.Next) != 0 {
		t.Errorf("bad schedule: %s", rec.Body)
	}
}

// A new list with a refresh schedule gets a task on each firewall but an
// HA secondary, named after the list (and the firewall, with several).
func TestIPListRefreshTasks(t *testing.T) {
	env := newEnv(t)
	tasks := func() []string {
		var out []string
		for _, t := range env.node("").Lists["task"] {
			out = append(out, t.Leaf("name"))
		}
		return out
	}
	env.put("ip-list=drop", map[string]any{"url": "https://example.com/drop.txt"})
	if rec := env.cfg("POST", "ip-list=drop?action=schedule", map[string]any{"schedule": "61 * * * *"}); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "refresh schedule") {
		t.Errorf("bad schedule: %d %s", rec.Code, rec.Body)
	}
	env.mustCfg("POST", "ip-list=drop?action=schedule", map[string]any{"schedule": "17  3 * * *"})
	if task := env.node("task=drop"); task == nil || task.Leaf("schedule") != "17 3 * * *" || !on(task, "enabled") || task.Leaf("kind") != "iplist" || task.Leaf("ip-list") != "drop" {
		t.Fatalf("tasks: %v", tasks())
	}

	env.create("/api/firewalls", map[string]any{"name": "branch", "agent_url": "https://192.0.2.2:8443", "agent_token": "secret"})
	env.put("ip-list=fh", map[string]any{"url": "https://example.com/fh.txt"})
	env.mustCfg("POST", "ip-list=fh?action=schedule", map[string]any{"schedule": "@daily"})
	if got := strings.Join(tasks(), " "); !strings.Contains(got, "fh-branch") || len(tasks()) != 3 {
		t.Errorf("tasks: %s", got)
	}
}
