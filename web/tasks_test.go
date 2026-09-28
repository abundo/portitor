// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/abundo/portitor/internal/agentclient"
	"github.com/abundo/portitor/internal/builder"
	"github.com/abundo/portitor/models"
)

func TestIPListsAndTasks(t *testing.T) {
	env := newEnv(t)
	inst := env.create("/api/instances", map[string]any{"name": "main"})
	env.create("/api/interfaces", map[string]any{"instance_id": inst, "name": "wan", "ipv4_mode": "dhcp", "enabled": true})

	const key = "bouncer-key-0123456789"
	cs := map[string]any{"name": "crowdsec", "source": "crowdsec", "url": "http://127.0.0.1:8080", "api_key": key}
	for field, v := range map[string]any{
		"name":    "Crowd Sec",
		"source":  "file",
		"url":     "ftp://example.com/list",
		"api_key": "",
	} {
		c := map[string]any{}
		for k, x := range cs {
			c[k] = x
		}
		c[field] = v
		if rec := env.do("POST", "/api/ip-lists", c); rec.Code != http.StatusBadRequest {
			t.Errorf("bad %s accepted: %d %s", field, rec.Code, rec.Body)
		}
	}
	rec := env.do("POST", "/api/ip-lists", cs)
	if rec.Code != http.StatusCreated || strings.Contains(rec.Body.String(), key) || !strings.Contains(rec.Body.String(), `"has_api_key":true`) {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var created models.IpList
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	csID := itoa(created.ID)
	drop := env.create("/api/ip-lists", map[string]any{"name": "drop", "url": "https://example.com/drop.txt", "username": "u", "password": "p"})

	// Rules take IP lists; NAT rules and other address fields do not.
	rule := env.create("/api/rules", map[string]any{"instance_id": inst, "chain": "input", "in_interfaces": []string{"wan"},
		"src_addrs": []string{"@crowdsec", "@drop", "192.0.2.0/24"}, "action": "drop", "enabled": true})
	if rec := env.do("POST", "/api/rules", map[string]any{"instance_id": inst, "chain": "input", "src_addrs": []string{"@nope"}, "action": "drop"}); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `no IP list named \"nope\"`) {
		t.Errorf("unknown list: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("POST", "/api/nat", map[string]any{"instance_id": inst, "kind": "masquerade", "out_interfaces": []string{"wan"}, "src_addrs": []string{"@drop"}}); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "only be used in firewall rules") {
		t.Errorf("list in NAT: %d %s", rec.Code, rec.Body)
	}

	// Tasks.
	for _, bad := range []map[string]any{
		{"name": "t", "schedule": "every hour", "kind": "iplist", "ip_list_id": drop},
		{"name": "t", "schedule": "@hourly", "kind": "iplist"},
		{"name": "t", "schedule": "@hourly", "kind": "command", "command": " "},
		{"name": "t", "schedule": "@hourly", "kind": "command", "command": "ls", "timeout": 100000},
		{"name": "t", "schedule": "@hourly", "kind": "reboot"},
	} {
		if rec := env.do("POST", "/api/tasks", bad); rec.Code != http.StatusBadRequest {
			t.Errorf("bad task %v accepted: %d %s", bad, rec.Code, rec.Body)
		}
	}
	env.create("/api/tasks", map[string]any{"name": "crowdsec", "schedule": " */5  * * * * ", "kind": "iplist", "ip_list_id": created.ID, "command": "ignored", "enabled": true})
	backup := env.create("/api/tasks", map[string]any{"name": "backup", "schedule": "30 3 * * *", "kind": "command", "command": "tar czf /tmp/x.tgz /etc", "timeout": 60, "enabled": true})
	env.create("/api/tasks", map[string]any{"name": "off", "schedule": "@daily", "kind": "command", "command": "true", "enabled": false})

	// Renaming a list rewrites the rules; deleting one in use is refused.
	if rec := env.do("PUT", "/api/ip-lists/"+csID, map[string]any{"name": "cs"}); rec.Code != http.StatusOK {
		t.Fatalf("rename: %d %s", rec.Code, rec.Body)
	}
	var r models.Rule
	env.srv.db.First(&r, rule)
	if strings.Join(r.SrcAddrs, " ") != "@cs @drop 192.0.2.0/24" {
		t.Errorf("rule after rename: %v", r.SrcAddrs)
	}
	rec = env.do("DELETE", "/api/ip-lists/"+csID, nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "input rule 1 in main") || !strings.Contains(rec.Body.String(), "task crowdsec") {
		t.Errorf("delete in use: %d %s", rec.Code, rec.Body)
	}

	doc, err := builder.Build(env.srv.db, 1)
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
	env.srv.newAgent = func(*models.Settings) (agentAPI, error) { return fake, nil }
	if rec := env.do("POST", "/api/tasks/"+itoa(backup)+"/run", map[string]any{}); rec.Code != http.StatusAccepted || fake.ran != "backup" {
		t.Errorf("run: %d %s %q", rec.Code, rec.Body, fake.ran)
	}
	if rec := env.do("POST", "/api/ip-lists/"+itoa(drop)+"/refresh", map[string]any{}); rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "not deployed") {
		t.Errorf("refresh error: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("POST", "/api/tasks/999/run", map[string]any{}); rec.Code != http.StatusNotFound {
		t.Errorf("unknown task: %d", rec.Code)
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
