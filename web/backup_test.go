// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/abundo/portitor/internal/datastore"
)

const testPassphrase = "a long enough passphrase"

func (env *testEnv) backup() []byte {
	env.t.Helper()
	rec := env.do("POST", "/api/backup", map[string]string{"passphrase": testPassphrase})
	if rec.Code != http.StatusOK {
		env.t.Fatalf("backup: %d %s", rec.Code, rec.Body)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, ".tar.age") {
		env.t.Errorf("Content-Disposition %q", cd)
	}
	return rec.Body.Bytes()
}

func objectNames(t *testing.T, env *testEnv) []string {
	t.Helper()
	var names []string
	for _, o := range env.view().AddressObjects {
		names = append(names, o.Name)
	}
	slices.Sort(names)
	return names
}

func TestBackupRestore(t *testing.T) {
	env := newEnv(t)
	if err := env.srv.ensureDefaultInstance(); err != nil {
		t.Fatal(err)
	}
	env.post("host", map[string]any{"name": "nas", "addresses": []string{"192.168.1.10"}})
	env.post("instance=main/rule", map[string]any{"chain": "input", "action": "accept", "enabled": true})
	env.do("PUT", "/api/settings", map[string]any{"wg_endpoint_host": "old.example.com"})
	env.do("PUT", "/api/firewalls/1", map[string]any{"name": "firewall", "agent_url": "https://10.0.0.1:8443"})
	// Role memberships come back; one of a user deleted since the backup
	// goes with that user.
	if err := CreateUser(env.srv, "stays", "another long password"); err != nil {
		t.Fatal(err)
	}
	if err := CreateUser(env.srv, "gone", "another long password"); err != nil {
		t.Fatal(err)
	}
	env.create("/api/roles", map[string]any{"name": "ops", "members": []map[string]any{
		{"user_id": env.userNamed("stays").ID, "level": "viewer"}, {"user_id": env.userNamed("gone").ID, "level": "viewer"}}})
	data := env.backup()

	// The download is age encrypted with the passphrase.
	id, _ := age.NewScryptIdentity(testPassphrase)
	r, err := age.Decrypt(bytes.NewReader(data), id)
	if err != nil {
		t.Fatal(err)
	}
	plain, _ := io.ReadAll(r)
	if !isTar(plain) {
		t.Fatal("decrypted backup is not an archive")
	}

	// Change things after the backup.
	env.post("host", map[string]any{"name": "printer", "addresses": []string{"192.168.1.20"}})
	printerID := env.rowID("address_objects", "printer")
	ruleAfter := env.post("instance=main/rule", map[string]any{"chain": "input", "action": "accept", "enabled": true})
	env.do("PUT", "/api/settings", map[string]any{"wg_endpoint_host": "new.example.com"})
	env.do("PUT", "/api/firewalls/1", map[string]any{"name": "firewall", "agent_url": "https://10.0.0.2:8443", "agent_token": "new-token"})
	_ = env.srv.rec.SetLastCommit(7)
	_ = env.srv.rec.SetGeneration(1, 9)
	if err := env.srv.rec.DeleteUser(env.userNamed("gone").ID); err != nil {
		t.Fatal(err)
	}
	if err := CreateUser(env.srv, "later", "another long password"); err != nil {
		t.Fatal(err)
	}

	for _, body := range []map[string]any{
		{"data": data, "passphrase": "wrong passphrase!"},
		{"data": []byte("garbage"), "passphrase": testPassphrase},
		{"data": append([]byte(nil), plain[:len(plain)/2]...)},
	} {
		if rec := env.do("POST", "/api/backup/restore", body); rec.Code != http.StatusBadRequest {
			t.Errorf("restore %.20q: %d %s", body["data"], rec.Code, rec.Body)
		}
	}
	if got := objectNames(t, env); strings.Join(got, ",") != "nas,printer" {
		t.Fatalf("a failed restore changed the database: %v", got)
	}

	if rec := env.do("POST", "/api/backup/restore", map[string]any{"data": data, "passphrase": testPassphrase}); rec.Code != http.StatusOK {
		t.Fatalf("restore: %d %s", rec.Code, rec.Body)
	}
	if got := objectNames(t, env); strings.Join(got, ",") != "nas" {
		t.Errorf("objects after restore: %v", got)
	}
	st, _ := env.srv.settings()
	if st.WgEndpointHost != "old.example.com" {
		t.Errorf("settings not restored: %q", st.WgEndpointHost)
	}
	// This installation's agent connection, generation, commit number and
	// users stay.
	fw := firstFirewall(t, env)
	if fw.AgentURL != "https://10.0.0.2:8443" || fw.AgentToken != "new-token" || fw.Generation != 9 || st.LastCommit != 7 {
		t.Errorf("agent settings: %q %q %d %d", fw.AgentURL, fw.AgentToken, fw.Generation, st.LastCommit)
	}
	// The backup is the configuration, users and roles with it: a user made
	// since is gone, one deleted since is back with their memberships.
	if _, err := env.srv.rec.UserNamed("later"); err == nil {
		t.Error("a user made after the backup survived the restore")
	}
	var members []string
	ms, _ := env.srv.rec.RoleMembers()
	for _, m := range ms {
		members = append(members, env.userID(m.UserID).Username)
	}
	slices.Sort(members)
	if strings.Join(members, ",") != "gone,stays" {
		t.Errorf("role members after restore: %v", members)
	}
	if rec := env.do("GET", "/api/me", nil); rec.Code != http.StatusOK {
		t.Errorf("session after restore: %d", rec.Code)
	}
	// A new row does not reuse the id of a row the restore removed.
	env.post("host", map[string]any{"name": "scanner", "addresses": []string{"192.168.1.30"}})
	next := env.rowID("address_objects", "scanner")
	if next <= printerID {
		t.Errorf("id %d reused (sequence was %d)", next, printerID)
	}
	// Nor a rule (its id is its connections' mark) one made since.
	if rule := env.post("instance=main/rule", map[string]any{"chain": "input", "action": "drop", "enabled": true}); rule <= ruleAfter || len(rule) < len(ruleAfter) {
		t.Errorf("rule id %s after the restore, %s was given before it", rule, ruleAfter)
	}

	// The unencrypted archive restores too.
	if rec := env.do("POST", "/api/backup/restore", map[string]any{"data": plain}); rec.Code != http.StatusOK {
		t.Fatalf("plain restore: %d %s", rec.Code, rec.Body)
	}
	if got := objectNames(t, env); strings.Join(got, ",") != "nas" {
		t.Errorf("objects after plain restore: %v", got)
	}
}

func TestBackupPassphrase(t *testing.T) {
	env := newEnv(t)
	if rec := env.do("POST", "/api/backup", map[string]string{"passphrase": "short"}); rec.Code != http.StatusBadRequest {
		t.Errorf("short passphrase: %d", rec.Code)
	}
}

// A copy without the global lists (global.json) is refused, and changes
// nothing.
func TestRestoreRefusesACopyWithoutGlobals(t *testing.T) {
	env := newEnv(t)
	tr, _ := env.srv.tree()
	cand, _ := tr.store.Candidate(context.Background())
	data, err := cand.JSON(datastore.JSONOptions{Secrets: true})
	if err != nil {
		t.Fatal(err)
	}
	env.post("host", map[string]any{"name": "nas", "addresses": []string{"192.168.1.10"}})
	err = env.srv.takeSnapshot(context.Background(), map[string][]byte{"candidate.json": data, "entry-ids.json": []byte("{}")}, nil, true)
	var re restoreError
	if !errors.As(err, &re) {
		t.Fatalf("a copy without global.json: %v", err)
	}
	if got := objectNames(t, env); strings.Join(got, ",") != "nas" {
		t.Errorf("the refused copy changed the candidate: %v", got)
	}
}
