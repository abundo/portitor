// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"bytes"
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/abundo/portitor/internal/cli"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/schema"
)

// TestActionHandlers: each action of the YANG modules has its handler,
// each handler its action, and the GUI's own actions are not in YANG.
func TestActionHandlers(t *testing.T) {
	root := schema.MustLoad()
	inYANG := map[string]bool{}
	root.Walk(func(n *schema.Node) {
		for _, a := range n.Actions {
			key := n.Path() + " " + a.Name
			inYANG[key] = true
			if actionHandlers[key] == nil {
				t.Errorf("%s: no handler (registerAction)", key)
			}
			if a.Kind == schema.ActionView && len(a.Input.Children) > 0 {
				t.Errorf("%s: a view takes no input (it is a GET)", key)
			}
		}
	})
	for key := range actionHandlers {
		if !inYANG[key] {
			t.Errorf("%s: a handler without its action in YANG", key)
		}
	}
	for key := range guiActions {
		if inYANG[key] {
			t.Errorf("%s: a GUI action that is in YANG", key)
		}
	}
	kt := root.Find("/instance/certificate/key-type").Type
	if !slices.Equal(kt.Enums, fwconfig.CertKeyTypes) {
		t.Errorf("cert-key-type %v, fwconfig.CertKeyTypes %v", kt.Enums, fwconfig.CertKeyTypes)
	}
}

// TestActionInput: the API checks an action's input by its schema.
func TestActionInput(t *testing.T) {
	env := newEnv(t)
	env.host("main")
	for _, body := range []map[string]any{
		{"domains": []string{"a.example.com"}, "days": 0},
		{"domains": []string{"a.example.com"}, "key-type": "dsa"},
		{"domains": []string{"a.example.com"}, "bogus": true},
		{"domains": []string{"a.example.com"}, "common-name": strings.Repeat("x", 65)},
	} {
		if rec := env.do("POST", "/api/config/candidate/instance=main/certificate=c1?action=generate", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%v: %d %s", body, rec.Code, rec.Body)
		}
	}
	// The defaults fill in what is left out (key type, days).
	if rec := env.do("POST", "/api/config/candidate/instance=main/certificate=c1?action=generate", map[string]any{"domains": []string{"a.example.com"}}); rec.Code != http.StatusOK {
		t.Fatalf("generate: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("POST", "/api/config/candidate/ip-list=nope?action=schedule", map[string]any{}); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "mandatory") {
		t.Errorf("schedule without one: %d %s", rec.Code, rec.Body)
	}
}

// TestCLITools: the CLI's tools runs the actions: a change in candidate
// mode alone, a view, typed input, and its output as text.
func TestCLITools(t *testing.T) {
	env, _ := consoleEnv(t, "")
	ctx := context.Background()
	cenv, err := env.srv.ConsoleCLI(ctx)
	if err != nil {
		t.Fatal(err)
	}
	host := env.instanceRow("").Name
	wg := "instance " + host + " interface wg9"
	out := cliScript(t, cenv, `enter candidate
`+wg+` kind wireguard
`+wg+` addresses [ 10.98.0.1/24 ]
tools `+wg+` wg-rekey
tools `+wg+` wg-next
`)
	if !strings.Contains(out, "wg-public-key ") || !strings.Contains(out, "addresses [ 10.98.0.2/32 ]") {
		t.Errorf("tools: %s", out)
	}
	cand, _ := cenv.Store.Candidate(ctx)
	if cand.Root.Entry("instance", []string{host}).Entry("interface", []string{"wg9"}).Leaves["wg-private-key"] == "" {
		t.Error("wg-rekey made no key")
	}

	cliScript(t, cenv, "enter candidate\ntools instance "+host+" certificate c2 generate domains [ c2.example.com ] days 30 key-type ec384\n")
	cand, _ = cenv.Store.Candidate(ctx)
	if c := cand.Root.Entry("instance", []string{host}).Entry("certificate", []string{"c2"}); c == nil || c.Leaves["source"] != fwconfig.CertSourceImport {
		t.Errorf("generate made %v", c)
	}

	for script, want := range map[string]string{
		"tools " + wg + " wg-rekey\n":                                                   "enter candidate first",
		"enter candidate\ntools " + wg + " bogus\n":                                     "no action",
		"enter candidate\ntools instance " + host + " certificate c3 generate days 0\n": "days",
		"enter candidate\ntools " + wg + " move-to\n":                                   "mandatory",
	} {
		var b bytes.Buffer
		if err := cli.RunScript(ctx, cenv, strings.NewReader(script), &b); err == nil || !strings.Contains(err.Error()+b.String(), want) {
			t.Errorf("%q: %v %s, want %q", script, err, b.String(), want)
		}
	}
}
