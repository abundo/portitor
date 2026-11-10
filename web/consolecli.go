// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	"github.com/abundo/portitor/internal/schema"
	"github.com/abundo/portitor/models"
)

// Configuration from the console: portitor-config (or portitor-web) run
// with an "api", "set" or "commit" command answers one API request
// in-process, as consoleUser, a global admin. Whoever can run it can read
// the database already (root, or its service user), so it asks for no
// password. The user rides in the request's context, which a request
// from the network never carries; every check of the API applies.

type consoleUserKey struct{}

// consoleUser is who console requests act as.
var consoleUser = &models.User{Username: "console", Role: models.RoleAdmin}

// ConsoleRequest answers method path with body (JSON, or nil) as the
// console user, and returns the status and answer.
func (s *Server) ConsoleRequest(ctx context.Context, method, path string, body []byte) (int, []byte) {
	if err := s.ensureDefaultInstance(); err != nil {
		return http.StatusInternalServerError, []byte(`{"error":"` + err.Error() + `"}`)
	}
	// Whether this host is a replica (read-only), from its agent.
	if s.cfg.Local {
		s.checkRole(ctx)
	}
	return s.requestAs(ctx, consoleUser, method, path, body)
}

// requestAs answers an API request in-process as the user u: the CLI's
// requests, with every check the API makes for u.
func (s *Server) requestAs(ctx context.Context, u *models.User, method, path string, body []byte) (int, []byte) {
	rec := s.recordAs(ctx, u, method, path, body)
	out, _ := io.ReadAll(rec.Result().Body)
	return rec.Code, out
}

// recordAs is requestAs's whole answer, its headers too.
func (s *Server) recordAs(ctx context.Context, u *models.User, method, path string, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequestWithContext(context.WithValue(ctx, consoleUserKey{}, u), method, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.Echo().ServeHTTP(rec, req)
	return rec
}

// ConsoleSetPath is the configuration path (for /api/config/candidate) of
// the entry the console's set names: resource a list of the virtual
// firewall vf ("" the host) or a shared one, by its YANG name, its table
// or its plural ("interfaces", "interface", "objects", "host"); name its
// key, or its keys joined by ",". leafLists names its leaf-lists, whose
// values set takes comma-separated.
func (s *Server) ConsoleSetPath(ctx context.Context, vf, resource, name string) (path string, leafLists map[string]bool, err error) {
	t, err := s.tree()
	if err != nil {
		return "", nil, err
	}
	cand, err := t.store.Candidate(ctx)
	if err != nil {
		return "", nil, err
	}
	want := strings.ReplaceAll(strings.ToLower(resource), "_", "-")
	matches := func(l *schema.Node) bool {
		table := strings.ReplaceAll(t.mapping.TableOf(l), "_", "-")
		return l.Kind == schema.List && (l.Name == want || l.Name+"s" == want || table == want ||
			(want == "objects" && l.Name == "host"))
	}
	var list *schema.Node
	var prefix string
	inst := t.schema.Child("instance")
	for _, l := range inst.Children {
		if matches(l) {
			list = l
		}
	}
	if list != nil {
		if vf == "" {
			for _, in := range cand.Root.Lists["instance"] {
				if in.Leaf("is-default") == "true" {
					vf = in.Leaf("name")
				}
			}
		}
		if cand.Root.Entry("instance", []string{vf}) == nil {
			return "", nil, fmt.Errorf("no virtual firewall %q", vf)
		}
		prefix = "instance=" + url.PathEscape(vf) + "/"
	} else {
		for _, l := range t.schema.Children {
			if matches(l) {
				list = l
			}
		}
	}
	if list == nil {
		return "", nil, fmt.Errorf("no list %q in the configuration", resource)
	}
	keys := strings.Split(name, ",")
	if len(keys) != len(list.Keys) {
		return "", nil, fmt.Errorf("%s is keyed by %s", list.Name, strings.Join(list.Keys, ", "))
	}
	for i, k := range keys {
		keys[i] = url.PathEscape(k)
	}
	leafLists = map[string]bool{}
	for _, c := range list.Children {
		if c.Kind == schema.LeafList {
			leafLists[c.Name] = true
		}
	}
	return prefix + list.Name + "=" + strings.Join(keys, ","), leafLists, nil
}
