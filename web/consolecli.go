// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"

	"github.com/abundo/portitor/models"
)

// Configuration from the console: portitor-config (or portitor-web) run
// with an "api", "set" or "commit" command answers one API request
// in-process, as consoleUser, a global admin. Whoever can run it can read
// the database already (root, or its service user), so it asks for no
// password. The user rides in the request's context, which a request
// from the network never carries; every check of the API applies, read-
// only managed virtual firewalls and break-glass included.

type consoleUserKey struct{}

// consoleUser is who console requests act as.
var consoleUser = &models.User{Username: "console", Role: models.RoleAdmin}

// ConsoleRequest answers method path with body (JSON, or nil) as the
// console user, and returns the status and answer.
func (s *Server) ConsoleRequest(ctx context.Context, method, path string, body []byte) (int, []byte) {
	if err := s.ensureDefaultInstance(); err != nil {
		return http.StatusInternalServerError, []byte(`{"error":"` + err.Error() + `"}`)
	}
	req := httptest.NewRequestWithContext(context.WithValue(ctx, consoleUserKey{}, consoleUser), method, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.Echo().ServeHTTP(rec, req)
	out, _ := io.ReadAll(rec.Result().Body)
	return rec.Code, out
}
