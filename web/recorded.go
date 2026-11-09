// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"maps"
	"net/http/httptest"

	"github.com/labstack/echo/v5"
)

// copyRecorded answers what the handler answered.
func copyRecorded(c *echo.Context, rec *httptest.ResponseRecorder, warnings []error) error {
	h := c.Response().Header()
	maps.Copy(h, rec.Header())
	if len(warnings) > 0 {
		h.Set("X-Portitor-Warnings", joinErrors(warnings))
	}
	c.Response().WriteHeader(rec.Code)
	if rec.Body.Len() == 0 {
		return nil // a 204 has none
	}
	_, err := c.Response().Write(rec.Body.Bytes())
	return err
}

func joinErrors(errs []error) string {
	out := ""
	for i, e := range errs {
		if i > 0 {
			out += "; "
		}
		out += e.Error()
	}
	return out
}
