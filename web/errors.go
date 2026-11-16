// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"errors"
	"net/http"

	"github.com/labstack/echo/v5"

	"github.com/abundo/portitor/internal/records"
)

// model is a pointer to a struct embedding models.Base.
type model[T any] interface {
	*T
	GetID() uint
	SetID(uint)
}

// badRequest is a validation failure shown to the user as-is.
type badRequest struct{ msg string }

func (e *badRequest) Error() string { return e.msg }

func bad(msg string) error { return &badRequest{msg} }

// errForbidden refuses a change the user may not make.
var errForbidden = errors.New("forbidden")

// writeError maps a write's refusals to 4xx answers.
func writeError(c *echo.Context, err error) error {
	var br *badRequest
	if errors.As(err, &br) {
		return errJSON(c, http.StatusBadRequest, br.msg)
	}
	if errors.Is(err, errForbidden) {
		return errJSON(c, http.StatusForbidden, "you can't change this")
	}
	if errors.Is(err, records.ErrExists) {
		return errJSON(c, http.StatusConflict, "an entry with that name/value already exists")
	}
	return err
}

func errJSON(c *echo.Context, status int, msg string) error {
	return c.JSON(status, map[string]any{"error": msg})
}
