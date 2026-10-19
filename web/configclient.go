// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/abundo/portitor/internal/agentclient"
	"github.com/abundo/portitor/models"
)

// configAPI is a firewall's portitor-config, as its manager calls it
// (managerapi.go is the other side).
type configAPI interface {
	State(ctx context.Context) (*ManagedState, error)
	Bundle(ctx context.Context, name string) (*Bundle, error)
	// Push puts a virtual firewall in place there, managed by manager.
	Push(ctx context.Context, name, manager string, overwrite bool, b *Bundle) ([]string, error)
	Delete(ctx context.Context, name, manager string) error
	// PushUsers sends the manager's users; it returns those left alone.
	PushUsers(ctx context.Context, u *ManagedUsers) ([]string, error)
	Commit(ctx context.Context, manager string, confirm int) (*commitResult, error)
	Confirm(ctx context.Context) error
	Rollback(ctx context.Context) error
}

type configClient struct{ c *agentclient.Client }

func newConfigClient(f *models.Firewall) (configAPI, error) {
	c, err := agentclient.New(f.ConfigURL, f.ConfigToken, f.ConfigFingerprint)
	if err != nil {
		return nil, err
	}
	return &configClient{c}, nil
}

// do calls the manager API, its errors named as portitor-config's.
func (c *configClient) do(ctx context.Context, method, path string, body, out any) error {
	err := c.c.Do(ctx, method, "/manager/v1"+path, body, out)
	var ae *agentclient.Error
	switch {
	case errors.As(err, &ae):
		return &configError{status: ae.Status, msg: ae.Message, problems: ae.Problems}
	case err != nil:
		return fmt.Errorf("portitor-config unreachable: %w", errors.Unwrap(err))
	}
	return nil
}

// configError is portitor-config's answer to a refused call.
type configError struct {
	status   int
	msg      string
	problems []string
}

func (e *configError) Error() string {
	if len(e.problems) > 0 {
		return "portitor-config: " + e.msg + ": " + strings.Join(e.problems, "; ")
	}
	return "portitor-config: " + e.msg
}

func (c *configClient) State(ctx context.Context) (*ManagedState, error) {
	var st ManagedState
	return &st, c.do(ctx, http.MethodGet, "/state", nil, &st)
}

func (c *configClient) Bundle(ctx context.Context, name string) (*Bundle, error) {
	var b Bundle
	return &b, c.do(ctx, http.MethodGet, "/instances/"+url.PathEscape(name)+"/bundle", nil, &b)
}

func (c *configClient) Push(ctx context.Context, name, manager string, overwrite bool, b *Bundle) ([]string, error) {
	var out struct {
		Problems []string `json:"problems"`
	}
	err := c.do(ctx, http.MethodPut, "/instances/"+url.PathEscape(name), map[string]any{"manager": manager, "overwrite": overwrite, "bundle": b}, &out)
	return out.Problems, err
}

func (c *configClient) Delete(ctx context.Context, name, manager string) error {
	return c.do(ctx, http.MethodDelete, "/instances/"+url.PathEscape(name)+"?manager="+url.QueryEscape(manager), nil, nil)
}

func (c *configClient) PushUsers(ctx context.Context, u *ManagedUsers) ([]string, error) {
	var out struct {
		Skipped []string `json:"skipped"`
	}
	return out.Skipped, c.do(ctx, http.MethodPut, "/users", u, &out)
}

func (c *configClient) Commit(ctx context.Context, manager string, confirm int) (*commitResult, error) {
	var res commitResult
	return &res, c.do(ctx, http.MethodPost, "/commit", map[string]any{"manager": manager, "confirm_timeout": confirm}, &res)
}

func (c *configClient) Confirm(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/confirm", map[string]any{}, nil)
}

func (c *configClient) Rollback(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/rollback", map[string]any{}, nil)
}

var nonName = regexp.MustCompile(`[^a-z0-9.-]+`)

// managerName is how this portitor-web names itself to the
// portitor-configs it manages.
func (s *Server) managerName() string {
	n := s.cfg.ManagerName
	if n == "" {
		n, _ = os.Hostname()
	}
	n = strings.Trim(nonName.ReplaceAllString(strings.ToLower(n), "-"), "-.")
	if !managerNameRe.MatchString(n) {
		return "portitor"
	}
	return n
}
