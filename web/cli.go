// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/abundo/portitor/internal/datastore"
)

// SetAgent sets the first firewall's agent connection (install.py, for
// portitor-config's own agent).
func SetAgent(s *Server, url, token, fingerprint string) error {
	if err := s.ensureFirewall(); err != nil {
		return err
	}
	id, err := s.firstFirewallID()
	if err != nil {
		return err
	}
	fw, err := s.rec.Firewall(id)
	if err != nil {
		return err
	}
	// The firewall's own checks, as its CRUD runs them.
	c := *fw
	c.AgentURL, c.NewAgentToken, c.AgentFingerprint = url, token, fingerprint
	if err := checkFirewallFields(&c); err != nil {
		return err
	}
	return s.rec.SetAgentConnection(id, c.AgentURL, c.AgentToken, c.AgentFingerprint)
}

// ImportBundleFile adds the bundle in path as a virtual firewall named
// name on the first firewall. Into a configuration without instances (a new
// portitor-config, before its first start) it becomes the host.
func ImportBundleFile(ctx context.Context, s *Server, path, name string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var b Bundle
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := s.ensureFirewall(); err != nil {
		return nil, err
	}
	if name == "" {
		name = b.Instance
	}
	name = strings.TrimSpace(name)
	fw, err := s.bundleFirewall(0)
	if err != nil {
		return nil, err
	}
	if err := s.editConfig(ctx, func(work *datastore.Tree) error { return s.importBundle(work, &b, name, fw) }); err != nil {
		var br *badRequest
		if errors.As(err, &br) {
			return nil, errors.New(br.msg)
		}
		return nil, err
	}
	return s.bundleProblems(ctx, name), nil
}
