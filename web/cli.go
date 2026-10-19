// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/abundo/portitor/models"
)

// SetAgent sets the first firewall's agent connection (install.py, for
// portitor-config's own agent).
func SetAgent(s *Server, url, token, fingerprint string) error {
	if err := s.ensureFirewall(); err != nil {
		return err
	}
	id, err := firstFirewallID(s.db)
	if err != nil {
		return err
	}
	var fw models.Firewall
	if err := s.db.First(&fw, id).Error; err != nil {
		return err
	}
	fw.AgentURL, fw.NewAgentToken, fw.AgentFingerprint = url, token, fingerprint
	if err := prepareFirewall(s.db, &fw, &fw); err != nil {
		return err
	}
	return s.db.Save(&fw).Error
}

// ImportBundleFile adds the bundle in path as a virtual firewall named
// name on the first firewall. Into a database without instances (a new
// portitor-config, before its first start) it becomes the host: how a
// firewall's own configuration moves from its manager.
//
// manager marks it as that manager's, as if it had pushed it: how a
// firewall's virtual firewalls move to portitor-config without being
// deleted at its first commit.
// With local, the instance stays this firewall's own and only its shared
// objects are the manager's.
func ImportBundleFile(ctx context.Context, s *Server, path, name, manager string, local bool) ([]string, error) {
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
	if manager != "" && !managerNameRe.MatchString(manager) {
		return nil, fmt.Errorf("manager: a lowercase name")
	}
	_, problems, err := importBundle(ctx, s.db, &b, strings.TrimSpace(name), 0, importOptions{Manager: manager, LocalInstance: local})
	return problems, err
}
