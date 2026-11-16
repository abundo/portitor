// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"log/slog"

	"github.com/abundo/portitor/internal/render"
)

// LoadEarly loads the host's boot-time policy (render.Early), before the
// network is up (`portitor-agent early`, portitor-early.service). cfg nil
// (agent.yaml unreadable) still closes the host, without the anti-lockout
// rule: failing closed. A dry run loads nothing, as its agent would never
// take the policy away.
func LoadEarly(ctx context.Context, cfg *Config, r Runner) error {
	var lockout *render.AntiLockout
	if cfg != nil {
		if cfg.DryRun {
			slog.Info("dry run: no boot-time policy")
			return nil
		}
		lockout = cfg.antiLockout()
	}
	_, err := r.RunInput(ctx, "", []byte(render.Early(lockout)), "nft", "-f", "-")
	return err
}

// dropEarly takes the boot-time policy away once the default instance's
// ruleset is loaded. A table left behind would drop what the ruleset
// lets in, so failing is an apply error.
func (a *Agent) dropEarly(ctx context.Context) error {
	return a.do(ctx, command{Name: "nft", Args: []string{"-f", "-"}, Stdin: []byte(render.EarlyDelete())})
}
