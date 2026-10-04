// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/abundo/portitor/internal/fwconfig"
)

// NAT64 runs in Jool, one instance (fwconfig.JoolInstance) in each
// namespace that translates. Jool doesn't say how its instance was made,
// so the agent keeps the NAT64 it applied in <state>/nat64.json and makes
// the instance again when that changes, or when it isn't running (after a
// reboot, or a namespace made again; the agent applies at start).

func (a *Agent) nat64File(in *fwconfig.Instance) string {
	return filepath.Join(a.cfg.Paths.InstanceState(in.Name), "nat64.json")
}

// applyNAT64 makes the instance's Jool instance match in.NAT64. Its
// ruleset, with the NAT64 guard, is loaded before.
func (a *Agent) applyNAT64(ctx context.Context, in *fwconfig.Instance, ns string) error {
	var have *fwconfig.NAT64
	if readJSON(a.nat64File(in), &have) != nil {
		have = nil // none applied, or unreadable: made again
	}
	// An error is no Jool instance: the module isn't loaded, or jool isn't
	// installed, which matters only when one is wanted (checkPrograms).
	out, err := a.run.Run(ctx, ns, "jool", "-i", fwconfig.JoolInstance, "instance", "status")
	running := err == nil && strings.Contains(string(out), "Running")
	if err := a.doAll(ctx, planNAT64(ns, in.NAT64, have, running)); err != nil {
		return err
	}
	if in.NAT64 == nil {
		if err := os.Remove(a.nat64File(in)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	return writeJSON(a.nat64File(in), in.NAT64, 0o644)
}

// planNAT64 removes the Jool instance when NAT64 is off or changed, and
// makes it when NAT64 is on and it isn't running as wanted. have is the
// NAT64 last applied, nil when unknown.
func planNAT64(ns string, want, have *fwconfig.NAT64, running bool) []command {
	jool := func(args ...string) command { return command{Netns: ns, Name: "jool", Args: args} }
	same := running && want.Equal(have)
	var cmds []command
	if running && !same {
		cmds = append(cmds, jool("instance", "remove", fwconfig.JoolInstance))
	}
	if want == nil || same {
		return cmds
	}
	cmds = append(cmds,
		command{Name: "modprobe", Args: []string{"jool"}},
		jool("instance", "add", fwconfig.JoolInstance, "--netfilter", "--pool6", want.Prefix),
	)
	// The pool is the NAT64's alone: every port (ICMP id), which Jool
	// wants given.
	for _, p := range want.Pool4 {
		for _, proto := range []string{"--tcp", "--udp", "--icmp"} {
			cmds = append(cmds, jool("-i", fwconfig.JoolInstance, "pool4", "add", proto, p, "1-65535"))
		}
	}
	return cmds
}
