// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/abundo/portitor/internal/render"
)

// recRunner records the nft commands it passes on.
type recRunner struct {
	Runner
	mu   sync.Mutex
	cmds []string
}

func (r *recRunner) RunInput(ctx context.Context, netns string, stdin []byte, name string, args ...string) ([]byte, error) {
	if name == "nft" && netns == "" {
		r.mu.Lock()
		r.cmds = append(r.cmds, strings.Join(args, " ")+"\n"+string(stdin))
		r.mu.Unlock()
	}
	return r.Runner.RunInput(ctx, netns, stdin, name, args...)
}

func (r *recRunner) Run(ctx context.Context, netns, name string, args ...string) ([]byte, error) {
	return r.RunInput(ctx, netns, nil, name, args...)
}

// The boot-time policy goes only after the host's ruleset is loaded.
func TestApplyDropsEarlyAfterRuleset(t *testing.T) {
	a, _ := testAgent(t)
	r := &recRunner{Runner: a.run}
	a.run = r
	if _, err := a.Apply(context.Background(), sampleGen(1), 0); err != nil {
		t.Fatal(err)
	}
	ruleset, drop := -1, -1
	for i, c := range r.cmds {
		if strings.HasPrefix(c, "-f "+a.cfg.Paths.NftablesFile) && ruleset < 0 {
			ruleset = i
		}
		if strings.Contains(c, "delete table inet "+render.EarlyTable) && drop < 0 {
			drop = i
		}
	}
	if ruleset < 0 || drop < 0 || drop < ruleset {
		t.Fatalf("ruleset at %d, early policy dropped at %d:\n%s", ruleset, drop, strings.Join(r.cmds, "---\n"))
	}
}

// A dry run loads no boot-time policy; an unreadable agent.yaml loads it
// without the anti-lockout rule.
func TestLoadEarly(t *testing.T) {
	a, _ := testAgent(t)
	r := &recRunner{Runner: a.run}
	if err := LoadEarly(context.Background(), &Config{DryRun: true}, r); err != nil || len(r.cmds) != 0 {
		t.Fatalf("dry run: %v %q", err, r.cmds)
	}
	if err := LoadEarly(context.Background(), nil, r); err != nil {
		t.Fatal(err)
	}
	if len(r.cmds) != 1 || !strings.Contains(r.cmds[0], "policy drop") || strings.Contains(r.cmds[0], render.AntiLockoutService) {
		t.Fatalf("no config: %q", r.cmds)
	}
}

// A ruleset that fails to load leaves the boot-time policy in place.
func TestFailedApplyKeepsEarly(t *testing.T) {
	a, _ := testAgent(t)
	f := withFailRunner(a)
	f.fail.Store(true)
	r := &recRunner{Runner: f}
	a.run = r
	if _, err := a.Apply(context.Background(), sampleGen(1), 0); err == nil {
		t.Fatal("apply did not fail")
	}
	for _, c := range r.cmds {
		if strings.Contains(c, "delete table inet "+render.EarlyTable) {
			t.Fatalf("boot-time policy dropped after a failed load:\n%s", c)
		}
	}
}
