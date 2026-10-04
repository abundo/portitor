// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Runner executes system commands, optionally inside a network namespace.
// Everything the agent does to the system goes through it, so dry-run mode
// and tests can swap it out.
type Runner interface {
	Run(ctx context.Context, netns, name string, args ...string) ([]byte, error)
	// RunInput is Run with stdin fed from the given bytes.
	RunInput(ctx context.Context, netns string, stdin []byte, name string, args ...string) ([]byte, error)
}

// ExecRunner runs real commands.
type ExecRunner struct {
	Log *OpLog
}

func (r *ExecRunner) Run(ctx context.Context, netns, name string, args ...string) ([]byte, error) {
	return r.RunInput(ctx, netns, nil, name, args...)
}

func (r *ExecRunner) RunInput(ctx context.Context, netns string, stdin []byte, name string, args ...string) ([]byte, error) {
	argv := inNetns(netns, append([]string{name}, args...))
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		err = fmt.Errorf("%s: %w: %s", strings.Join(argv, " "), err, msg)
	}
	if !isQuery(name, args) {
		r.Log.Cmd(netns, argv, err)
	}
	return out, err
}

// inNetns prefixes argv to run in a named network namespace. nsenter only
// switches the network namespace; `ip netns exec` also remounts /sys, which
// a user namespace (rootless container, see dev/lab) doesn't allow. Nothing
// the agent runs there reads /sys.
func inNetns(netns string, argv []string) []string {
	if netns == "" {
		return argv
	}
	return append([]string{"nsenter", "--net=/run/netns/" + netns, "--"}, argv...)
}

// DryRunner logs mutating commands instead of running them. Read-only
// queries (ip -j ..., wg show) still run, so the plan is computed against
// the real system when the host has the tools.
type DryRunner struct {
	Log *OpLog
}

func (r *DryRunner) RunInput(ctx context.Context, netns string, stdin []byte, name string, args ...string) ([]byte, error) {
	return r.Run(ctx, netns, name, args...)
}

func (r *DryRunner) Run(ctx context.Context, netns, name string, args ...string) ([]byte, error) {
	// ExecRunner can't start a command on a finished context; neither
	// does a dry run, so tests catch one.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if isQuery(name, args) {
		if netns != "" || name != "ip" {
			// Namespaces don't exist in dry-run, and the other queries
			// need root; report empty state.
			return []byte("[]"), nil
		}
		out, err := exec.CommandContext(ctx, name, args...).Output()
		if err != nil {
			return []byte("[]"), nil
		}
		return out, nil
	}
	argv := append([]string{name}, args...)
	r.Log.Cmd(netns, append([]string{"(dry-run)"}, argv...), nil)
	return nil, nil
}

// isQuery reports commands that only read state.
func isQuery(name string, args []string) bool {
	switch name {
	case "ip":
		if len(args) > 0 && args[0] == "-j" {
			return true
		}
		return len(args) >= 2 && args[0] == "netns" && args[1] == "list"
	case "wg":
		return len(args) > 0 && args[0] == "show"
	case "tc":
		return len(args) > 0 && args[0] == "-j"
	case "systemctl":
		return len(args) > 0 && (args[0] == "is-active" || args[0] == "is-enabled" || args[0] == "show")
	case "journalctl":
		return true
	case "vtysh":
		// BGP and OSPF info: vtysh [-N <instance>] -c "show ...".
		return len(args) >= 2 && args[len(args)-2] == "-c" &&
			strings.HasPrefix(args[len(args)-1], "show ")
	case "apt-get":
		return len(args) > 0 && args[0] == "-s"
	case "nft":
		return len(args) > 0 && (args[0] == "-c" || args[0] == "list" || (args[0] == "-j" && len(args) > 1 && args[1] == "list"))
	}
	return false
}

// OpLog collects what an apply did, for the API response and the journal.
type OpLog struct {
	mu    sync.Mutex
	lines []string
}

func (l *OpLog) Cmd(netns string, argv []string, err error) {
	prefix := "$ "
	if netns != "" {
		prefix = "[" + netns + "] $ "
	}
	line := prefix + strings.Join(argv, " ")
	if err != nil {
		line += "\n  ! " + err.Error()
		slog.Warn("command failed", "netns", netns, "cmd", strings.Join(argv, " "), "err", err)
	} else {
		slog.Info("command", "netns", netns, "cmd", strings.Join(argv, " "))
	}
	l.add(line)
}

func (l *OpLog) Infof(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	slog.Info(msg)
	l.add("# " + msg)
}

func (l *OpLog) add(line string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, line)
}

// Take returns and clears the collected lines.
func (l *OpLog) Take() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := l.lines
	l.lines = nil
	return out
}
