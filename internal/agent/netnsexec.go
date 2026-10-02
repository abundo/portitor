// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// droppedCaps leave the bounding set of an instance's daemons (named, Kea,
// radvd). They run as root, at least at first; without CAP_SYS_ADMIN they
// cannot setns into another instance's namespace or mount, and the rest
// would reach the host's kernel, devices or other processes.
var droppedCaps = []uintptr{
	unix.CAP_SYS_ADMIN,
	unix.CAP_SYS_MODULE,
	unix.CAP_SYS_PTRACE,
	unix.CAP_SYS_RAWIO,
	unix.CAP_SYS_BOOT,
	unix.CAP_SYS_TIME,
	unix.CAP_SYSLOG,
	unix.CAP_MKNOD,
	unix.CAP_BPF,
	unix.CAP_PERFMON,
	unix.CAP_MAC_ADMIN,
	unix.CAP_MAC_OVERRIDE,
	unix.CAP_AUDIT_CONTROL,
	unix.CAP_LINUX_IMMUTABLE,
}

// NetnsExec replaces the process with argv run inside an instance's
// namespace. systemd template units use it (portitor-named@.service, ...)
// so the daemon's PID stays the unit's main PID. The namespace is read
// from the file the agent writes on apply; empty means root namespace.
// It enters the namespace itself rather than through nsenter, so it can
// drop droppedCaps after the setns: systemd's CapabilityBoundingSet would
// drop CAP_SYS_ADMIN before it.
func NetnsExec(stateDir, instance string, argv []string) error {
	if len(argv) == 0 {
		return errors.New("no command")
	}
	if strings.ContainsAny(instance, "/.") || instance == "" {
		return fmt.Errorf("invalid instance %q", instance)
	}
	data, err := os.ReadFile(filepath.Join(stateDir, "instances", instance, "netns"))
	if err != nil {
		return fmt.Errorf("instance %s is not configured: %w", instance, err)
	}
	path, err := exec.LookPath(argv[0])
	if err != nil {
		return err
	}
	// The namespace belongs to this thread; exec from the same thread.
	runtime.LockOSThread()
	if ns := strings.TrimSpace(string(data)); ns != "" {
		if strings.ContainsAny(ns, "/.") {
			return fmt.Errorf("invalid netns %q", ns)
		}
		f, err := os.Open(filepath.Join("/run/netns", ns))
		if err != nil {
			return err
		}
		err = unix.Setns(int(f.Fd()), unix.CLONE_NEWNET)
		f.Close()
		if err != nil {
			return fmt.Errorf("setns %s: %w", ns, err)
		}
	}
	for _, c := range droppedCaps {
		// EINVAL: a capability this kernel does not know.
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, c, 0, 0, 0); err != nil && !errors.Is(err, unix.EINVAL) {
			return fmt.Errorf("drop capability %d: %w", c, err)
		}
	}
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil && !errors.Is(err, unix.EINVAL) {
		return fmt.Errorf("clear ambient capabilities: %w", err)
	}
	return syscall.Exec(path, argv, os.Environ())
}
