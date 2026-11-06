// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/abundo/portitor/internal/agentapi"
)

// The watchdog resets an open HA host whose HA loop stops: a hung agent
// must not keep the addresses from the standby, which takes them when the
// vote runs out. Armed when the gate opens, disarmed when it closes, fed
// from the HA loop alone, which touches no disk. An agent killed while
// armed closes the device without the magic character, so the host resets:
// that is what a crash has to do. A clean stop disarms it first.
//
// softdog covers an agent's hang, not the kernel's; the status says which
// one a host has.
const (
	watchdogDevice = "/dev/watchdog"
	// watchdogNoWayOut says whether the device can be stopped at all.
	watchdogNoWayOut = "/sys/class/watchdog/watchdog0/nowayout"
)

type watchdog struct {
	dry  bool
	run  Runner
	f    *os.File
	kind string // agentapi.HAWatchdog*, "" until looked for
}

// Linux's WDIOC ioctls.
const (
	wdiocGetSupport = 0x80285700
	wdiocSetTimeout = 0xc0045706
)

// watchdogInfo is struct watchdog_info.
type watchdogInfo struct {
	Options  uint32
	Firmware uint32
	Identity [32]byte
}

// watchdogKind tells a soft watchdog from the identity its driver gives.
func watchdogKind(identity []byte) string {
	if bytes.Contains(bytes.ToLower(identity), []byte("software watchdog")) || bytes.Contains(bytes.ToLower(identity), []byte("softdog")) {
		return agentapi.HAWatchdogSoft
	}
	return agentapi.HAWatchdogHardware
}

// detect finds out what the host has, loading softdog when it has
// nothing. It has to open the device to ask, and closes it with the magic
// character.
func (w *watchdog) detect(ctx context.Context) string {
	if w.kind != "" {
		return w.kind
	}
	if w.dry {
		w.kind = agentapi.HAWatchdogSoft
		return w.kind
	}
	if _, err := os.Stat(watchdogDevice); err != nil {
		if _, err := w.run.Run(ctx, "", "modprobe", "softdog"); err != nil {
			slog.Warn("ha: no watchdog, and softdog can't be loaded", "err", err)
		}
	}
	// With nowayout, just opening the device to ask would reset the host
	// when the agent closed it, and a closing gate couldn't disarm it.
	if b, err := os.ReadFile(watchdogNoWayOut); err == nil && string(bytes.TrimSpace(b)) == "1" {
		slog.Warn("ha: the watchdog can't be stopped (nowayout): automatic failover to this host is refused")
		w.kind = agentapi.HAWatchdogNone
		return w.kind
	}
	f, err := w.openDevice()
	if err != nil {
		slog.Warn("ha: no watchdog: automatic failover to this host is refused", "err", err)
		w.kind = agentapi.HAWatchdogNone
		return w.kind
	}
	defer disarm(f)
	var info watchdogInfo
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, f.Fd(), wdiocGetSupport, uintptr(unsafe.Pointer(&info))); e != 0 {
		w.kind = agentapi.HAWatchdogHardware
		return w.kind
	}
	w.kind = watchdogKind(info.Identity[:])
	return w.kind
}

func (w *watchdog) openDevice() (*os.File, error) {
	f, err := os.OpenFile(watchdogDevice, os.O_WRONLY, 0)
	if err != nil {
		return nil, err
	}
	secs := int32(haWatchdogTimeout / time.Second)
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, f.Fd(), wdiocSetTimeout, uintptr(unsafe.Pointer(&secs))); e != 0 {
		disarm(f)
		return nil, fmt.Errorf("set the timeout: %w", e)
	}
	return f, nil
}

func disarm(f *os.File) {
	_, _ = f.Write([]byte("V"))
	f.Close()
}

// arm starts the watchdog; from now on the host resets if feed stops.
func (w *watchdog) arm() error {
	if w.dry || w.f != nil {
		return nil
	}
	f, err := w.openDevice()
	if err != nil {
		return err
	}
	w.f = f
	return nil
}

func (w *watchdog) feed() {
	if w.f != nil {
		if _, err := w.f.Write([]byte{0}); err != nil && !errors.Is(err, os.ErrClosed) {
			slog.Error("ha: feeding the watchdog", "err", err)
		}
	}
}

// disarm stops the watchdog.
func (w *watchdog) disarm() {
	if w.f != nil {
		disarm(w.f)
		w.f = nil
	}
}
