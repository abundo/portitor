// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os/exec"
	"slices"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/fwconfig"
)

// serviceLogs counts the followed service logs and journals
// (agentapi.ServiceLogMaxSessions).
var serviceLogs atomic.Int32

// handleServiceLog streams journalctl --follow of one of the instance's
// service units as text.
func (a *Agent) handleServiceLog(w http.ResponseWriter, r *http.Request) {
	var req agentapi.ServiceLogRequest
	if !decode(w, r, &req) {
		return
	}
	a.mu.Lock()
	var in *fwconfig.Instance
	if a.applied != nil {
		d := a.applied.Expand()
		in = d.Instance(req.Instance)
	}
	a.mu.Unlock()
	if in == nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("no applied instance %q", req.Instance))
		return
	}
	if !slices.Contains(a.serviceUnits(in), req.Unit) {
		writeError(w, http.StatusBadRequest, fmt.Errorf("instance %s has no service %q", in.Name, req.Unit))
		return
	}
	a.followJournal(w, r, agentapi.ServiceLogLines, "service log", "--unit="+req.Unit)
}

// followJournal streams journalctl --follow as text, starting with the
// last lines entries, of the units in args (none: the whole journal), and
// logs it as what. journalctl only reads, so it runs outside the Runner,
// as the DNS query log's does. The client disconnecting stops it.
func (a *Agent) followJournal(w http.ResponseWriter, r *http.Request, lines int, what string, args ...string) {
	if serviceLogs.Add(1) > agentapi.ServiceLogMaxSessions {
		serviceLogs.Add(-1)
		writeError(w, http.StatusTooManyRequests, fmt.Errorf("%d logs are already followed", agentapi.ServiceLogMaxSessions))
		return
	}
	defer serviceLogs.Add(-1)

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	cmd := exec.CommandContext(ctx, "journalctl", append([]string{"--follow", "--no-pager", "--output=short-iso",
		"--lines=" + strconv.Itoa(lines)}, args...)...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM) }
	cmd.WaitDelay = 5 * time.Second
	out, err := cmd.StdoutPipe()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if err := cmd.Start(); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Errorf("start journalctl: %w", err))
		return
	}
	slog.Info(what+" started", "args", args, "remote", r.RemoteAddr)

	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{}) // the server's timeout is for requests
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	buf := make([]byte, 8<<10)
	for {
		n, rerr := out.Read(buf)
		if n > 0 {
			if _, err := w.Write(buf[:n]); err != nil {
				break
			}
			_ = rc.Flush()
		}
		if rerr != nil {
			break
		}
	}
	cancel()
	if err := cmd.Wait(); err != nil && !errors.Is(ctx.Err(), context.Canceled) {
		slog.Warn(what, "args", args, "err", err)
	}
	slog.Info(what+" ended", "args", args)
}
