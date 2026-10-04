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

// serviceLogs counts the followed service logs
// (agentapi.ServiceLogMaxSessions).
var serviceLogs atomic.Int32

// handleServiceLog streams journalctl --follow of one of the instance's
// service units as text. journalctl only reads, so it runs outside the
// Runner, as the DNS query log's does. The client disconnecting stops it.
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
	if serviceLogs.Add(1) > agentapi.ServiceLogMaxSessions {
		serviceLogs.Add(-1)
		writeError(w, http.StatusTooManyRequests, fmt.Errorf("%d service logs are already followed", agentapi.ServiceLogMaxSessions))
		return
	}
	defer serviceLogs.Add(-1)

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	cmd := exec.CommandContext(ctx, "journalctl", "--follow", "--no-pager", "--output=short-iso",
		"--lines="+strconv.Itoa(agentapi.ServiceLogLines), "--unit="+req.Unit)
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
	slog.Info("service log started", "instance", req.Instance, "unit", req.Unit, "remote", r.RemoteAddr)

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
		slog.Warn("service log", "unit", req.Unit, "err", err)
	}
	slog.Info("service log ended", "instance", req.Instance, "unit", req.Unit)
}
