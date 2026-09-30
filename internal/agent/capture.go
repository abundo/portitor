// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unicode"

	"golang.org/x/time/rate"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/fwconfig"
)

// captures counts the running captures (agentapi.CaptureMaxSessions).
var captures atomic.Int32

// handleCapture runs tcpdump in the instance's namespace and streams its
// pcap output, paced to the requested rate. When the stream falls behind,
// the pipe from tcpdump fills and the kernel drops packets; the capture
// never buffers without bound. The client disconnecting stops tcpdump.
func (a *Agent) handleCapture(w http.ResponseWriter, r *http.Request) {
	var req agentapi.CaptureRequest
	if !decode(w, r, &req) {
		return
	}
	if a.cfg.DryRun {
		writeError(w, http.StatusServiceUnavailable, errors.New("packet capture is not available in dry-run mode"))
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
	argv, err := captureArgs(in, &req, a.agentPort())
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if captures.Add(1) > agentapi.CaptureMaxSessions {
		captures.Add(-1)
		writeError(w, http.StatusTooManyRequests, fmt.Errorf("%d captures are already running", agentapi.CaptureMaxSessions))
		return
	}
	defer captures.Add(-1)

	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(req.MaxSeconds)*time.Second)
	defer cancel()
	argv = inNetns(in.NetnsName(), argv)
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// SIGINT makes tcpdump flush and exit cleanly; nsenter passes it on.
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGINT) }
	cmd.WaitDelay = 5 * time.Second
	stderr := &tailBuffer{max: 4 << 10}
	cmd.Stderr = stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if err := cmd.Start(); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Errorf("start tcpdump: %w", err))
		return
	}
	slog.Info("capture started", "instance", req.Instance, "interface", req.Interface, "filter", req.Filter, "remote", r.RemoteAddr)

	// The pcap header comes as soon as tcpdump has opened the interface;
	// a bad filter or interface fails before it.
	buf := make([]byte, captureChunk)
	n, rerr := io.ReadAtLeast(out, buf, 24)
	if rerr != nil {
		werr := cmd.Wait()
		msg := strings.TrimSpace(stderr.String())
		if msg == "" && werr != nil {
			msg = werr.Error()
		}
		writeError(w, http.StatusBadRequest, errors.New(msg))
		return
	}

	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{}) // the server's timeout is for requests
	w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	w.WriteHeader(http.StatusOK)
	var lim *rate.Limiter
	if req.RateKbps > 0 {
		lim = rate.NewLimiter(rate.Limit(req.RateKbps*1000/8), captureChunk)
	}
	var sent int64
	for {
		if n > 0 {
			if lim != nil {
				if lim.WaitN(ctx, n) != nil {
					break
				}
			}
			if _, err := w.Write(buf[:n]); err != nil {
				break
			}
			_ = rc.Flush()
			sent += int64(n)
		}
		if rerr != nil {
			break
		}
		n, rerr = out.Read(buf)
	}
	cancel()
	_ = cmd.Wait()
	slog.Info("capture ended", "instance", req.Instance, "interface", req.Interface, "bytes", sent, "tcpdump", strings.TrimSpace(stderr.String()))
}

// captureChunk is the most the stream writes at once, and the rate
// limiter's burst.
const captureChunk = 16 << 10

// captureArgs checks and clamps the request and returns tcpdump's argv.
// In the default instance, the agent's own API connection is left out so
// the capture does not capture itself.
func captureArgs(in *fwconfig.Instance, req *agentapi.CaptureRequest, apiPort int) ([]string, error) {
	if req.Interface != "any" {
		if ifc := in.Interface(req.Interface); ifc == nil {
			return nil, fmt.Errorf("instance %s has no interface %q", in.Name, req.Interface)
		}
	}
	if len(req.Filter) > agentapi.CaptureMaxFilterLen {
		return nil, fmt.Errorf("filter is longer than %d characters", agentapi.CaptureMaxFilterLen)
	}
	if strings.IndexFunc(req.Filter, unicode.IsControl) >= 0 {
		return nil, errors.New("filter has control characters")
	}
	clamp := func(v *int, max int) {
		if *v <= 0 || *v > max {
			*v = max
		}
	}
	clamp(&req.Snaplen, agentapi.CaptureMaxSnaplen)
	clamp(&req.MaxPackets, agentapi.CaptureMaxPackets)
	clamp(&req.MaxSeconds, agentapi.CaptureMaxSeconds)
	if req.RateKbps < 0 {
		req.RateKbps = 0
	}
	filter := strings.TrimSpace(req.Filter)
	if in.Default && apiPort > 0 {
		self := "not tcp port " + strconv.Itoa(apiPort)
		if filter == "" {
			filter = self
		} else {
			filter = self + " and (" + filter + ")"
		}
	}
	argv := []string{"tcpdump", "-i", req.Interface, "-n", "-U", "-w", "-",
		"-s", strconv.Itoa(req.Snaplen), "-c", strconv.Itoa(req.MaxPackets)}
	if filter != "" {
		// After "--" the filter is one argument that can't be an option.
		argv = append(argv, "--", filter)
	}
	return argv, nil
}

// agentPort is the API's TCP port (cfg.Listen).
func (a *Agent) agentPort() int {
	if i := strings.LastIndex(a.cfg.Listen, ":"); i >= 0 {
		if p, err := strconv.Atoi(a.cfg.Listen[i+1:]); err == nil {
			return p
		}
	}
	return 0
}
