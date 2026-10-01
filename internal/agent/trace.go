// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/fwconfig"
)

// traces counts the running traceroutes (agentapi.TraceMaxSessions).
var traces atomic.Int32

// handleTrace runs mtr in the instance's namespace and streams its raw
// output as agentapi.TraceEvents, one JSON line each. The client
// disconnecting stops mtr.
func (a *Agent) handleTrace(w http.ResponseWriter, r *http.Request) {
	var req agentapi.TraceRequest
	if !decode(w, r, &req) {
		return
	}
	if a.cfg.DryRun {
		writeError(w, http.StatusServiceUnavailable, errors.New("traceroute is not available in dry-run mode"))
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
	if err := resolveTarget(r.Context(), in.NetnsName(), &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	argv, err := traceArgs(in, &req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if traces.Add(1) > agentapi.TraceMaxSessions {
		traces.Add(-1)
		writeError(w, http.StatusTooManyRequests, fmt.Errorf("%d traceroutes are already running", agentapi.TraceMaxSessions))
		return
	}
	defer traces.Add(-1)

	// One round a second, and some time for the last replies.
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(req.Count+30)*time.Second)
	defer cancel()
	argv = inNetns(in.NetnsName(), argv)
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM) }
	cmd.WaitDelay = 5 * time.Second
	stderr := &tailBuffer{max: 4 << 10}
	cmd.Stderr = stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if err := cmd.Start(); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Errorf("start mtr: %w", err))
		return
	}
	slog.Info("traceroute started", "instance", req.Instance, "interface", req.Interface, "target", req.Target, "remote", r.RemoteAddr)

	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{}) // the server's timeout is for requests
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	// The reverse lookups send from their own goroutines.
	var sendMu sync.Mutex
	send := func(ev agentapi.TraceEvent) bool {
		sendMu.Lock()
		defer sendMu.Unlock()
		if enc.Encode(ev) != nil {
			return false
		}
		_ = rc.Flush()
		return true
	}
	send(agentapi.TraceEvent{Type: "target", Addr: req.Target})
	var lookups sync.WaitGroup
	looked := map[string]bool{}
	sc := bufio.NewScanner(out)
	for sc.Scan() {
		ev, ok := parseMtrRaw(sc.Text())
		if !ok {
			continue
		}
		if !send(ev) {
			break
		}
		if ev.Type == "host" && !looked[ev.Addr] && len(looked) < traceMaxLookups {
			looked[ev.Addr] = true
			lookups.Go(func() {
				if name := reverseName(ctx, in.NetnsName(), ev.Addr); name != "" {
					send(agentapi.TraceEvent{Type: "name", Hop: ev.Hop, Addr: ev.Addr, Name: name})
				}
			})
		}
	}
	ctxErr := ctx.Err()
	werr := cmd.Wait()
	// Lookups still running get a few seconds after mtr is done.
	done := make(chan struct{})
	go func() { lookups.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
	cancel()
	<-done
	if msg := strings.TrimSpace(stderr.String()); werr != nil && ctxErr == nil && r.Context().Err() == nil {
		if msg == "" {
			msg = werr.Error()
		}
		send(agentapi.TraceEvent{Type: "error", Error: msg})
	}
	slog.Info("traceroute ended", "instance", req.Instance, "target", req.Target)
}

// traceMaxLookups is how many addresses a trace looks up names for.
const traceMaxLookups = 256

// reverseName looks up addr's name (PTR, or /etc/hosts) with getent in
// the instance's namespace; "" when it has none.
func reverseName(ctx context.Context, netns, addr string) string {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	argv := inNetns(netns, []string{"getent", "hosts", "--", addr})
	out, _ := exec.CommandContext(ctx, argv[0], argv[1:]...).Output()
	f := strings.Fields(string(out))
	if len(f) < 2 || len(f[1]) > 253 || !dnsName.MatchString(f[1]) {
		return ""
	}
	return strings.TrimSuffix(f[1], ".")
}

// dnsName is a host name a trace may resolve: letters, digits, '-' and
// '_' in dot-separated labels, never starting with '-'.
var dnsName = regexp.MustCompile(`^(?i)[a-z0-9_]([a-z0-9_-]{0,62})(\.[a-z0-9_]([a-z0-9_-]{0,62}))*\.?$`)

// resolveTarget replaces a DNS name in req.Target by its first address
// (of req.Family), resolved in the instance's namespace.
func resolveTarget(ctx context.Context, netns string, req *agentapi.TraceRequest) error {
	if _, err := netip.ParseAddr(req.Target); err == nil {
		return nil
	}
	if len(req.Target) > 253 || !dnsName.MatchString(req.Target) {
		return fmt.Errorf("target %q is not an IP address or a DNS name", req.Target)
	}
	a, err := resolveName(ctx, netns, req.Target, req.Family)
	if err != nil {
		return err
	}
	req.Target = a.String()
	return nil
}

// resolveName returns name's first address of family ("ipv4", "ipv6", or
// "" for IPv4 first, as for named hosts), resolved with getent in the
// instance's namespace so the name means what it means to the instance.
// The caller checks name against dnsName.
func resolveName(ctx context.Context, netns, name, family string) (netip.Addr, error) {
	db := "ahosts"
	switch family {
	case "ipv4":
		db = "ahostsv4"
	case "ipv6":
		db = "ahostsv6"
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	argv := inNetns(netns, []string{"getent", db, "--", name})
	out, _ := exec.CommandContext(ctx, argv[0], argv[1:]...).Output()
	var first netip.Addr
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		a, err := netip.ParseAddr(f[0])
		if err != nil {
			continue
		}
		a = a.Unmap()
		if family == "" && a.Is4() {
			first = a
			break
		}
		if !first.IsValid() {
			first = a
		}
	}
	if !first.IsValid() {
		return netip.Addr{}, fmt.Errorf("cannot resolve %s", name)
	}
	return first, nil
}

// traceArgs checks and clamps the request and returns mtr's argv.
func traceArgs(in *fwconfig.Instance, req *agentapi.TraceRequest) ([]string, error) {
	addr, err := netip.ParseAddr(req.Target)
	if err != nil || addr.Zone() != "" {
		return nil, fmt.Errorf("target %q is not an IP address", req.Target)
	}
	addr = addr.Unmap()
	if req.Count <= 0 {
		req.Count = agentapi.TraceDefaultCount
	}
	if req.Count > agentapi.TraceMaxCount {
		req.Count = agentapi.TraceMaxCount
	}
	argv := []string{"mtr", "--raw", "--no-dns", "--report-cycles", strconv.Itoa(req.Count), "--interval", "1"}
	if addr.Is4() {
		argv = append(argv, "-4")
	} else {
		argv = append(argv, "-6")
	}
	if req.Interface != "" {
		if in.Interface(req.Interface) == nil {
			return nil, fmt.Errorf("instance %s has no interface %q", in.Name, req.Interface)
		}
		argv = append(argv, "--interface", req.Interface)
	}
	return append(argv, "--", addr.String()), nil
}

// parseMtrRaw reads one line of mtr --raw: "x <hop> <seq>" (sent),
// "h <hop> <addr>" (host), "p <hop> <usec> <seq>" (reply). mtr numbers
// hops from 0; events number them from 1. Other lines are left out.
func parseMtrRaw(line string) (agentapi.TraceEvent, bool) {
	f := strings.Fields(line)
	if len(f) < 3 {
		return agentapi.TraceEvent{}, false
	}
	hop, err := strconv.Atoi(f[1])
	if err != nil || hop < 0 || hop > 255 {
		return agentapi.TraceEvent{}, false
	}
	ev := agentapi.TraceEvent{Hop: hop + 1}
	num := func(s string) (int, bool) {
		n, err := strconv.Atoi(s)
		return n, err == nil && n >= 0
	}
	var ok bool
	switch f[0] {
	case "x":
		ev.Type = "sent"
		ev.Seq, ok = num(f[2])
	case "h":
		ev.Type = "host"
		a, err := netip.ParseAddr(f[2])
		ev.Addr, ok = a.String(), err == nil
	case "p":
		ev.Type = "reply"
		ev.RTTus, ok = num(f[2])
		if ok && len(f) > 3 {
			ev.Seq, ok = num(f[3])
		}
	}
	return ev, ok
}
