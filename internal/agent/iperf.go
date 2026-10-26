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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/render"
)

// iperfs counts the running iperf3 tests and servers
// (agentapi.IperfMaxSessions).
var iperfs atomic.Int32

// iperfServers are the ports of the running servers, by namespace and
// port: one server per port in an instance.
var iperfServers = struct {
	sync.Mutex
	m map[string]bool
}{m: map[string]bool{}}

// iperfRenew is how often a running server's port is opened again in
// the ruleset, well within render.IperfServerTimeout.
const iperfRenew = 20 * time.Second

// handleIperf runs iperf3 in the instance's namespace, a client or a
// server, and streams its --json-stream output as agentapi.IperfEvents,
// one JSON line each. A server's port is in the ruleset's
// render.IperfServerSet while it runs. The client disconnecting stops
// iperf3.
func (a *Agent) handleIperf(w http.ResponseWriter, r *http.Request) {
	var req agentapi.IperfRequest
	if !decode(w, r, &req) {
		return
	}
	if a.cfg.DryRun {
		writeError(w, http.StatusServiceUnavailable, errors.New("iperf3 is not available in dry-run mode"))
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
	ns := in.NetnsName()
	if req.Mode == "client" {
		if _, err := netip.ParseAddr(req.Target); err != nil {
			if len(req.Target) > 253 || !dnsName.MatchString(req.Target) {
				writeError(w, http.StatusBadRequest, fmt.Errorf("server %q is not an IP address or a DNS name", req.Target))
				return
			}
			addr, err := resolveName(r.Context(), ns, req.Target, req.Family)
			if err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
			req.Target = addr.String()
		}
	}
	argv, err := iperfArgs(in, &req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if iperfs.Add(1) > agentapi.IperfMaxSessions {
		iperfs.Add(-1)
		writeError(w, http.StatusTooManyRequests, fmt.Errorf("%d iperf3 tests are already running", agentapi.IperfMaxSessions))
		return
	}
	defer iperfs.Add(-1)
	server := req.Mode == "server"
	if server {
		key := ns + "/" + strconv.Itoa(req.Port)
		iperfServers.Lock()
		taken := iperfServers.m[key]
		iperfServers.m[key] = true
		iperfServers.Unlock()
		if taken {
			writeError(w, http.StatusConflict, fmt.Errorf("an iperf3 server is already running on port %d in %s", req.Port, req.Instance))
			return
		}
		defer func() {
			iperfServers.Lock()
			delete(iperfServers.m, key)
			iperfServers.Unlock()
		}()
	}

	// A client's test and some time to connect and end; a server listens
	// for its duration.
	limit := time.Duration(req.Duration) * time.Second
	if !server {
		limit += 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(r.Context(), limit)
	defer cancel()
	argv = inNetns(ns, argv)
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
		writeError(w, http.StatusInternalServerError, fmt.Errorf("start iperf3: %w", err))
		return
	}
	slog.Info("iperf3 started", "instance", req.Instance, "mode", req.Mode, "interface", req.Interface, "target", req.Target, "port", req.Port, "remote", r.RemoteAddr)
	if server {
		renewed := make(chan struct{})
		go func() {
			defer close(renewed)
			for {
				if _, err := a.run.RunInput(ctx, ns, []byte(render.IperfServerOpen(req.Port)), "nft", "-f", "-"); err != nil && ctx.Err() == nil {
					slog.Error("iperf3: open port", "instance", req.Instance, "port", req.Port, "err", err)
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(iperfRenew):
				}
			}
		}()
		defer func() {
			cancel()
			<-renewed
			cctx, ccancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer ccancel()
			// Gone already when the ruleset was loaded since the last renewal
			// and it timed out.
			_, _ = a.run.RunInput(cctx, ns, []byte(render.IperfServerClose(req.Port)), "nft", "-f", "-")
		}()
	}

	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{}) // the server's timeout is for requests
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	send := func(ev agentapi.IperfEvent) bool {
		if enc.Encode(ev) != nil {
			return false
		}
		_ = rc.Flush()
		return true
	}
	if server {
		send(agentapi.IperfEvent{Type: "listening", Port: req.Port})
	}
	sc := bufio.NewScanner(out)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		ev, ok := parseIperfLine(sc.Bytes())
		// Stopping makes iperf3 report its signal as an error.
		if !ok || ctx.Err() != nil {
			continue
		}
		if !send(ev) {
			break
		}
	}
	ctxErr := ctx.Err()
	werr := cmd.Wait()
	if msg := strings.TrimSpace(stderr.String()); werr != nil && ctxErr == nil && r.Context().Err() == nil && msg != "" {
		send(agentapi.IperfEvent{Type: "error", Error: msg})
	}
	slog.Info("iperf3 ended", "instance", req.Instance, "mode", req.Mode, "target", req.Target, "port", req.Port)
}

// iperfArgs checks the request, fills in its defaults, clamps it and
// returns iperf3's argv. The client's Target must be an address by now.
func iperfArgs(in *fwconfig.Instance, req *agentapi.IperfRequest) ([]string, error) {
	if req.Port == 0 {
		req.Port = agentapi.IperfDefaultPort
	}
	if req.Port < 1 || req.Port > 65535 {
		return nil, fmt.Errorf("port %d is not 1-65535", req.Port)
	}
	argv := []string{"iperf3", "--json-stream", "--forceflush", "--interval", "1"}
	switch req.Mode {
	case "client":
		addr, err := netip.ParseAddr(req.Target)
		if err != nil || addr.Zone() != "" {
			return nil, fmt.Errorf("server %q is not an IP address", req.Target)
		}
		addr = addr.Unmap()
		if req.Duration <= 0 {
			req.Duration = agentapi.IperfDefaultDuration
		}
		req.Duration = min(req.Duration, agentapi.IperfMaxDuration)
		if req.Streams <= 0 {
			req.Streams = 1
		}
		if req.Streams > agentapi.IperfMaxStreams {
			return nil, fmt.Errorf("at most %d parallel streams", agentapi.IperfMaxStreams)
		}
		argv = append(argv, "--client", addr.String(), "--port", strconv.Itoa(req.Port),
			"--time", strconv.Itoa(req.Duration), "--parallel", strconv.Itoa(req.Streams), "--connect-timeout", "5000")
		switch req.Protocol {
		case "", "tcp":
		case "udp":
			argv = append(argv, "--udp")
		default:
			return nil, fmt.Errorf("protocol %q is not tcp or udp", req.Protocol)
		}
		switch req.Direction {
		case "", "send":
		case "receive":
			argv = append(argv, "--reverse")
		case "both":
			argv = append(argv, "--bidir")
		default:
			return nil, fmt.Errorf("direction %q is not send, receive or both", req.Direction)
		}
		if req.Bitrate < 0 {
			return nil, errors.New("the bitrate cannot be negative")
		}
		if req.Bitrate > 0 {
			argv = append(argv, "--bitrate", strconv.FormatInt(req.Bitrate, 10))
		}
		if addr.Is4() {
			argv = append(argv, "-4")
		} else {
			argv = append(argv, "-6")
		}
	case "server":
		if req.Duration <= 0 {
			req.Duration = agentapi.IperfDefaultServerDuration
		}
		req.Duration = min(req.Duration, agentapi.IperfMaxDuration)
		argv = append(argv, "--server", "--port", strconv.Itoa(req.Port))
		if req.OneOff {
			argv = append(argv, "--one-off")
		}
		switch req.Family {
		case "":
		case "ipv4":
			argv = append(argv, "-4")
		case "ipv6":
			argv = append(argv, "-6")
		default:
			return nil, fmt.Errorf("family %q is not ipv4 or ipv6", req.Family)
		}
	default:
		return nil, fmt.Errorf("mode %q is not client or server", req.Mode)
	}
	if req.Interface != "" {
		if in.Interface(req.Interface) == nil {
			return nil, fmt.Errorf("instance %s has no interface %q", in.Name, req.Interface)
		}
		argv = append(argv, "--bind-dev", req.Interface)
	}
	return argv, nil
}

// iperfSum is a sum of iperf3's JSON: an interval's or a test's, of one
// direction. Sender is whether this host sent it.
type iperfSum struct {
	Start         float64  `json:"start"`
	End           float64  `json:"end"`
	Bytes         int64    `json:"bytes"`
	BitsPerSecond float64  `json:"bits_per_second"`
	Retransmits   *int64   `json:"retransmits"`
	JitterMs      *float64 `json:"jitter_ms"`
	LostPackets   *int64   `json:"lost_packets"`
	Packets       *int64   `json:"packets"`
	LostPercent   *float64 `json:"lost_percent"`
	Sender        bool     `json:"sender"`
}

func (s *iperfSum) event(receiver bool) agentapi.IperfSum {
	dir := "received"
	if s.Sender {
		dir = "sent"
	}
	out := agentapi.IperfSum{Dir: dir, Receiver: receiver, Start: s.Start, End: s.End, Bytes: s.Bytes, BitsPerSecond: s.BitsPerSecond, Packets: s.Packets}
	// The sender counts retransmits; jitter and loss only the receiver
	// knows (the sender's are 0).
	if receiver {
		out.JitterMs, out.LostPackets, out.LostPercent = s.JitterMs, s.LostPackets, s.LostPercent
	} else {
		out.Retransmits = s.Retransmits
	}
	return out
}

// parseIperfLine reads one line of iperf3 --json-stream: {"event": ...,
// "data": ...}. Other lines, and an end without sums (after an error),
// are left out.
func parseIperfLine(line []byte) (agentapi.IperfEvent, bool) {
	var raw struct {
		Event string          `json:"event"`
		Data  json.RawMessage `json:"data"`
	}
	if json.Unmarshal(line, &raw) != nil {
		return agentapi.IperfEvent{}, false
	}
	switch raw.Event {
	case "start":
		var d struct {
			Connected []struct {
				RemoteHost string `json:"remote_host"`
			} `json:"connected"`
			TestStart struct {
				Protocol   string `json:"protocol"`
				NumStreams int    `json:"num_streams"`
				Duration   int    `json:"duration"`
			} `json:"test_start"`
		}
		if json.Unmarshal(raw.Data, &d) != nil {
			return agentapi.IperfEvent{}, false
		}
		ev := agentapi.IperfEvent{Type: "start", Protocol: strings.ToLower(d.TestStart.Protocol), Streams: d.TestStart.NumStreams, Duration: d.TestStart.Duration}
		if len(d.Connected) > 0 {
			if a, err := netip.ParseAddr(d.Connected[0].RemoteHost); err == nil {
				ev.Remote = a.Unmap().String()
			}
		}
		return ev, true
	case "interval":
		var d struct {
			Sum        *iperfSum `json:"sum"`
			SumReverse *iperfSum `json:"sum_bidir_reverse"`
		}
		if json.Unmarshal(raw.Data, &d) != nil {
			return agentapi.IperfEvent{}, false
		}
		ev := agentapi.IperfEvent{Type: "interval"}
		for _, s := range []*iperfSum{d.Sum, d.SumReverse} {
			if s != nil {
				ev.Sums = append(ev.Sums, s.event(!s.Sender))
			}
		}
		return ev, len(ev.Sums) > 0
	case "end":
		var d struct {
			Sent            *iperfSum `json:"sum_sent"`
			Received        *iperfSum `json:"sum_received"`
			SentReverse     *iperfSum `json:"sum_sent_bidir_reverse"`
			ReceivedReverse *iperfSum `json:"sum_received_bidir_reverse"`
		}
		if json.Unmarshal(raw.Data, &d) != nil {
			return agentapi.IperfEvent{}, false
		}
		ev := agentapi.IperfEvent{Type: "end"}
		for _, s := range []struct {
			sum      *iperfSum
			receiver bool
		}{{d.Sent, false}, {d.Received, true}, {d.SentReverse, false}, {d.ReceivedReverse, true}} {
			// A server knows only what it received of what the client
			// sent: the sender's sum is empty.
			if s.sum != nil && (s.receiver || s.sum.Bytes > 0) {
				ev.Sums = append(ev.Sums, s.sum.event(s.receiver))
			}
		}
		return ev, len(ev.Sums) > 0
	case "error":
		var msg string
		if json.Unmarshal(raw.Data, &msg) != nil || msg == "" {
			return agentapi.IperfEvent{}, false
		}
		return agentapi.IperfEvent{Type: "error", Error: msg}, true
	}
	return agentapi.IperfEvent{}, false
}
