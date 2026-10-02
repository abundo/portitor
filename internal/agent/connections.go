// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"sync/atomic"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
	"golang.org/x/time/rate"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/fwconfig"
)

// connStreams counts the running connection streams
// (agentapi.ConnectionsMaxSessions).
var connStreams atomic.Int32

// handleConnections streams the instance's conntrack table as
// agentapi.ConnectionsSnapshots, one JSON line each, paced by a rate
// limiter to one per interval. The client disconnecting ends it.
func (a *Agent) handleConnections(w http.ResponseWriter, r *http.Request) {
	var req agentapi.ConnectionsRequest
	if !decode(w, r, &req) {
		return
	}
	if a.cfg.DryRun {
		writeError(w, http.StatusServiceUnavailable, errors.New("connections are not available in dry-run mode"))
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
	clampConnections(&req)
	h, err := conntrackHandle(in.NetnsName())
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Errorf("conntrack: %w", err))
		return
	}
	defer h.Close()
	if connStreams.Add(1) > agentapi.ConnectionsMaxSessions {
		connStreams.Add(-1)
		writeError(w, http.StatusTooManyRequests, fmt.Errorf("%d connection streams are already running", agentapi.ConnectionsMaxSessions))
		return
	}
	defer connStreams.Add(-1)
	slog.Info("connections stream started", "instance", req.Instance, "remote", r.RemoteAddr)
	defer slog.Info("connections stream ended", "instance", req.Instance)

	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{}) // the server's timeout is for requests
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	lim := rate.NewLimiter(rate.Every(time.Duration(req.IntervalMs)*time.Millisecond), 1)
	ctx := r.Context()
	for lim.Wait(ctx) == nil {
		snap := agentapi.ConnectionsSnapshot{Time: time.Now().UTC()}
		var flows []*netlink.ConntrackFlow
		for _, fam := range []netlink.InetFamily{unix.AF_INET, unix.AF_INET6} {
			f, err := h.ConntrackTableList(netlink.ConntrackTable, fam)
			if err != nil {
				snap.Error = err.Error()
				break
			}
			flows = append(flows, f...)
		}
		if snap.Error == "" {
			snap.Total, snap.Entries = connections(flows, req.Max)
		}
		if enc.Encode(snap) != nil || rc.Flush() != nil {
			break
		}
	}
}

// conntrackHandle opens a netfilter netlink socket in the namespace; ""
// is the root namespace (an instance that runs there).
func conntrackHandle(nsName string) (*netlink.Handle, error) {
	if nsName == "" {
		return netlink.NewHandle(unix.NETLINK_NETFILTER)
	}
	ns, err := netns.GetFromName(nsName)
	if err != nil {
		return nil, err
	}
	defer ns.Close()
	return netlink.NewHandleAt(ns, unix.NETLINK_NETFILTER)
}

func clampConnections(req *agentapi.ConnectionsRequest) {
	if req.IntervalMs <= 0 {
		req.IntervalMs = agentapi.ConnectionsDefaultIntervalMs
	}
	req.IntervalMs = max(req.IntervalMs, agentapi.ConnectionsMinIntervalMs)
	if req.Max <= 0 {
		req.Max = agentapi.ConnectionsDefaultMax
	}
	req.Max = min(req.Max, agentapi.ConnectionsMaxEntries)
}

// connections converts flows, largest (both directions' bytes) first,
// and returns how many there are and the first maxEntries.
func connections(flows []*netlink.ConntrackFlow, maxEntries int) (int, []agentapi.Connection) {
	size := func(f *netlink.ConntrackFlow) uint64 { return f.Forward.Bytes + f.Reverse.Bytes }
	slices.SortStableFunc(flows, func(a, b *netlink.ConntrackFlow) int { return cmp.Compare(size(b), size(a)) })
	out := make([]agentapi.Connection, 0, min(len(flows), maxEntries))
	for _, f := range flows[:min(len(flows), maxEntries)] {
		c := agentapi.Connection{
			Family:       "ipv4",
			Protocol:     protoName(f.Forward.Protocol),
			Src:          f.Forward.SrcIP.String(),
			Dst:          f.Forward.DstIP.String(),
			SrcPort:      f.Forward.SrcPort,
			DstPort:      f.Forward.DstPort,
			ReplySrc:     f.Reverse.SrcIP.String(),
			ReplyDst:     f.Reverse.DstIP.String(),
			ReplySrcPort: f.Reverse.SrcPort,
			ReplyDstPort: f.Reverse.DstPort,
			Packets:      f.Forward.Packets,
			Bytes:        f.Forward.Bytes,
			ReplyPackets: f.Reverse.Packets,
			ReplyBytes:   f.Reverse.Bytes,
			Mark:         f.Mark,
			Timeout:      f.TimeOut,
		}
		if f.FamilyType == unix.AF_INET6 {
			c.Family = "ipv6"
		}
		if t, ok := f.ProtoInfo.(*netlink.ProtoInfoTCP); ok {
			c.State = tcpState(t.State)
		}
		if f.TimeStart > 0 {
			c.Start = int64(f.TimeStart / uint64(time.Second))
		}
		out = append(out, c)
	}
	return len(flows), out
}

func protoName(p uint8) string {
	switch p {
	case unix.IPPROTO_TCP:
		return "tcp"
	case unix.IPPROTO_UDP:
		return "udp"
	case unix.IPPROTO_ICMP:
		return "icmp"
	case unix.IPPROTO_ICMPV6:
		return "icmpv6"
	case unix.IPPROTO_SCTP:
		return "sctp"
	case unix.IPPROTO_GRE:
		return "gre"
	}
	return fmt.Sprint(p)
}

var tcpStates = []string{"NONE", "SYN_SENT", "SYN_RECV", "ESTABLISHED", "FIN_WAIT", "CLOSE_WAIT", "LAST_ACK", "TIME_WAIT", "CLOSE", "SYN_SENT2"}

func tcpState(s uint8) string {
	if int(s) < len(tcpStates) {
		return tcpStates[s]
	}
	return fmt.Sprint(s)
}
