// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/agentclient"
	"github.com/abundo/portitor/internal/dhcpd"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/render"
)

// The DHCP servers' leases go from the active host of an HA pair to its
// standby: a worker per instance long-polls its server's changes (the
// dhcpd control socket), posts them to the peer's agent (POST
// /v1/ha/dhcp, the pair's secret, over the HA link and else management),
// which applies them to its server, and reports the acknowledgement back,
// which releases the replies waiting for it (dhcpd/repl.go). A batch that
// doesn't arrive is followed by a snapshot. The agent passes leases
// through; it never parses a client's packet.

// replIdle is the pause of a worker with nothing to send to: this host
// isn't active, or the peer isn't heard.
const replIdle = 500 * time.Millisecond

type dhcpRepl struct {
	mu      sync.Mutex
	workers map[string]context.CancelFunc
}

// reconcileDHCPRepl runs a worker for each instance with a DHCP server on
// an HA pair, and stops the rest.
func (a *Agent) reconcileDHCPRepl(exp *fwconfig.Document) {
	want := map[string]string{}
	if exp.HA != nil && !a.cfg.DryRun {
		for i := range exp.Instances {
			in := &exp.Instances[i]
			if render.DHCPRunning(in) {
				want[in.Name] = a.cfg.Paths.Files(in).DHCPDSocket()
			}
		}
	}
	r := &a.repl
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.workers == nil {
		r.workers = map[string]context.CancelFunc{}
	}
	for name, stop := range r.workers {
		if _, ok := want[name]; !ok {
			stop()
			delete(r.workers, name)
		}
	}
	for name, sock := range want {
		if r.workers[name] == nil {
			ctx, cancel := context.WithCancel(context.Background())
			r.workers[name] = cancel
			go a.replicate(ctx, name, sock)
		}
	}
}

func (a *Agent) replicate(ctx context.Context, instance, sock string) {
	var epoch, seq uint64
	var lastErr string
	sleep := func(d time.Duration) {
		select {
		case <-ctx.Done():
		case <-time.After(d):
		}
	}
	for ctx.Err() == nil {
		cfg, term, clients := a.ha.replTarget()
		if cfg == nil {
			epoch = 0 // a snapshot first, once there is a standby
			sleep(replIdle)
			continue
		}
		qctx, cancel := context.WithTimeout(ctx, 8*time.Second)
		rep, err := dhcpd.Query(qctx, sock, dhcpd.Control{Op: "changes", Epoch: epoch, Seq: seq, WaitMS: 1000})
		cancel()
		if err != nil || rep.Changes == nil {
			sleep(time.Second)
			continue
		}
		ch := rep.Changes
		leases, _ := json.Marshal(ch.Leases)
		req := agentapi.HADHCPRequest{Instance: instance, Term: term, Snapshot: ch.Snapshot, Leases: leases}
		err = errors.New("no path to the peer")
		for _, c := range clients {
			pctx, cancel := context.WithTimeout(ctx, time.Second)
			_, err = c.HADHCP(pctx, req)
			cancel()
			if err == nil {
				break
			}
		}
		if err != nil {
			// The peer that just took over refuses them, as it should.
			if err.Error() != lastErr && !strings.Contains(err.Error(), "takes no leases") {
				slog.Warn("ha: DHCP leases not sent to the peer", "instance", instance, "err", err)
			}
			lastErr = err.Error()
			epoch = 0
			sleep(replIdle)
			continue
		}
		if lastErr != "" || ch.Snapshot {
			slog.Info("ha: DHCP leases sent to the peer", "instance", instance, "snapshot", ch.Snapshot, "leases", len(ch.Leases))
			lastErr = ""
		}
		actx, cancel := context.WithTimeout(ctx, time.Second)
		_, _ = dhcpd.Query(actx, sock, dhcpd.Control{Op: "acked", Seq: ch.Seq})
		cancel()
		epoch, seq = ch.Epoch, ch.Seq
	}
}

// replTarget is the pair's config, this host's term and clients for the
// peer's agent (the HA link first), while this host is active and hears
// its peer; else nil.
func (h *haManager) replTarget() (*fwconfig.HA, int64, []*agentclient.Client) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cfg == nil || !h.active || time.Since(h.peerSeen) >= haDeadAfter {
		return nil, 0, nil
	}
	var out []*agentclient.Client
	for _, url := range []string{h.cfg.PeerLink, h.cfg.Peer} {
		if url == "" {
			continue
		}
		if c, err := h.client(h.cfg, url); err == nil {
			out = append(out, c)
		}
	}
	return h.cfg, h.term, out
}

// takesLeases says whether this host takes its peer's leases sent at
// term: as a standby, from a peer no older than the newest term it has
// seen.
func (h *haManager) takesLeases(term int64) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	switch {
	case h.cfg == nil:
		return errors.New("not on an HA pair")
	case h.active:
		return errors.New("the active host takes no leases")
	case term < max(h.term, h.peer.Term):
		return fmt.Errorf("leases of term %d, older than %d", term, max(h.term, h.peer.Term))
	}
	return nil
}

// takeDHCPLeases applies the active peer's leases to the instance's DHCP
// server.
func (a *Agent) takeDHCPLeases(ctx context.Context, req agentapi.HADHCPRequest) (*agentapi.HADHCPReply, error) {
	if err := a.ha.takesLeases(req.Term); err != nil {
		return nil, err
	}
	a.mu.Lock()
	var sock string
	if a.applied != nil {
		for i := range a.applied.Instances {
			in := &a.applied.Instances[i]
			if in.Name == req.Instance && render.DHCPRunning(in) {
				sock = a.cfg.Paths.Files(in).DHCPDSocket()
			}
		}
	}
	a.mu.Unlock()
	if sock == "" {
		return nil, fmt.Errorf("instance %q runs no DHCP server here", req.Instance)
	}
	var leases []dhcpd.Lease
	if len(req.Leases) > 0 {
		if err := json.Unmarshal(req.Leases, &leases); err != nil {
			return nil, err
		}
	}
	rep, err := dhcpd.Query(ctx, sock, dhcpd.Control{Op: "apply", Leases: leases})
	if err != nil {
		return nil, err
	}
	return &agentapi.HADHCPReply{Applied: rep.Applied}, nil
}
