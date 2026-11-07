// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

// A closed gate on kernel 6.12 doesn't hold a device made again or moved
// out of its namespace and back (gate.go). Apply loads the gate around its
// own changes; for the rest (a driver reset, a hand-made change) the agent
// watches the links of each gated namespace and checks the gate at once on
// any event of a gated device, so the window is the time to run the check,
// not haGateCheck. The poll stays, for a watch that fails.

// watchGate keeps a link watch on each gated namespace, until ctx is done.
func (h *haManager) watchGate(ctx context.Context) {
	watching := map[string]context.CancelFunc{}
	defer func() {
		for _, stop := range watching {
			stop()
		}
	}()
	t := time.NewTicker(haGateCheck)
	defer t.Stop()
	for {
		want := h.gate.namespaces()
		for ns, stop := range watching {
			if !slices.Contains(want, ns) {
				stop()
				delete(watching, ns)
			}
		}
		for _, ns := range want {
			if watching[ns] == nil {
				wctx, cancel := context.WithCancel(ctx)
				watching[ns] = cancel
				go h.watchNamespace(wctx, ns)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (h *haManager) watchNamespace(ctx context.Context, ns string) {
	for {
		err := subscribeLinks(ctx, ns, func(name string) {
			if h.gate.gated(ns, name) {
				notify(h.gateWake)
			}
		})
		if ctx.Err() != nil {
			return
		}
		slog.Warn("ha: gate link watch", "namespace", ns, "err", err)
		if !sleepCtx(ctx, 5*time.Second) {
			return
		}
		notify(h.gateWake)
	}
}

// subscribeLinks calls fn with the name of each link in the namespace that
// is added, changed, moved in or removed, until ctx is done.
func subscribeLinks(ctx context.Context, nsName string, fn func(name string)) error {
	var opts netlink.LinkSubscribeOptions
	if nsName != "" {
		ns, err := netns.GetFromName(nsName)
		if err != nil {
			return err
		}
		opts.Namespace = &ns
	}
	updates := make(chan netlink.LinkUpdate)
	done := make(chan struct{})
	err := netlink.LinkSubscribeWithOptions(updates, done, opts)
	if opts.Namespace != nil {
		opts.Namespace.Close()
	}
	if err != nil {
		return err
	}
	defer func() {
		close(done)
		for range updates {
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return nil
		case u, ok := <-updates:
			if !ok {
				return errors.New("subscription closed")
			}
			if u.Link != nil {
				fn(u.Link.Attrs().Name)
			}
		}
	}
}
