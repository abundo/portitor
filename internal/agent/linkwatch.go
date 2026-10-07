// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// watchCarrier signals wake each time iface in the namespace gets a
// carrier (IFF_LOWER_UP), until ctx is done: a DHCP client then asks at
// once instead of after its backoff, at boot or when a cable is plugged
// in. It subscribes again when the subscription fails.
func watchCarrier(ctx context.Context, nsName, iface string, wake chan<- struct{}, log *slog.Logger) {
	for {
		err := subscribeCarrier(ctx, nsName, iface, wake)
		if ctx.Err() != nil {
			return
		}
		log.Warn("link events", "err", err)
		if !sleepCtx(ctx, 5*time.Second) {
			return
		}
		notify(wake) // a carrier may have come up meanwhile
	}
}

// carrierCame reports whether a link update with flags is iface getting
// its carrier, given what was known before (known false: the interface
// was missing).
func carrierCame(known, up bool, flags uint32) bool {
	return flags&unix.IFF_LOWER_UP != 0 && !(known && up)
}

func subscribeCarrier(ctx context.Context, nsName, iface string, wake chan<- struct{}) error {
	h, err := netlinkHandle(nsName)
	if err != nil {
		return err
	}
	defer h.Close()
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
	err = netlink.LinkSubscribeWithOptions(updates, done, opts)
	if opts.Namespace != nil {
		opts.Namespace.Close() // only needed to open the socket
	}
	if err != nil {
		return err
	}
	defer func() {
		close(done)
		for range updates { // the reader closes it when it stops
		}
	}()
	// The state now, looked up after subscribing so no change is missed.
	known, up := false, false
	if link, err := h.LinkByName(iface); err == nil {
		known, up = true, link.Attrs().RawFlags&unix.IFF_LOWER_UP != 0
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case u, ok := <-updates:
			if !ok {
				return errors.New("subscription closed")
			}
			if u.Link == nil || u.Link.Attrs().Name != iface {
				continue
			}
			if u.Header.Type == unix.RTM_DELLINK {
				known, up = false, false
				continue
			}
			if carrierCame(known, up, u.Flags) {
				notify(wake)
			}
			known, up = true, u.Flags&unix.IFF_LOWER_UP != 0
		}
	}
}
