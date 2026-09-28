// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"cmp"
	"context"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/abundo/portitor/internal/agentapi"
)

// Logs keeps the agent's latest log records for the GUI's log panel.
var Logs = NewLogRing(2000)

// LogRing is a fixed-size buffer of log records.
type LogRing struct {
	*ring[agentapi.LogEntry]
}

func NewLogRing(size int) *LogRing {
	return &LogRing{newRing(size, func(e *agentapi.LogEntry) *int64 { return &e.ID })}
}

// ring is a fixed-size buffer of entries that get increasing ids as they
// are added; id points into an entry at its id field.
type ring[T any] struct {
	mu      sync.Mutex
	entries []T
	size    int
	nextID  int64
	id      func(*T) *int64
}

func newRing[T any](size int, id func(*T) *int64) *ring[T] {
	// Start at the clock so ids keep increasing over a restart, and a
	// client's "after" from before it doesn't hide the new entries.
	return &ring[T]{size: size, nextID: time.Now().UnixMicro(), id: id}
}

func (r *ring[T]) add(e T) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.nextID++
	*r.id(&e) = r.nextID
	if len(r.entries) >= r.size {
		r.entries = slices.Delete(r.entries, 0, len(r.entries)-r.size+1)
	}
	r.entries = append(r.entries, e)
}

// After returns the entries with an id above after. An id beyond the
// newest one comes from before a restart with a clock that went back,
// so it returns everything.
func (r *ring[T]) After(after int64) []T {
	r.mu.Lock()
	defer r.mu.Unlock()
	if after > r.nextID {
		after = 0
	}
	i, _ := slices.BinarySearchFunc(r.entries, after+1, func(e T, id int64) int {
		return cmp.Compare(*r.id(&e), id)
	})
	return slices.Clone(r.entries[i:])
}

// Handler wraps next so that every record it handles is also kept here.
func (r *LogRing) Handler(next slog.Handler) slog.Handler {
	return &ringHandler{ring: r, next: next}
}

type ringHandler struct {
	ring   *LogRing
	next   slog.Handler
	attrs  []slog.Attr
	prefix string // open groups, "a.b."
}

func (h *ringHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.next.Enabled(ctx, l)
}

func (h *ringHandler) Handle(ctx context.Context, rec slog.Record) error {
	e := agentapi.LogEntry{Time: rec.Time, Level: rec.Level.String(), Message: rec.Message}
	attrs := map[string]string{}
	for _, a := range h.attrs {
		flatten(attrs, "", a)
	}
	rec.Attrs(func(a slog.Attr) bool {
		flatten(attrs, h.prefix, a)
		return true
	})
	if len(attrs) > 0 {
		e.Attrs = attrs
	}
	h.ring.add(e)
	return h.next.Handle(ctx, rec)
}

func (h *ringHandler) WithAttrs(as []slog.Attr) slog.Handler {
	c := *h
	c.next = h.next.WithAttrs(as)
	c.attrs = slices.Clone(h.attrs)
	for _, a := range as {
		c.attrs = append(c.attrs, slog.Attr{Key: h.prefix + a.Key, Value: a.Value})
	}
	return &c
}

func (h *ringHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	c := *h
	c.next = h.next.WithGroup(name)
	c.prefix = h.prefix + name + "."
	return &c
}

func flatten(out map[string]string, prefix string, a slog.Attr) {
	v := a.Value.Resolve()
	if v.Kind() == slog.KindGroup {
		p := prefix
		if a.Key != "" {
			p += a.Key + "."
		}
		for _, g := range v.Group() {
			flatten(out, p, g)
		}
		return
	}
	if a.Key == "" {
		return
	}
	out[prefix+a.Key] = v.String()
}
