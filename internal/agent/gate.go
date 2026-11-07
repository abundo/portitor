// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"sync"

	"github.com/abundo/portitor/internal/render"
)

// gate holds the namespaces' gates (render.Gate): whether an HA host's
// physical traffic interfaces are open, apart from an apply, which may run
// for minutes: closing must not wait for one, so gate has its own lock and
// Agent.mu is never taken here.
//
// On Debian trixie's 6.12 a netdev chain holds a device only from when it
// is loaded: one deleted and made again, or moved out of the namespace and
// back, is no longer gated, and a gate naming a missing device is refused.
// So apply loads the gate after moving a device and before it comes up,
// and check finds a device a closed gate lost. `nft -j list table` shows
// only the devices a chain holds (kernel 6.12, nft 1.1.3).
type gate struct {
	mu   sync.Mutex
	run  Runner
	file string
	open bool
	// devs are the devices to gate, by namespace.
	devs map[string][]string
	// down are those that stay down, not enabled in the document.
	down map[string]bool
}

func newGate(run Runner, file string) *gate {
	g := &gate{run: run, file: file, devs: map[string][]string{}, down: map[string]bool{}}
	// A gate left by an earlier run: this host may have left its pair
	// since, and it closes at start until it decides otherwise.
	_ = readJSON(file, &g.devs)
	return g
}

// load replaces the namespace's gate, without the devices that aren't
// there if the kernel refuses to name them. g.mu held.
func (g *gate) load(ctx context.Context, ns string) error {
	devs := g.devs[ns]
	_, err := g.run.RunInput(ctx, ns, []byte(render.Gate(devs, g.open)), "nft", "-f", "-")
	if err == nil {
		return nil
	}
	have, lerr := g.present(ctx, ns, devs)
	if lerr != nil || len(have) == len(devs) {
		return err
	}
	_, err = g.run.RunInput(ctx, ns, []byte(render.Gate(have, g.open)), "nft", "-f", "-")
	return err
}

// linkMap is `ip -j link show` by device.
func linkMap(out []byte) (map[string]ipLink, error) {
	list, err := parseLinks(out)
	if err != nil {
		return nil, err
	}
	m := make(map[string]ipLink, len(list))
	for _, l := range list {
		m[l.Ifname] = l
	}
	return m, nil
}

// present are those of devs that exist in the namespace.
func (g *gate) present(ctx context.Context, ns string, devs []string) ([]string, error) {
	out, err := g.run.Run(ctx, ns, "ip", "-j", "link", "show")
	if err != nil {
		return nil, err
	}
	links, err := linkMap(out)
	if err != nil {
		return nil, err
	}
	var have []string
	for _, d := range devs {
		if _, ok := links[d]; ok {
			have = append(have, d)
		}
	}
	return have, nil
}

// set is what apply calls after moving a namespace's devices and before
// they come up: it loads the namespace's gate for devs, in its state.
// down are the devices of those that the document leaves down.
func (g *gate) set(ctx context.Context, ns string, devs, down []string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.devs[ns] = slices.Clone(devs)
	for _, d := range devs {
		g.down[d] = slices.Contains(down, d)
	}
	g.save()
	return g.load(ctx, ns)
}

// remove takes the gate out of a namespace that no longer has one (it is
// gone with the namespace when that is deleted).
func (g *gate) remove(ctx context.Context, ns string, exists bool) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, ok := g.devs[ns]; !ok {
		return nil
	}
	delete(g.devs, ns)
	g.save()
	// A host that left its pair starts closed if it joins one again.
	if len(g.devs) == 0 {
		g.open = false
	}
	if !exists {
		return nil
	}
	_, err := g.run.RunInput(ctx, ns, []byte(render.Gate(nil, false)), "nft", "-f", "-")
	return err
}

// namespaces are those with a gate.
// gated says whether the namespace's gate names the device.
func (g *gate) gated(ns, dev string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return slices.Contains(g.devs[ns], dev)
}

func (g *gate) namespaces() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return slices.Sorted(maps.Keys(g.devs))
}

func (g *gate) save() {
	if err := writeJSON(g.file, g.devs, 0o644); err != nil {
		slog.Error("ha: gate state", "err", err)
	}
}

// setOpen opens or closes every namespace's gate. When a gate can't be
// closed, its devices are set down instead: a host must close.
func (g *gate) setOpen(ctx context.Context, open bool) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.open = open
	var errs []error
	for ns, devs := range g.devs {
		err := g.load(ctx, ns)
		if err == nil {
			continue
		}
		errs = append(errs, fmt.Errorf("namespace %q: %w", ns, err))
		if open {
			continue
		}
		for _, d := range devs {
			if _, derr := g.run.Run(ctx, ns, "ip", "link", "set", "dev", d, "down"); derr != nil {
				errs = append(errs, derr)
			}
		}
	}
	return errors.Join(errs...)
}

func (g *gate) isOpen() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.open
}

// gateChains is `nft -j list table`'s output as far as it matters: a
// chain's dev is one name, a list of them, or missing.
type gateChains struct {
	Nftables []struct {
		Chain *struct {
			Dev json.RawMessage `json:"dev"`
		} `json:"chain"`
	} `json:"nftables"`
}

// gateHeld parses the devices that both chains hold. A device must be in
// each: a gate on one direction alone doesn't close it.
func gateHeld(out []byte) (map[string]bool, error) {
	var t gateChains
	if err := json.Unmarshal(out, &t); err != nil {
		return nil, err
	}
	count := map[string]int{}
	chains := 0
	for _, o := range t.Nftables {
		if o.Chain == nil {
			continue
		}
		chains++
		var one string
		var many []string
		switch {
		case len(o.Chain.Dev) == 0:
		case json.Unmarshal(o.Chain.Dev, &one) == nil:
			many = []string{one}
		default:
			if err := json.Unmarshal(o.Chain.Dev, &many); err != nil {
				return nil, err
			}
		}
		for _, d := range many {
			count[d]++
		}
	}
	held := map[string]bool{}
	for d, n := range count {
		if n == chains {
			held[d] = true
		}
	}
	return held, nil
}

// check makes sure a closed gate holds every device that exists: one it
// lost is set down at once, the gate loaded again, and it comes up as the
// document has it, not as it was: a device that moved or was made again is
// down, and a standby must not take over with a dead interface. It returns
// the devices it found loose.
func (g *gate) check(ctx context.Context) ([]string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.open {
		return nil, nil
	}
	var loose []string
	var errs []error
	for ns, devs := range g.devs {
		out, err := g.run.Run(ctx, ns, "nft", "-j", "list", "table", "netdev", render.GateTable)
		var held map[string]bool
		if err == nil {
			held, err = gateHeld(out)
		}
		if err != nil {
			// No table to read: treat every device as loose.
			held, errs = map[string]bool{}, append(errs, fmt.Errorf("namespace %q: %w", ns, err))
		}
		out, err = g.run.Run(ctx, ns, "ip", "-j", "link", "show")
		if err != nil {
			errs = append(errs, err)
			continue
		}
		links, err := linkMap(out)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		var lost []string
		for _, d := range devs {
			if _, ok := links[d]; ok && !held[d] {
				lost = append(lost, d)
			}
		}
		if len(lost) == 0 {
			continue
		}
		loose = append(loose, lost...)
		for _, d := range lost {
			if _, err := g.run.Run(ctx, ns, "ip", "link", "set", "dev", d, "down"); err != nil {
				errs = append(errs, err)
			}
		}
		if err := g.load(ctx, ns); err != nil {
			errs = append(errs, err)
			continue
		}
		for _, d := range lost {
			if !g.down[d] {
				if _, err := g.run.Run(ctx, ns, "ip", "link", "set", "dev", d, "up"); err != nil {
					errs = append(errs, err)
				}
			}
		}
	}
	return loose, errors.Join(errs...)
}
