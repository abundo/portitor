// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/abundo/portitor/internal/buildinfo"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/iplist"
	"github.com/abundo/portitor/internal/render"
)

// ipListTimeout bounds one download.
const ipListTimeout = 2 * time.Minute

// ipLists holds the state of the applied document's IP lists. Each list
// has an elements file (render.Paths.IPListFile), which the rulesets
// include, and a .json file beside it recording what was downloaded
// (ipListMeta), so a restart loads the last download without fetching.
type ipLists struct {
	fetch func(ctx context.Context, l fwconfig.IPList) (*iplist.Result, error)

	mu    sync.Mutex
	lists map[string]*ipListState
	wg    sync.WaitGroup
	ctx   context.Context // cancelled by Stop
	stop  context.CancelFunc
}

type ipListState struct {
	cfg fwconfig.IPList
	// fetching: a download runs; again: the list changed during it, so
	// it downloads once more.
	fetching, again bool
	status          IPListStatus
}

type ipListMeta struct {
	// Hash is ipListHash of the configuration downloaded.
	Hash    string    `json:"hash"`
	Updated time.Time `json:"updated"`
	IPv4    int       `json:"ipv4"`
	IPv6    int       `json:"ipv6"`
	Skipped int       `json:"skipped"`
}

func newIPLists() *ipLists {
	client := iplist.NewClient(ipListTimeout)
	ctx, stop := context.WithCancel(context.Background())
	return &ipLists{
		fetch: func(ctx context.Context, l fwconfig.IPList) (*iplist.Result, error) {
			return iplist.Fetch(ctx, client, l, "portitor-agent/"+buildinfo.Version)
		},
		lists: map[string]*ipListState{},
		ctx:   ctx,
		stop:  stop,
	}
}

func (m *ipLists) Stop() {
	m.stop()
	m.wg.Wait()
}

// ipListHash identifies a list's configuration, so a changed URL or key
// downloads the list again.
func ipListHash(l fwconfig.IPList) string {
	b, _ := json.Marshal(l)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func (a *Agent) ipListMetaFile(name string) string {
	return strings.TrimSuffix(a.cfg.Paths.IPListFile(name), ".nft") + ".json"
}

// prepareIPLists makes sure every list of doc has an elements file before
// a ruleset that includes it is checked or loaded; a list not downloaded
// yet starts empty.
func (a *Agent) prepareIPLists(doc *fwconfig.Document) error {
	for _, l := range doc.IPLists {
		path := a.cfg.Paths.IPListFile(l.Name)
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			if err := atomicWrite(path, []byte(render.IPListElements(l.Name, nil)), 0o644); err != nil {
				return err
			}
		}
	}
	return nil
}

// reconcileIPLists takes the lists of a just applied document: it drops
// the state and files of removed lists, and downloads lists that were
// never downloaded or whose configuration changed. Caller holds a.mu.
func (a *Agent) reconcileIPLists(doc *fwconfig.Document) {
	m := a.lists
	m.mu.Lock()
	defer m.mu.Unlock()
	keep := map[string]bool{}
	for _, l := range doc.IPLists {
		keep[l.Name] = true
		st, ok := m.lists[l.Name]
		if !ok {
			st = &ipListState{status: IPListStatus{Name: l.Name, State: "pending"}}
			var meta ipListMeta
			if readJSON(a.ipListMetaFile(l.Name), &meta) == nil {
				st.setMeta(meta)
				if meta.Hash == ipListHash(l) {
					st.status.State = "ok"
				}
			}
			m.lists[l.Name] = st
		} else if st.cfg != l && !st.fetching {
			st.status.State = "pending"
		}
		changed := st.cfg != l
		st.cfg = l
		switch {
		case st.fetching:
			st.again = st.again || changed
		case st.status.State == "pending":
			a.startIPListFetch(st)
		}
	}
	for name := range m.lists {
		if !keep[name] {
			delete(m.lists, name)
			os.Remove(a.cfg.Paths.IPListFile(name))
			os.Remove(a.ipListMetaFile(name))
		}
	}
}

func (st *ipListState) setMeta(meta ipListMeta) {
	t := meta.Updated
	st.status.Updated = &t
	st.status.IPv4, st.status.IPv6, st.status.Skipped = meta.IPv4, meta.IPv6, meta.Skipped
}

// RefreshIPList starts downloading a list now.
func (a *Agent) RefreshIPList(name string) error {
	m := a.lists
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.lists[name]
	if !ok {
		return errNotFound{"no ip list " + name + " in the applied configuration"}
	}
	if st.fetching {
		return errBusy{"ip list " + name + " is being downloaded"}
	}
	a.startIPListFetch(st)
	return nil
}

// startIPListFetch downloads st's list in the background. Caller holds
// a.lists.mu.
func (a *Agent) startIPListFetch(st *ipListState) {
	st.fetching = true
	st.status.State = "fetching"
	a.lists.wg.Add(1)
	go func() {
		defer a.lists.wg.Done()
		_ = a.fetchIPList(a.lists.ctx, st)
	}()
}

// refreshIPList downloads a list and waits for it, for a task. It fails
// when the list is unknown or a download is already running.
func (a *Agent) refreshIPList(ctx context.Context, name string) error {
	m := a.lists
	m.mu.Lock()
	st, ok := m.lists[name]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("no ip list %s in the applied configuration", name)
	}
	if st.fetching {
		m.mu.Unlock()
		return fmt.Errorf("ip list %s is being downloaded already", name)
	}
	st.fetching = true
	st.status.State = "fetching"
	m.mu.Unlock()
	return a.fetchIPList(ctx, st)
}

// fetchIPList downloads st's list (st.fetching is set), writes its
// elements file and reloads its sets in every instance that uses it. The
// list is "ok" only once its sets are loaded.
func (a *Agent) fetchIPList(ctx context.Context, st *ipListState) error {
	m := a.lists
	m.mu.Lock()
	cfg := st.cfg
	m.mu.Unlock()
	log := slog.With("ip_list", cfg.Name)

	// The download has its own deadline; ctx must stay live for the
	// reload below.
	fetchCtx, cancel := context.WithTimeout(ctx, ipListTimeout)
	res, err := m.fetch(fetchCtx, cfg)
	cancel()
	now := time.Now()

	var meta ipListMeta
	if err == nil {
		meta = ipListMeta{Hash: ipListHash(cfg), Updated: now, IPv4: countFamily(res, true), IPv6: countFamily(res, false), Skipped: res.Skipped}
	}

	m.mu.Lock()
	// The list may have been removed by an apply meanwhile; then its
	// file must not come back.
	gone := m.lists[cfg.Name] != st
	written := false
	if err == nil && !gone {
		err = a.writeIPList(cfg.Name, res, meta)
		written = err == nil
	}
	m.mu.Unlock()

	// loadIPList takes a.mu, which is taken before m.mu, so it runs
	// without m.mu.
	var loadErr error
	if written {
		log.Info("ip list downloaded", "ipv4", meta.IPv4, "ipv6", meta.IPv6, "skipped", meta.Skipped)
		if loadErr = a.loadIPList(ctx, cfg.Name); loadErr != nil {
			err = fmt.Errorf("load: %w", loadErr)
		}
	}

	m.mu.Lock()
	st.fetching = false
	st.status.LastAttempt = &now
	gone = m.lists[cfg.Name] != st
	if !gone {
		if written {
			st.setMeta(meta)
		}
		if err != nil {
			st.status.State, st.status.LastError = "error", err.Error()
		} else {
			st.status.State, st.status.LastError = "ok", ""
		}
	}
	again := st.again && !gone
	st.again = false
	if again {
		a.startIPListFetch(st)
	}
	m.mu.Unlock()

	switch {
	case gone:
		return nil
	case loadErr != nil:
		log.Error("ip list load failed", "err", loadErr)
	case err != nil:
		log.Warn("ip list download failed", "err", err)
	}
	return err
}

func (a *Agent) writeIPList(name string, res *iplist.Result, meta ipListMeta) error {
	if err := atomicWrite(a.cfg.Paths.IPListFile(name), []byte(render.IPListElements(name, res.Prefixes)), 0o644); err != nil {
		return err
	}
	return writeJSON(a.ipListMetaFile(name), meta, 0o644)
}

// loadIPList replaces the elements of a list's sets with its elements
// file, in every instance whose rules use it.
func (a *Agent) loadIPList(ctx context.Context, name string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	defer a.log.Take()
	if a.applied == nil {
		return nil
	}
	var errs []error
	for i := range a.applied.Instances {
		in := &a.applied.Instances[i]
		if !slices.Contains(in.UsedIPLists(), name) {
			continue
		}
		c := command{Netns: in.NetnsName(), Name: "nft", Args: []string{"-f", "-"}, Stdin: []byte(render.IPListReload(name, a.cfg.Paths))}
		if err := a.do(ctx, c); err != nil {
			errs = append(errs, fmt.Errorf("instance %s: %w", in.Name, err))
		}
	}
	return errors.Join(errs...)
}

func countFamily(res *iplist.Result, v4 bool) int {
	n := 0
	for _, p := range res.Prefixes {
		if p.Addr().Is4() == v4 {
			n++
		}
	}
	return n
}

// Status returns every list's state, by name.
func (m *ipLists) Status() []IPListStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]IPListStatus, 0, len(m.lists))
	for _, st := range m.lists {
		out = append(out, st.status)
	}
	slices.SortFunc(out, func(a, b IPListStatus) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// errNotFound and errBusy map to 404 and 409 in the API.
type errNotFound struct{ msg string }

func (e errNotFound) Error() string { return e.msg }

type errBusy struct{ msg string }

func (e errBusy) Error() string { return e.msg }
