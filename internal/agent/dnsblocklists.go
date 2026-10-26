// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/abundo/portitor/internal/buildinfo"
	"github.com/abundo/portitor/internal/dnsblocklist"
	"github.com/abundo/portitor/internal/fwconfig"
)

const (
	// dnsBlocklistTimeout bounds one download of a blocklist, all its
	// URLs (Hagezi's full TIF list is some 100 MB).
	dnsBlocklistTimeout = 10 * time.Minute
	// dnsBlocklistRetry is the wait after a failed download, unless the
	// list's refresh is sooner.
	dnsBlocklistRetry = 15 * time.Minute
)

// dnsBlocklists keeps the applied document's DNS blocklists current. Each
// has a zone file in its instance's InstanceFiles.RPZDir, which named.conf
// names (render.Paths.RPZFile) and which starts empty (prepareDNSBlocklists),
// and a .json file under state_dir recording the last download
// (dnsBlocklistMeta), so a restart keeps the list and its schedule. A
// list is downloaded on apply when it never was or its URLs or key
// changed, and then every Refresh minutes, with conditional requests.
type dnsBlocklists struct {
	fetch func(ctx context.Context, b fwconfig.DNSBlocklist, prev []dnsblocklist.Validator, tmpDir string, w io.Writer) (*dnsblocklist.Result, error)

	mu    sync.Mutex
	lists map[string]*dnsBlocklistState // by dnsBlocklistKey
	wg    sync.WaitGroup
	ctx   context.Context // cancelled by Stop
	stop  context.CancelFunc
}

type dnsBlocklistState struct {
	instance string
	cfg      fwconfig.DNSBlocklist
	// zone is the list's zone file; unit the instance's named, reloaded
	// when it changes.
	zone, unit string
	// fetching: a download runs; again: the URLs or key changed during
	// it, so it downloads once more.
	fetching, again bool
	timer           *time.Timer
	meta            dnsBlocklistMeta
	status          DNSBlocklistStatus
}

type dnsBlocklistMeta struct {
	// Hash is dnsBlocklistHash of the configuration downloaded.
	Hash       string                   `json:"hash"`
	Updated    time.Time                `json:"updated"`
	Changed    time.Time                `json:"changed"`
	Names      int                      `json:"names"`
	Skipped    int                      `json:"skipped"`
	Validators []dnsblocklist.Validator `json:"validators,omitempty"`
}

func newDNSBlocklists() *dnsBlocklists {
	client := dnsblocklist.NewClient(dnsBlocklistTimeout)
	ctx, stop := context.WithCancel(context.Background())
	return &dnsBlocklists{
		fetch: func(ctx context.Context, b fwconfig.DNSBlocklist, prev []dnsblocklist.Validator, tmpDir string, w io.Writer) (*dnsblocklist.Result, error) {
			return dnsblocklist.Fetch(ctx, client, b, prev, "portitor-agent/"+buildinfo.Version, tmpDir, w)
		},
		lists: map[string]*dnsBlocklistState{},
		ctx:   ctx,
		stop:  stop,
	}
}

func (m *dnsBlocklists) Stop() {
	m.stop()
	m.mu.Lock()
	for _, st := range m.lists {
		if st.timer != nil {
			st.timer.Stop()
		}
	}
	m.mu.Unlock()
	m.wg.Wait()
}

func dnsBlocklistKey(instance, name string) string { return instance + "/" + name }

// dnsBlocklistHash identifies what a list downloads: its URLs and key.
func dnsBlocklistHash(b fwconfig.DNSBlocklist) string {
	data, _ := json.Marshal([]any{b.URLs, b.Key})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func (a *Agent) dnsBlocklistMetaDir(instance string) string {
	return filepath.Join(a.cfg.Paths.StateDir, "dnsblocklists", instance)
}

// dnsBlocklistZoneDir is where an instance's zone files go: named's
// directory, or, in a dry run, the agent's state.
func (a *Agent) dnsBlocklistZoneDir(in *fwconfig.Instance) string {
	if a.cfg.DryRun {
		return a.dnsBlocklistMetaDir(in.Name)
	}
	return a.cfg.Paths.Files(in).RPZDir
}

// prepareDNSBlocklists makes sure each blocklist of in has a zone file
// before named loads it: a list not downloaded yet starts empty.
func (a *Agent) prepareDNSBlocklists(in *fwconfig.Instance) error {
	if len(in.DNS.Blocklists) == 0 {
		return nil
	}
	dir := a.dnsBlocklistZoneDir(in)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, b := range in.DNS.Blocklists {
		var empty strings.Builder
		_ = dnsblocklist.WriteHeader(&empty, b.Name, 1)
		ensureFile(filepath.Join(dir, b.Name+".db"), empty.String())
	}
	return nil
}

// reconcileDNSBlocklists takes the blocklists of a just applied document:
// it drops the state and files of removed lists, downloads new lists and
// lists whose URLs or key changed, and schedules the others. Caller holds
// a.mu.
func (a *Agent) reconcileDNSBlocklists(doc *fwconfig.Document) {
	m := a.blocklists
	m.mu.Lock()
	defer m.mu.Unlock()
	keep := map[string]bool{}
	for i := range doc.Instances {
		in := &doc.Instances[i]
		var lists []fwconfig.DNSBlocklist
		if in.DNS.Enabled {
			lists = in.DNS.Blocklists
		}
		names := map[string]bool{}
		for _, b := range lists {
			key := dnsBlocklistKey(in.Name, b.Name)
			keep[key], names[b.Name] = true, true
			st, ok := m.lists[key]
			if !ok {
				st = &dnsBlocklistState{instance: in.Name, status: DNSBlocklistStatus{Instance: in.Name, Name: b.Name, State: "pending"}}
				if readJSON(filepath.Join(a.dnsBlocklistMetaDir(in.Name), b.Name+".json"), &st.meta) == nil {
					st.setMeta()
				}
				m.lists[key] = st
			}
			st.cfg = b
			st.zone = filepath.Join(a.dnsBlocklistZoneDir(in), b.Name+".db")
			st.unit = a.cfg.Units.Named(in)
			current := st.meta.Hash == dnsBlocklistHash(b)
			switch {
			case st.fetching:
				st.again = st.again || !current
			case !current:
				st.status.State = "pending"
				a.scheduleDNSBlocklist(st, 0)
			default:
				if st.status.State == "pending" {
					st.status.State = "ok"
				}
				a.scheduleDNSBlocklist(st, time.Until(st.meta.Updated.Add(time.Duration(b.RefreshMinutes())*time.Minute)))
			}
		}
		// Files of lists gone, also of those removed while the agent was
		// not running.
		a.removeStaleBlocklistFiles(a.dnsBlocklistZoneDir(in), ".db", names)
		a.removeStaleBlocklistFiles(a.dnsBlocklistMetaDir(in.Name), ".json", names)
	}
	for key, st := range m.lists {
		if !keep[key] {
			if st.timer != nil {
				st.timer.Stop()
			}
			delete(m.lists, key)
		}
	}
}

func (a *Agent) removeStaleBlocklistFiles(dir, ext string, keep map[string]bool) {
	files, _ := filepath.Glob(filepath.Join(dir, "*"+ext))
	for _, f := range files {
		if !keep[strings.TrimSuffix(filepath.Base(f), ext)] {
			os.Remove(f)
		}
	}
}

func (st *dnsBlocklistState) setMeta() {
	if st.meta.Updated.IsZero() {
		return
	}
	u, c := st.meta.Updated, st.meta.Changed
	st.status.Updated, st.status.Changed = &u, &c
	st.status.Names, st.status.Skipped = st.meta.Names, st.meta.Skipped
}

// scheduleDNSBlocklist downloads st's list after d. Caller holds
// a.blocklists.mu.
func (a *Agent) scheduleDNSBlocklist(st *dnsBlocklistState, d time.Duration) {
	m := a.blocklists
	if st.timer != nil {
		st.timer.Stop()
	}
	d = max(d, 0)
	next := time.Now().Add(d)
	st.status.Next = &next
	key := dnsBlocklistKey(st.instance, st.cfg.Name)
	st.timer = time.AfterFunc(d, func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.ctx.Err() == nil && m.lists[key] == st && !st.fetching {
			a.startDNSBlocklistFetch(st)
		}
	})
}

// RefreshDNSBlocklist starts downloading an instance's blocklist now.
func (a *Agent) RefreshDNSBlocklist(instance, name string) error {
	m := a.blocklists
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.lists[dnsBlocklistKey(instance, name)]
	if !ok {
		return errNotFound{fmt.Sprintf("no dns blocklist %s in instance %s of the applied configuration", name, instance)}
	}
	if st.fetching {
		return errBusy{"dns blocklist " + name + " is being downloaded"}
	}
	a.startDNSBlocklistFetch(st)
	return nil
}

// startDNSBlocklistFetch downloads st's list in the background. Caller
// holds a.blocklists.mu.
func (a *Agent) startDNSBlocklistFetch(st *dnsBlocklistState) {
	if st.timer != nil {
		st.timer.Stop()
	}
	st.fetching = true
	st.status.State, st.status.Next = "fetching", nil
	a.blocklists.wg.Add(1)
	go func() {
		defer a.blocklists.wg.Done()
		a.fetchDNSBlocklist(a.blocklists.ctx, st)
	}()
}

// fetchDNSBlocklist downloads st's list (st.fetching is set) into its zone
// file, reloads named when it changed, and schedules the next download.
func (a *Agent) fetchDNSBlocklist(ctx context.Context, st *dnsBlocklistState) {
	m := a.blocklists
	m.mu.Lock()
	cfg, zone, unit := st.cfg, st.zone, st.unit
	hash := dnsBlocklistHash(cfg)
	var prev []dnsblocklist.Validator
	if st.meta.Hash == hash {
		prev = st.meta.Validators
	}
	m.mu.Unlock()
	log := slog.With("instance", st.instance, "dns_blocklist", cfg.Name)

	res, tmp, err := a.downloadDNSBlocklist(ctx, cfg, prev, zone)
	now := time.Now()

	m.mu.Lock()
	// The list may have been removed by an apply meanwhile; then its
	// file must not come back.
	key := dnsBlocklistKey(st.instance, cfg.Name)
	gone := m.lists[key] != st
	changed := false
	if err == nil && !gone {
		meta := st.meta
		meta.Hash, meta.Updated, meta.Validators = hash, now, res.Validators
		if !res.NotModified {
			meta.Changed, meta.Names, meta.Skipped = now, res.Names, res.Skipped
			if err = os.Rename(tmp, zone); err == nil {
				tmp, changed = "", true
			}
		}
		if err == nil {
			err = writeJSON(filepath.Join(a.dnsBlocklistMetaDir(st.instance), cfg.Name+".json"), meta, 0o600)
			st.meta = meta
			st.setMeta()
		}
	}
	if tmp != "" {
		os.Remove(tmp)
	}
	m.mu.Unlock()

	// reloadNamed takes a.mu, which is taken before m.mu, so it runs
	// without m.mu.
	var loadErr error
	if changed {
		log.Info("dns blocklist downloaded", "names", res.Names, "skipped", res.Skipped)
		if loadErr = a.reloadNamed(ctx, st.instance, cfg.Name, unit); loadErr != nil {
			err = fmt.Errorf("reload named: %w", loadErr)
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	st.fetching = false
	st.status.LastAttempt = &now
	if m.lists[key] != st || ctx.Err() != nil {
		return
	}
	next := time.Duration(st.cfg.RefreshMinutes()) * time.Minute
	if err != nil {
		st.status.State, st.status.LastError = "error", err.Error()
		next = min(next, dnsBlocklistRetry)
		log.Warn("dns blocklist download failed", "err", err)
	} else {
		st.status.State, st.status.LastError = "ok", ""
	}
	if st.again {
		st.again = false
		a.startDNSBlocklistFetch(st)
		return
	}
	a.scheduleDNSBlocklist(st, next)
}

// downloadDNSBlocklist writes a zone file of cfg's names beside zone and
// returns its path, which is "" when nothing changed or on error.
func (a *Agent) downloadDNSBlocklist(ctx context.Context, cfg fwconfig.DNSBlocklist, prev []dnsblocklist.Validator, zone string) (*dnsblocklist.Result, string, error) {
	ctx, cancel := context.WithTimeout(ctx, dnsBlocklistTimeout)
	defer cancel()
	if err := os.MkdirAll(filepath.Dir(zone), 0o755); err != nil {
		return nil, "", err
	}
	f, err := os.CreateTemp(filepath.Dir(zone), "."+cfg.Name+".tmp-")
	if err != nil {
		return nil, "", err
	}
	keep := false
	defer func() {
		f.Close()
		if !keep {
			os.Remove(f.Name())
		}
	}()
	// The serial is the time: a reload sees a new one.
	if err := dnsblocklist.WriteHeader(f, cfg.Name, uint32(time.Now().Unix())); err != nil {
		return nil, "", err
	}
	res, err := a.blocklists.fetch(ctx, cfg, prev, a.cfg.Paths.StateDir, f)
	if err != nil {
		return nil, "", err
	}
	if res.NotModified {
		return res, "", nil
	}
	// named reads it as its own user.
	if err := f.Chmod(0o644); err != nil {
		return nil, "", err
	}
	if err := f.Close(); err != nil {
		return nil, "", err
	}
	keep = true
	return res, f.Name(), nil
}

// reloadNamed has an instance's named load a blocklist's new zone file,
// if the applied document still has the list and named runs.
func (a *Agent) reloadNamed(ctx context.Context, instance, name, unit string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	defer a.log.Take()
	if a.applied == nil {
		return nil
	}
	for i := range a.applied.Instances {
		in := &a.applied.Instances[i]
		if in.Name == instance && in.DNS.Enabled && slices.ContainsFunc(in.DNS.Blocklists, func(b fwconfig.DNSBlocklist) bool { return b.Name == name }) {
			return a.do(ctx, command{Name: "systemctl", Args: []string{"try-reload-or-restart", unit}})
		}
	}
	return nil
}

// Status returns every blocklist's state, by instance and name.
func (m *dnsBlocklists) Status() []DNSBlocklistStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]DNSBlocklistStatus, 0, len(m.lists))
	for _, st := range m.lists {
		out = append(out, st.status)
	}
	slices.SortFunc(out, func(a, b DNSBlocklistStatus) int {
		return strings.Compare(dnsBlocklistKey(a.Instance, a.Name), dnsBlocklistKey(b.Instance, b.Name))
	})
	return out
}
