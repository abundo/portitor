// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package records

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"sort"
	"time"

	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/models"
)

// The deployments and the interfaces seen, in files in the data directory
// (deployments.jsonl, known-nics.json), with the other files of files.go.
//
// deployments.jsonl is an append-only log, one JSON object per line:
//
//	{"add": {...}}   a deployment (all its fields, the redacted document too)
//	{"set": {...}}   a change of a deployment's status, message and log
//	{"next": N}      the next id (first line of a compacted log)
//
// It is read whole at the first use and kept in memory, which the queries
// answer from. A last line cut short by a crash is ignored. PruneDeployments
// compacts it.
const (
	deploymentsFile = "deployments.jsonl"
	knownNICsFile   = "known-nics.json"
)

// depRec is a deployment in the log (Deployment hides its document).
type depRec struct {
	ID         uint              `json:"id"`
	CreatedAt  time.Time         `json:"created_at"`
	UpdatedAt  time.Time         `json:"updated_at"`
	FirewallID uint              `json:"firewall_id"`
	CommitID   int64             `json:"commit_id"`
	Generation int64             `json:"generation"`
	Username   string            `json:"username"`
	Status     string            `json:"status"`
	Message    string            `json:"message"`
	Document   string            `json:"document"`
	DocHash    string            `json:"doc_hash"`
	Log        string            `json:"log"`
	Instances  models.StringList `json:"instances"`
}

type depSet struct {
	ID        uint      `json:"id"`
	UpdatedAt time.Time `json:"updated_at"`
	Status    string    `json:"status"`
	Message   string    `json:"message"`
	Log       string    `json:"log"`
}

type depLine struct {
	Add  *depRec `json:"add,omitempty"`
	Set  *depSet `json:"set,omitempty"`
	Next *uint   `json:"next,omitempty"`
}

func toRec(d *models.Deployment) depRec {
	return depRec{ID: d.ID, CreatedAt: d.CreatedAt, UpdatedAt: d.UpdatedAt, FirewallID: d.FirewallID, CommitID: d.CommitID,
		Generation: d.Generation, Username: d.Username, Status: d.Status, Message: d.Message, Document: d.Document,
		DocHash: d.DocHash, Log: d.Log, Instances: d.Instances}
}

func fromRec(r depRec) models.Deployment {
	d := models.Deployment{FirewallID: r.FirewallID, CommitID: r.CommitID, Generation: r.Generation, Username: r.Username,
		Status: r.Status, Message: r.Message, Document: r.Document, DocHash: r.DocHash, Log: r.Log, Instances: r.Instances}
	d.ID, d.CreatedAt, d.UpdatedAt = r.ID, r.CreatedAt, r.UpdatedAt
	return d
}

// loadDeployments reads the log, under f.mu.
func (f *fileState) loadDeployments() error {
	if f.depsLoaded {
		return nil
	}
	f.deps, f.depNext = nil, 1
	if f.dir != "" {
		switch b, err := os.ReadFile(f.path(deploymentsFile)); {
		case err == nil:
			f.parseDeployments(b)
			f.depsLoaded = true
			return nil
		case !errors.Is(err, os.ErrNotExist):
			return err
		}
	}
	f.depsLoaded = true
	return f.rewriteDeployments()
}

func (f *fileState) parseDeployments(b []byte) {
	byID := map[uint]int{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 1<<20), 1<<28)
	for sc.Scan() {
		var l depLine
		if json.Unmarshal(sc.Bytes(), &l) != nil {
			continue // a line cut short
		}
		switch {
		case l.Next != nil:
			f.depNext = max(f.depNext, *l.Next)
		case l.Add != nil:
			byID[l.Add.ID] = len(f.deps)
			f.deps = append(f.deps, fromRec(*l.Add))
			f.depNext = max(f.depNext, l.Add.ID+1)
		case l.Set != nil:
			if i, ok := byID[l.Set.ID]; ok {
				d := &f.deps[i]
				d.Status, d.Message, d.Log, d.UpdatedAt = l.Set.Status, l.Set.Message, l.Set.Log, l.Set.UpdatedAt
			}
		}
	}
}

// appendDeployment writes a line to the log, under f.mu.
func (f *fileState) appendDeployment(l depLine) error {
	if f.dir == "" {
		return nil
	}
	b, err := json.Marshal(l)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(f.path(deploymentsFile), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(append(b, '\n')); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	f.wrote(deploymentsFile)
	return nil
}

// rewriteDeployments writes the whole log compacted, under f.mu.
func (f *fileState) rewriteDeployments() error {
	if f.dir == "" {
		return nil
	}
	b, err := f.encodeDeployments()
	if err != nil {
		return err
	}
	if err := datastore.WriteFile(f.path(deploymentsFile), b); err != nil {
		return err
	}
	f.wrote(deploymentsFile)
	return nil
}

// encodeDeployments is the whole log compacted, under f.mu.
func (f *fileState) encodeDeployments() ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	next := f.depNext
	if err := enc.Encode(depLine{Next: &next}); err != nil {
		return nil, err
	}
	for i := range f.deps {
		r := toRec(&f.deps[i])
		if err := enc.Encode(depLine{Add: &r}); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

func (g *Files) RecordDeployment(dep *models.Deployment) error {
	defer g.files.begin(true)()
	if err := g.files.loadDeployments(); err != nil {
		return err
	}
	now := time.Now()
	dep.ID, dep.CreatedAt, dep.UpdatedAt = g.files.depNext, now, now
	r := toRec(dep)
	if err := g.files.appendDeployment(depLine{Add: &r}); err != nil {
		dep.ID = 0
		return err
	}
	g.files.depNext++
	g.files.deps = append(g.files.deps, *dep)
	return nil
}

func (g *Files) UpdateDeployment(dep *models.Deployment) error {
	defer g.files.begin(true)()
	if err := g.files.loadDeployments(); err != nil {
		return err
	}
	i := slices.IndexFunc(g.files.deps, func(d models.Deployment) bool { return d.ID == dep.ID })
	if i < 0 {
		return ErrNotFound
	}
	dep.UpdatedAt = time.Now()
	s := depSet{ID: dep.ID, UpdatedAt: dep.UpdatedAt, Status: dep.Status, Message: dep.Message, Log: dep.Log}
	if err := g.files.appendDeployment(depLine{Set: &s}); err != nil {
		return err
	}
	d := &g.files.deps[i]
	d.Status, d.Message, d.Log, d.UpdatedAt = dep.Status, dep.Message, dep.Log, dep.UpdatedAt
	return nil
}

// newest is the deployments matching keep, newest commit first (by commit,
// then id), under f.mu.
func (f *fileState) newest(keep func(*models.Deployment) bool) []models.Deployment {
	var out []models.Deployment
	for i := range f.deps {
		if keep(&f.deps[i]) {
			out = append(out, f.deps[i])
		}
	}
	sort.SliceStable(out, func(a, b int) bool {
		if out[a].CommitID != out[b].CommitID {
			return out[a].CommitID > out[b].CommitID
		}
		return out[a].ID > out[b].ID
	})
	return out
}

func isLive(d *models.Deployment) bool {
	return d.Status == "applied" || d.Status == "pending" || d.Status == "confirmed"
}

func (g *Files) LatestDeployment(firewallID uint) (*models.Deployment, error) {
	defer g.files.begin(false)()
	if err := g.files.loadDeployments(); err != nil {
		return nil, err
	}
	out := g.files.newest(func(d *models.Deployment) bool { return d.FirewallID == firewallID })
	if len(out) == 0 {
		return nil, nil
	}
	return &out[0], nil
}

func (g *Files) LiveDeployment(firewallID uint) (*models.Deployment, error) {
	defer g.files.begin(false)()
	if err := g.files.loadDeployments(); err != nil {
		return nil, err
	}
	return g.files.live(firewallID), nil
}

func (f *fileState) live(firewallID uint) *models.Deployment {
	out := f.newest(func(d *models.Deployment) bool { return d.FirewallID == firewallID && isLive(d) })
	if len(out) == 0 {
		return nil
	}
	return &out[0]
}

// settled is the newest deployment the firewall runs for certain (applied
// or confirmed, not pending), under f.mu.
func (f *fileState) settled(firewallID uint) *models.Deployment {
	out := f.newest(func(d *models.Deployment) bool {
		return d.FirewallID == firewallID && (d.Status == "applied" || d.Status == "confirmed")
	})
	if len(out) == 0 {
		return nil
	}
	return &out[0]
}

func (g *Files) RecentDeployments(limit int) ([]models.Deployment, error) {
	defer g.files.begin(false)()
	if err := g.files.loadDeployments(); err != nil {
		return nil, err
	}
	out := slices.Clone(g.files.deps)
	slices.SortStableFunc(out, func(a, b models.Deployment) int { return int(b.ID) - int(a.ID) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	if out == nil {
		out = []models.Deployment{}
	}
	return out, nil
}

func (g *Files) LiveCommits(limit int) ([]int64, error) {
	defer g.files.begin(false)()
	if err := g.files.loadDeployments(); err != nil {
		return nil, err
	}
	seen := map[int64]bool{}
	var commits []int64
	for _, d := range g.files.newest(isLive) {
		if !seen[d.CommitID] {
			seen[d.CommitID] = true
			commits = append(commits, d.CommitID)
		}
	}
	if limit > 0 && len(commits) > limit {
		commits = commits[:limit]
	}
	return commits, nil
}

func (g *Files) PruneDeployments(keep int, olderThan time.Time) error {
	defer g.files.begin(true)()
	if err := g.files.loadDeployments(); err != nil {
		return err
	}
	// What a firewall needs stays, however old: the deployment it runs (a
	// pending one may be rolled back, so the newest settled one too, which
	// is what runs then), and its latest (a skipped one is caught up).
	stay := map[uint]bool{}
	for _, d := range g.files.deps {
		if live := g.files.live(d.FirewallID); live != nil {
			stay[live.ID] = true
		}
		if settled := g.files.settled(d.FirewallID); settled != nil {
			stay[settled.ID] = true
		}
		if latest := g.files.newest(func(o *models.Deployment) bool { return o.FirewallID == d.FirewallID }); len(latest) > 0 {
			stay[latest[0].ID] = true
		}
	}
	var drop map[uint]bool
	if keep > 0 && len(g.files.deps) > keep {
		ids := make([]uint, len(g.files.deps))
		for i, d := range g.files.deps {
			ids[i] = d.ID
		}
		slices.Sort(ids)
		drop = map[uint]bool{}
		for _, id := range ids[:len(ids)-keep] {
			drop[id] = true
		}
	}
	kept := g.files.deps[:0:0]
	for _, d := range g.files.deps {
		old := !olderThan.IsZero() && d.CreatedAt.Before(olderThan)
		if (drop[d.ID] || old) && !stay[d.ID] {
			continue
		}
		kept = append(kept, d)
	}
	if len(kept) == len(g.files.deps) {
		return nil
	}
	g.files.deps = kept
	return g.files.rewriteDeployments()
}

// Known NICs: firewall id -> names.

func (f *fileState) loadNICs() error {
	if f.nicsLoaded {
		return nil
	}
	f.nics = map[uint][]string{}
	if f.dir != "" {
		switch b, err := os.ReadFile(f.path(knownNICsFile)); {
		case err == nil:
			var raw map[uint][]string
			if err := json.Unmarshal(b, &raw); err != nil {
				return err
			}
			f.nics, f.nicsLoaded = raw, true
			return nil
		case !errors.Is(err, os.ErrNotExist):
			return err
		}
	}
	f.nicsLoaded = true
	return f.writeNICs()
}

func (f *fileState) writeNICs() error {
	if f.dir == "" {
		return nil
	}
	b, err := json.Marshal(f.nics)
	if err != nil {
		return err
	}
	if err := datastore.WriteFile(f.path(knownNICsFile), b); err != nil {
		return err
	}
	f.wrote(knownNICsFile)
	return nil
}

func (g *Files) KnownNICs(firewallID uint) ([]string, error) {
	defer g.files.begin(false)()
	if err := g.files.loadNICs(); err != nil {
		return nil, err
	}
	return slices.Clone(g.files.nics[firewallID]), nil
}

func (g *Files) RememberNICs(firewallID uint, names []string) error {
	defer g.files.begin(true)()
	if err := g.files.loadNICs(); err != nil {
		return err
	}
	have := g.files.nics[firewallID]
	changed := false
	for _, n := range names {
		if !slices.Contains(have, n) {
			have = append(have, n)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	g.files.nics[firewallID] = have
	return g.files.writeNICs()
}
