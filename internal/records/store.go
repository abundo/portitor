// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package records

import (
	"encoding/json"
	"errors"

	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/datastore/sqlmap"
)

// Files is what portitor-config keeps besides the configuration tree, in
// files in its data directory (files.go, deploylog.go, sessions.go). The
// users, roles, directory and firewalls are the tree's: web's treeRecords
// answers them, on top of this.
type Files struct {
	files fileState
}

// NewFiles keeps its files in dir ("": in memory).
func NewFiles(dir string) *Files {
	f := &Files{}
	f.files.dir = dir
	return f
}

func (g *Files) Own() (Own, error) {
	defer g.files.begin()()
	if err := g.files.loadState(); err != nil {
		return Own{}, err
	}
	if err := g.files.loadDeployments(); err != nil {
		return Own{}, err
	}
	// The counter is the highest number given anywhere it is kept.
	last := max(g.files.st.LastCommit, g.files.lastDeployedCommit())
	for _, d := range g.files.deps {
		last = max(last, d.CommitID)
	}
	return Own{LastCommit: last, WebCertificateID: g.files.st.WebCertificateID}, nil
}

func (g *Files) SetLastCommit(n int64) error {
	end, err := g.files.beginWrite()
	if err != nil {
		return err
	}
	defer end()
	if err := g.files.loadState(); err != nil {
		return err
	}
	st := g.files.st
	st.LastCommit = n
	return g.files.setState(st)
}

func (g *Files) SetWebCertificate(id *uint) error {
	end, err := g.files.beginWrite()
	if err != nil {
		return err
	}
	defer end()
	if err := g.files.loadState(); err != nil {
		return err
	}
	st := g.files.st
	st.WebCertificateID = id
	return g.files.setState(st)
}

// SetGeneration raises the generation handed to the firewall's agent; it is
// the file's, never lowered (a restore knows nothing of it).
func (g *Files) SetGeneration(id uint, generation int64) error {
	end, err := g.files.beginWrite()
	if err != nil {
		return err
	}
	defer end()
	if err := g.files.loadSessions(); err != nil {
		return err
	}
	if generation <= g.files.gens[id] {
		return nil
	}
	g.files.gens[id] = generation
	return g.files.writeSessions()
}

func (g *Files) Generations() (map[uint]int64, error) {
	defer g.files.begin()()
	if err := g.files.loadSessions(); err != nil {
		return nil, err
	}
	out := make(map[uint]int64, len(g.files.gens))
	for id, gen := range g.files.gens {
		out[id] = gen
	}
	return out, nil
}

func (g *Files) UseTOTPStep(userID uint, step int64) (bool, error) {
	_, ok, err := g.changeSession(userID, func(r *sessionRec) bool {
		if step <= r.TOTPLastStep {
			return false
		}
		r.TOTPLastStep = step
		return true
	})
	return ok, err
}

func (g *Files) IDs() (sqlmap.IDs, error) {
	defer g.files.begin()()
	if err := g.files.loadIDs(); err != nil {
		return sqlmap.IDs{}, err
	}
	return g.files.ids, nil
}

func (g *Files) AssignIDs(m *sqlmap.Mapping, tree *datastore.Tree) (sqlmap.Index, error) {
	end, err := g.files.beginWrite()
	if err != nil {
		return nil, err
	}
	defer end()
	if err := g.files.loadIDs(); err != nil {
		return nil, err
	}
	next, idx := m.PlanIDs(g.files.ids, tree)
	if !next.Equal(g.files.ids) {
		if err := g.files.setIDs(next); err != nil {
			return nil, err
		}
	}
	return idx, nil
}

func (g *Files) Seed() error {
	end, err := g.files.beginWrite()
	if err != nil {
		return err
	}
	defer end()
	f := &g.files
	for _, load := range []func() error{f.loadIDs, f.loadState, f.loadDeployments, f.loadNICs, f.loadSessions} {
		if err := load(); err != nil {
			return err
		}
	}
	return nil
}

func (g *Files) UpdateIDs(fn func(ids sqlmap.IDs)) error {
	end, err := g.files.beginWrite()
	if err != nil {
		return err
	}
	defer end()
	if err := g.files.loadIDs(); err != nil {
		return err
	}
	next := g.files.ids.Clone()
	fn(next)
	return g.files.setIDs(next)
}

func (g *Files) ExportState(forReplica bool) (map[string][]byte, error) {
	defer g.files.begin()()
	if err := g.files.loadIDs(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(g.files.ids)
	if err != nil {
		return nil, err
	}
	out := map[string][]byte{entryIDsFile: b}
	if !forReplica {
		return out, nil
	}
	if err := g.files.loadDeployments(); err != nil {
		return nil, err
	}
	if out[deploymentsFile], err = g.files.encodeDeployments(); err != nil {
		return nil, err
	}
	if err := g.files.loadNICs(); err != nil {
		return nil, err
	}
	if out[knownNICsFile], err = json.Marshal(g.files.nics); err != nil {
		return nil, err
	}
	// The sessions are valid on both hosts of a pair.
	if err := g.files.loadSessions(); err != nil {
		return nil, err
	}
	if out[sessionsFile], err = json.Marshal(sessionsJSON{Version: 1, Users: g.files.sess, Generations: g.files.gens}); err != nil {
		return nil, err
	}
	return out, nil
}

func (g *Files) ImportState(files map[string][]byte) error {
	end, err := g.files.beginWrite()
	if err != nil {
		return err
	}
	defer end()
	if b, ok := files[entryIDsFile]; ok {
		var ids sqlmap.IDs
		if err := json.Unmarshal(b, &ids); err != nil {
			return err
		}
		// No id given here since the copy is given again.
		if err := g.files.loadIDs(); err != nil {
			return err
		}
		ids.KeepHigher(g.files.ids)
		if err := g.files.setIDs(ids); err != nil {
			return err
		}
	} else {
		// Every copy since the ids were a file has them.
		return errors.New("the copy has no entry ids (" + entryIDsFile + ")")
	}
	if b, ok := files[deploymentsFile]; ok {
		g.files.deps, g.files.depNext = nil, 1
		g.files.parseDeployments(b)
		g.files.depsLoaded = true
		if err := g.files.rewriteDeployments(); err != nil {
			return err
		}
	}
	if b, ok := files[sessionsFile]; ok {
		if err := g.files.loadSessions(); err != nil {
			return err
		}
		if err := g.files.mergeSessions(b); err != nil {
			return err
		}
	}
	if b, ok := files[knownNICsFile]; ok {
		var nics map[uint][]string
		if err := json.Unmarshal(b, &nics); err != nil {
			return err
		}
		g.files.nics, g.files.nicsLoaded = nics, true
		if err := g.files.writeNICs(); err != nil {
			return err
		}
	}
	return nil
}

func (g *Files) FollowChange(m *sqlmap.Mapping, c *datastore.Tree) error {
	end, err := g.files.beginWrite()
	if err != nil {
		return err
	}
	defer end()
	if err := g.files.loadIDs(); err != nil {
		return err
	}
	next, idx := m.PlanIDs(g.files.ids, c)
	if !next.Equal(g.files.ids) {
		if err := g.files.setIDs(next); err != nil {
			return err
		}
	}
	return g.forgetWebCertificate(idx)
}

// forgetWebCertificate forgets the certificate chosen for portitor-config
// when the configuration no longer has it, under files.mu.
func (g *Files) forgetWebCertificate(idx sqlmap.Index) error {
	if err := g.files.loadState(); err != nil {
		return err
	}
	cert := g.files.st.WebCertificateID
	if cert == nil {
		return nil
	}
	for n, id := range idx {
		if n.S.Name == "certificate" && uint(id) == *cert {
			return nil
		}
	}
	st := g.files.st
	st.WebCertificateID = nil
	return g.files.setState(st)
}
