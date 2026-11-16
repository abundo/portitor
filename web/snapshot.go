// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/datastore/sqlmap"
)

// A copy of portitor-config's state is an archive of files (copybundle.go), for
// a backup and for the HA replica.

// takeSnapshot makes the configuration of a copy (decodeCopy) this
// installation's candidate, and its ids this one's. With keepFirewalls (a
// backup) the firewalls stay this installation's, with the ids the
// deployments name them by: they are hosts with their agents, not the
// configuration; a replica's copy takes the primary's whole.
func (s *Server) takeSnapshot(ctx context.Context, files map[string][]byte, fix func(*datastore.Tree), keepFirewalls bool) error {
	t, err := s.tree()
	if err != nil {
		return err
	}
	tree := datastore.New(t.schema)
	if err := tree.UnmarshalJSON(files["candidate.json"]); err != nil {
		return restoreError("the backup's configuration: " + err.Error())
	}
	if _, ok := files["entry-ids.json"]; !ok {
		return restoreError("the copy holds no entry ids (entry-ids.json)")
	}
	gt := datastore.New(t.schema)
	if g, ok := files["global.json"]; !ok {
		return restoreError("the copy holds no global lists (global.json)")
	} else if err := gt.UnmarshalJSON(g); err != nil {
		return restoreError("the backup's global lists: " + err.Error())
	}
	var mine *datastore.Tree
	var myIDs []struct {
		path, tbl string
		id        int64
	}
	if keepFirewalls {
		if mine, err = s.globalsTree(t); err != nil {
			return err
		}
		tree.CopyLists(mine, "firewall")
		ids, err := s.rec.IDs()
		if err != nil {
			return err
		}
		ids.Each("/firewall[", func(path, tbl string, id int64) {
			myIDs = append(myIDs, struct {
				path, tbl string
				id        int64
			}{path, tbl, id})
		})
	}
	if fix != nil {
		fix(tree)
	}
	if ids, ok := files["ids.json"]; ok && t.dir != "" {
		// The copy's marks, but none lower than this installation's: an id
		// given here since the copy is not given again.
		var theirs, mine map[string]uint64
		if err := json.Unmarshal(ids, &theirs); err != nil {
			return restoreError("the backup's ids.json: " + err.Error())
		}
		if theirs == nil {
			theirs = map[string]uint64{}
		}
		path := filepath.Join(t.dir, "ids.json")
		if b, err := os.ReadFile(path); err == nil {
			_ = json.Unmarshal(b, &mine)
		}
		for k, v := range mine {
			theirs[k] = max(theirs[k], v)
		}
		b, err := json.Marshal(theirs)
		if err != nil {
			return err
		}
		if err := datastore.WriteFile(path, b); err != nil {
			return err
		}
		t.idMarks = nil
	}
	// The entries' ids are those of the copy.
	if err := s.rec.ImportState(files); err != nil {
		return err
	}
	if keepFirewalls {
		if err := s.rec.UpdateIDs(func(ids sqlmap.IDs) {
			var theirs []string
			ids.Each("/firewall[", func(path, _ string, _ int64) { theirs = append(theirs, path) })
			for _, p := range theirs {
				ids.Delete(p)
			}
			for _, m := range myIDs {
				ids.Set(m.path, m.tbl, m.id)
			}
		}); err != nil {
			return err
		}
	}
	if err := t.store.Replace(ctx, tree); err != nil {
		return err
	}
	// What runs of the global lists is the copy's.
	if keepFirewalls {
		gt.CopyLists(mine, "firewall")
	}
	unlock, err := s.lockData()
	if err != nil {
		return err
	}
	defer unlock()
	if err := s.writeGlobals(t, gt); err != nil {
		return err
	}
	s.forgetRunning()
	return nil
}
