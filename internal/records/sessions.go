// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package records

import (
	"encoding/json"
	"errors"
	"os"
	"slices"

	"gorm.io/gorm"

	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/models"
)

// The users' runtime values, which are not configuration and are never in a
// commit or a backup, are in sessions.json next to the database, by user id:
//
//   - the token version, which a session carries and which ends it when
//     raised (a password or role change, a delete, a logout everywhere);
//   - the TOTP step last accepted, so a code is good once;
//   - a TOTP secret being set up.
//
// The values only grow (a version, a step), so the replica merges them by
// maximum. An entry is never removed: a deleted user's version stays, and
// whoever gets the id again starts above it.
const sessionsFile = "sessions.json"

type sessionRec struct {
	TokenVersion int    `json:"tv,omitempty"`
	TOTPLastStep int64  `json:"step,omitempty"`
	TOTPPending  string `json:"pending,omitempty"`
	// UsedRecovery are the hashes of the recovery codes used: the codes
	// themselves are configuration, which a login never writes.
	UsedRecovery []string `json:"used,omitempty"`
}

type sessionsJSON struct {
	Version int                 `json:"version"`
	Users   map[uint]sessionRec `json:"users"`
	// Generations are the last generation handed to each firewall's agent:
	// runtime, only growing.
	Generations map[uint]int64 `json:"generations,omitempty"`
}

// loadSessions loads the values (or seeds them from db's users table), under
// f.mu.
func (f *fileState) loadSessions(db *gorm.DB) error {
	if f.sessLoaded {
		return nil
	}
	f.sess = map[uint]sessionRec{}
	f.gens = map[uint]int64{}
	if f.dir != "" {
		switch b, err := os.ReadFile(f.path(sessionsFile)); {
		case err == nil:
			var j sessionsJSON
			if err := json.Unmarshal(b, &j); err != nil {
				return err
			}
			if j.Users != nil {
				f.sess = j.Users
			}
			f.gens = j.Generations
			if f.gens == nil {
				f.gens = map[uint]int64{}
			}
			f.sessLoaded = true
			return nil
		case !errors.Is(err, os.ErrNotExist):
			return err
		}
	}
	if db != nil && db.Migrator().HasTable("users") {
		var rows []struct {
			ID           uint
			TokenVersion int
			TOTPLastStep int64  `gorm:"column:totp_last_step"`
			TOTPPending  string `gorm:"column:totp_pending"`
		}
		if err := db.Table("users").Select("id, token_version, totp_last_step, totp_pending").Find(&rows).Error; err != nil {
			return err
		}
		for _, r := range rows {
			if r.TokenVersion != 0 || r.TOTPLastStep != 0 || r.TOTPPending != "" {
				f.sess[r.ID] = sessionRec{TokenVersion: r.TokenVersion, TOTPLastStep: r.TOTPLastStep, TOTPPending: r.TOTPPending}
			}
		}
	}
	f.sessLoaded = true
	return f.writeSessions()
}

// writeSessions writes the values, under f.mu.
func (f *fileState) writeSessions() error {
	if f.dir == "" {
		return nil
	}
	b, err := json.Marshal(sessionsJSON{Version: 1, Users: f.sess, Generations: f.gens})
	if err != nil {
		return err
	}
	if err := datastore.WriteFile(f.path(sessionsFile), b); err != nil {
		return err
	}
	f.wrote(sessionsFile)
	return nil
}

// mergeSessions takes the values of a copy: the larger of each, a setup in
// progress here kept before the copy's.
func (f *fileState) mergeSessions(b []byte) error {
	var j sessionsJSON
	if err := json.Unmarshal(b, &j); err != nil {
		return err
	}
	for id, theirs := range j.Users {
		mine := f.sess[id]
		mine.TokenVersion = max(mine.TokenVersion, theirs.TokenVersion)
		mine.TOTPLastStep = max(mine.TOTPLastStep, theirs.TOTPLastStep)
		if mine.TOTPPending == "" {
			mine.TOTPPending = theirs.TOTPPending
		}
		for _, h := range theirs.UsedRecovery {
			if !slices.Contains(mine.UsedRecovery, h) {
				mine.UsedRecovery = append(mine.UsedRecovery, h)
			}
		}
		f.sess[id] = mine
	}
	for id, gen := range j.Generations {
		f.gens[id] = max(f.gens[id], gen)
	}
	return f.writeSessions()
}

// Runtime fills the runtime values into users, as the rows of the models
// have them.
func (g *GORM) Runtime(users ...*models.User) error {
	defer g.files.begin(false)()
	if err := g.files.loadSessions(g.db); err != nil {
		return err
	}
	for _, u := range users {
		r := g.files.sess[u.ID]
		u.TokenVersion, u.TOTPLastStep, u.TOTPPending = r.TokenVersion, r.TOTPLastStep, r.TOTPPending
		if len(r.UsedRecovery) > 0 && u.RecoveryCodes != "" {
			var codes []string
			if json.Unmarshal([]byte(u.RecoveryCodes), &codes) == nil {
				codes = slices.DeleteFunc(codes, func(h string) bool { return slices.Contains(r.UsedRecovery, h) })
				if b, err := json.Marshal(codes); err == nil {
					u.RecoveryCodes = string(b)
				}
			}
		}
	}
	return nil
}

// withRuntime is Runtime, for the records' own use.
func (g *GORM) withRuntime(users ...*models.User) error { return g.Runtime(users...) }

func (g *GORM) Revoke(userID uint) (int, error) {
	r, _, err := g.changeSession(userID, func(r *sessionRec) bool { r.TokenVersion++; return true })
	return r.TokenVersion, err
}

func (g *GORM) SetTOTPPending(userID uint, secret string) error {
	_, _, err := g.changeSession(userID, func(r *sessionRec) bool { r.TOTPPending = secret; return true })
	return err
}

func (g *GORM) EnableTOTPState(userID uint, step int64) error {
	_, _, err := g.changeSession(userID, func(r *sessionRec) bool {
		r.TOTPPending, r.TOTPLastStep, r.UsedRecovery = "", step, nil
		return true
	})
	return err
}

func (g *GORM) ClearTOTPState(userID uint) error {
	_, _, err := g.changeSession(userID, func(r *sessionRec) bool {
		r.TOTPPending, r.TOTPLastStep, r.UsedRecovery = "", 0, nil
		return true
	})
	return err
}

func (g *GORM) MarkRecoveryCodeUsed(userID uint, hash string) (bool, error) {
	_, ok, err := g.changeSession(userID, func(r *sessionRec) bool {
		if slices.Contains(r.UsedRecovery, hash) {
			return false
		}
		r.UsedRecovery = append(r.UsedRecovery, hash)
		return true
	})
	return ok, err
}

func (g *GORM) ForgetRecoveryCodes(userID uint, codes []string) error {
	_, _, err := g.changeSession(userID, func(r *sessionRec) bool {
		kept := slices.DeleteFunc(slices.Clone(r.UsedRecovery), func(h string) bool { return !slices.Contains(codes, h) })
		if len(kept) == len(r.UsedRecovery) {
			return false
		}
		r.UsedRecovery = kept
		return true
	})
	return err
}

// changeSession changes a user's runtime values with fn under the lock the
// other processes share; it returns the values after.
func (g *GORM) changeSession(id uint, fn func(r *sessionRec) bool) (sessionRec, bool, error) {
	defer g.files.begin(true)()
	if err := g.files.loadSessions(g.db); err != nil {
		return sessionRec{}, false, err
	}
	r := g.files.sess[id]
	if !fn(&r) {
		return r, false, nil
	}
	g.files.sess[id] = r
	return r, true, g.files.writeSessions()
}
