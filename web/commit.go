// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/labstack/echo/v5"
	"gorm.io/gorm"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/agentclient"
	"github.com/abundo/portitor/internal/builder"
	"github.com/abundo/portitor/internal/buildinfo"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/render"
	"github.com/abundo/portitor/models"
)

// A commit deploys to every firewall whose document changed (all of them
// when none did, which applies the configuration again). It is numbered
// by Settings.LastCommit, which names its database snapshot for Revert;
// each firewall it deploys to gets a Deployment with that firewall's own
// generation. Several firewalls change together: each apply waits for
// confirmation, so when one fails the others are rolled back at once, and
// without a confirm timeout they are confirmed as soon as all succeeded.

// jointConfirm is the confirm window of a commit to several firewalls
// without a confirm timeout: long enough to apply them all.
const jointConfirm = 300

// errPending refuses a commit while a change waits for confirmation.
var errPending = errors.New("a deployment is waiting for confirmation; confirm or roll it back first")

// commitResult is what a commit did on each firewall it deployed to.
type commitResult struct {
	Commit int64 `json:"commit"`
	// Status is failed when a firewall failed, else pending when the
	// change waits for confirmation, else applied.
	Status      string              `json:"status"`
	Deployments []models.Deployment `json:"deployments"`
	// Results are the agents' answers, by firewall name.
	Results map[string]*agentapi.ApplyResult `json:"results"`
}

type commitTarget struct {
	fw  models.Firewall
	a   agentAPI
	doc *fwconfig.Document
	dep models.Deployment
	// cfg: a firewall with portitor-config, committed there (push.go);
	// doc and a are unused then.
	cfg configAPI
	// push are its virtual firewalls to push before the commit, del
	// those to delete there.
	push []string
	del  []string
	// skip: an HA host that can't be reached while its peer can; it
	// catches up when it answers (witness.go).
	skip bool
}

// deploy commits: it builds each firewall's document, applies the changed
// ones and records the deployments. timeout nil takes the confirm timeout
// from the settings. only names the instances to deploy from the database
// (nil: everything); see buildDoc.
func (s *Server) deploy(ctx context.Context, username string, timeout *int, only map[string]bool) (*commitResult, error) {
	s.deployMu.Lock()
	defer s.deployMu.Unlock()
	st, err := s.settings()
	if err != nil {
		return nil, err
	}
	fws, err := s.firewalls()
	if err != nil {
		return nil, err
	}
	commit := st.LastCommit + 1
	// Build from the snapshot, so it is exactly what Revert restores even
	// if an edit comes in meanwhile.
	snap, err := s.takeSnapshot(commit)
	if err != nil {
		return nil, err
	}
	kept := false
	defer func() {
		if !kept {
			os.Remove(snap)
		}
	}()
	snapDB, err := openSnapshot(snap)
	if err != nil {
		return nil, err
	}
	viaChanged, viaSame, err := s.configTargets(ctx, snapDB, fws, only)
	if err != nil {
		closeDB(snapDB)
		return nil, err
	}
	targets, same, err := s.commitTargets(snapDB, fws, only)
	if err == nil {
		// Nothing changed: all are applied again.
		if len(targets) == 0 && len(viaChanged) == 0 {
			targets, viaChanged = same, viaSame
		}
		targets = append(targets, viaChanged...)
		if len(targets) == 0 {
			err = bad("there is nothing to deploy")
		}
	}
	if err == nil {
		err = s.pushTargets(ctx, snapDB, viaChanged)
	}
	closeDB(snapDB)
	if err != nil {
		return nil, err
	}
	reached := map[uint]bool{}
	var unreached []*commitTarget
	var reachErr error
	for _, t := range targets {
		if t.cfg != nil {
			// portitor-config asks its agents.
			reached[t.fw.ID] = true
			continue
		}
		if t.a, err = s.newAgent(&t.fw); err != nil {
			return nil, bad(fmt.Sprintf("firewall %s: %v", t.fw.Name, err))
		}
		// The history may not know yet that a change timed out.
		as, err := t.a.Status(ctx)
		if err != nil {
			unreached = append(unreached, t)
			reachErr = fmt.Errorf("firewall %s: %w", t.fw.Name, err)
			continue
		}
		reached[t.fw.ID] = true
		if as.Pending != nil {
			return nil, errPending
		}
	}
	// An HA host that can't be reached is skipped when its peer can be
	// (the witness keeps it fenced unless it hears that peer).
	for _, t := range unreached {
		peer := haPeerOf(fws, t.fw)
		if peer == 0 || (!reached[peer] && !s.answers(ctx, fws, peer)) {
			return nil, reachErr
		}
		t.skip = true
	}

	confirm := st.ConfirmTimeout
	if timeout != nil {
		confirm = *timeout
	}
	applying := 0
	for _, t := range targets {
		if !t.skip {
			applying++
		}
	}
	together := applying > 1
	applyConfirm := confirm
	if together && applyConfirm == 0 {
		applyConfirm = jointConfirm
	}
	// Burn the numbers even if the apply fails, so every attempt an agent
	// sees has a unique generation.
	st.LastCommit = commit
	if err := s.db.Save(st).Error; err != nil {
		return nil, err
	}
	for _, t := range targets {
		if t.doc == nil {
			continue
		}
		if err := s.db.Model(&models.Firewall{}).Where("id = ?", t.fw.ID).Update("generation", t.doc.Generation).Error; err != nil {
			return nil, err
		}
	}

	res := &commitResult{Commit: commit, Status: "applied", Deployments: []models.Deployment{}, Results: map[string]*agentapi.ApplyResult{}}
	var applyErr error
	for _, t := range targets {
		if t.cfg != nil {
			t.dep = models.Deployment{FirewallID: t.fw.ID, CommitID: commit, Username: username, Instances: models.StringList{}}
			if only != nil {
				t.dep.Instances = sortedNames(only)
			}
		} else {
			docJSON, _ := json.Marshal(redactDoc(*t.doc))
			t.dep = models.Deployment{FirewallID: t.fw.ID, CommitID: commit, Generation: t.doc.Generation, Username: username,
				Document: string(docJSON), DocHash: docHash(*t.doc), Instances: models.StringList{}}
			if only != nil {
				t.dep.Instances = sortedNames(onlyOn(only, t.doc))
			}
		}
		if t.skip {
			t.dep.Status, t.dep.Message = "skipped", "not reachable; it catches up when it answers"
			continue
		}
		if applyErr != nil {
			t.dep.Status, t.dep.Message = "failed", "not applied: firewall "+failedName(targets)+" failed"
			continue
		}
		if t.cfg != nil {
			if err := s.commitVia(ctx, t, applyConfirm); err != nil {
				applyErr = fmt.Errorf("firewall %s: %w", t.fw.Name, err)
			}
			continue
		}
		r, err := t.a.Apply(ctx, *t.doc, applyConfirm)
		switch {
		case err != nil:
			applyErr = fmt.Errorf("firewall %s: %w", t.fw.Name, err)
			if !together {
				applyErr = err
			}
			t.dep.Status, t.dep.Message = "failed", err.Error()
			var ae *agentclient.Error
			if errors.As(err, &ae) && ae.Result != nil {
				r = ae.Result
				switch {
				case ae.Result.RollbackErrors != "":
					t.dep.Message += " (restoring the previous configuration failed: " + ae.Result.RollbackErrors + ")"
				case ae.Result.RolledBack:
					t.dep.Message += " (previous configuration restored)"
				}
			}
		case r.ConfirmBy != nil:
			t.dep.Status = "pending"
			t.dep.Message = "confirm before " + r.ConfirmBy.Local().Format(time.TimeOnly)
		default:
			t.dep.Status = "applied"
		}
		if r != nil {
			t.dep.Log = strings.Join(r.Log, "\n")
		}
		res.Results[t.fw.Name] = r
	}
	switch {
	case applyErr != nil && together:
		for _, t := range targets {
			if t.dep.Status != "pending" {
				continue
			}
			if err := s.finishTarget(context.WithoutCancel(ctx), t, false); err != nil {
				t.dep.Message = "rolling back after firewall " + failedName(targets) + " failed: " + err.Error()
				continue
			}
			t.dep.Status, t.dep.Message = "rolled_back", "rolled back: firewall "+failedName(targets)+" failed"
		}
	case together && confirm == 0:
		for _, t := range targets {
			if t.skip {
				continue
			}
			if err := s.finishTarget(context.WithoutCancel(ctx), t, true); err != nil {
				t.dep.Message = "confirming: " + err.Error()
				continue
			}
			t.dep.Status, t.dep.Message = "applied", ""
		}
	}

	for _, t := range targets {
		if err := s.db.Create(&t.dep).Error; err != nil {
			return nil, err
		}
		res.Deployments = append(res.Deployments, t.dep)
		switch t.dep.Status {
		case "failed", "rolled_back":
			res.Status = "failed"
			continue
		case "pending":
			if res.Status == "applied" {
				res.Status = "pending"
			}
		}
		if t.doc == nil {
			continue
		}
		if err := s.keepDocument(t.doc, commit, t.fw.ID); err != nil {
			slog.Warn("keeping the deployed document", "firewall", t.fw.Name, "err", err)
		}
	}
	// Revert restores a snapshot of the database, which matches what
	// runs only after a deploy of everything that succeeded.
	if only == nil && applyErr == nil {
		s.keepSnapshot(snap, commit)
		kept = true
	} else {
		s.pruneSnapshots()
	}
	return res, applyErr
}

// commitTargets builds each firewall's document and picks the firewalls
// a commit deploys to: those whose document changed, or all of them when
// none did. Problems come back as one *fwconfig.ValidationError, each
// named by its firewall when there are several.
func (s *Server) commitTargets(db *gorm.DB, fws []models.Firewall, only map[string]bool) (changed, same []*commitTarget, err error) {
	var problems []string
	for _, fw := range fws {
		if viaConfig(fws, fw) {
			continue
		}
		doc, err := s.buildDoc(db, &fw, fw.Generation+1, only)
		var ve *fwconfig.ValidationError
		switch {
		case errors.As(err, &ve):
			for _, p := range ve.Problems {
				problems = append(problems, firewallProblem(fws, fw, p))
			}
			continue
		case err != nil:
			return nil, nil, err
		case doc == nil:
			continue
		}
		t := &commitTarget{fw: fw, doc: doc}
		live, err := s.liveDeployment(fw.ID)
		if err != nil {
			return nil, nil, err
		}
		if live != nil && live.DocHash == docHash(*doc) {
			same = append(same, t)
		} else {
			changed = append(changed, t)
		}
	}
	if len(problems) > 0 {
		return nil, nil, &fwconfig.ValidationError{Problems: problems}
	}
	return changed, same, nil
}

// firewallProblem names the firewall of a problem when there are several.
func firewallProblem(fws []models.Firewall, fw models.Firewall, p string) string {
	if len(fws) < 2 {
		return p
	}
	return fw.Name + ": " + p
}

func failedName(targets []*commitTarget) string {
	for _, t := range targets {
		if t.dep.Status == "failed" && !strings.HasPrefix(t.dep.Message, "not applied") {
			return t.fw.Name
		}
	}
	return ""
}

// onlyOn is the part of only that doc holds.
func onlyOn(only map[string]bool, doc *fwconfig.Document) map[string]bool {
	out := map[string]bool{}
	for _, in := range doc.Instances {
		if only[in.Name] {
			out[in.Name] = true
		}
	}
	return out
}

// buildDoc builds a firewall's document from db. With only nil it is
// everything on the firewall; otherwise only those instances come from db
// and the rest from the firewall's live document, and it is nil when only
// names nothing on the firewall. Problems come back as a
// *fwconfig.ValidationError alongside the document.
func (s *Server) buildDoc(db *gorm.DB, fw *models.Firewall, gen int64, only map[string]bool) (*fwconfig.Document, error) {
	if only == nil {
		return builder.BuildFirewall(db, gen, fw.ID)
	}
	if len(only) == 0 {
		return nil, errForbidden
	}
	runs := fw.ID
	if fw.HAPrimaryID != nil {
		runs = *fw.HAPrimaryID
	}
	var names []string
	if err := db.Model(&models.Instance{}).Where("firewall_id = ?", runs).Pluck("name", &names).Error; err != nil {
		return nil, err
	}
	mine := map[string]bool{}
	for _, n := range names {
		if only[n] {
			mine[n] = true
		}
	}
	if len(mine) == 0 {
		return nil, nil
	}
	live, err := s.liveDocument(fw.ID)
	if err != nil {
		return nil, err
	}
	part, err := builder.BuildFirewallInstances(db, gen, fw.ID, mine)
	var problems []string
	var ve *fwconfig.ValidationError
	if errors.As(err, &ve) {
		problems = ve.Problems
	} else if err != nil {
		return nil, err
	}
	doc := mergeInstances(live, part)
	doc.Generation = gen
	if err := doc.Validate(); err != nil {
		if errors.As(err, &ve) {
			problems = append(problems, ve.Problems...)
		} else {
			problems = append(problems, err.Error())
		}
	}
	if len(problems) > 0 {
		return doc, &fwconfig.ValidationError{Problems: problems}
	}
	return doc, nil
}

// latestDeployment is the firewall's latest deployment, or nil.
func (s *Server) latestDeployment(firewallID uint) (*models.Deployment, error) {
	var dep models.Deployment
	err := s.db.Where("firewall_id = ?", firewallID).Order("commit_id desc, id desc").First(&dep).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &dep, err
}

// liveDeployment is the latest deployment the firewall runs (or runs
// pending confirmation); a failed or rolled back one left the previous
// one in place.
func (s *Server) liveDeployment(firewallID uint) (*models.Deployment, error) {
	var dep models.Deployment
	err := s.db.Where("firewall_id = ? AND status IN ?", firewallID, []string{"applied", "pending", "confirmed"}).
		Order("commit_id desc, id desc").First(&dep).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &dep, err
}

// pendingDeployments are the firewalls' latest deployments that wait for
// confirmation.
func (s *Server) pendingDeployments() ([]models.Deployment, error) {
	fws, err := s.firewalls()
	if err != nil {
		return nil, err
	}
	var out []models.Deployment
	for _, fw := range fws {
		dep, err := s.liveDeployment(fw.ID)
		if err != nil {
			return nil, err
		}
		if dep != nil && dep.Status == "pending" {
			out = append(out, *dep)
		}
	}
	return out, nil
}

// liveCommit is the newest commit that the firewalls run: each firewall
// runs its live deployment's commit or the database at a later one, since
// a commit skips the firewalls it does not change. 0: nothing deployed.
func (s *Server) liveCommit() (int64, error) {
	fws, err := s.firewalls()
	if err != nil {
		return 0, err
	}
	var commit int64
	for _, fw := range fws {
		dep, err := s.liveDeployment(fw.ID)
		if err != nil {
			return 0, err
		}
		if dep != nil && dep.CommitID > commit {
			commit = dep.CommitID
		}
	}
	return commit, nil
}

func (s *Server) handleDeployApply(c *echo.Context) error {
	var req struct {
		ConfirmTimeout *int     `json:"confirm_timeout"`
		Instances      []string `json:"instances"`
	}
	_ = c.Bind(&req)
	// One change at a time: a pending one is confirmed or rolled back
	// first.
	if deps, err := s.pendingDeployments(); err != nil {
		return err
	} else if len(deps) > 0 {
		return errJSON(c, http.StatusConflict, errPending.Error())
	}
	only, err := s.chosenScope(currentAccess(c), req.Instances, false)
	if err != nil {
		return dbError(c, err)
	}
	if only != nil && len(only) == 0 {
		return errJSON(c, http.StatusForbidden, "you are not an admin of any virtual firewall")
	}
	res, err := s.deploy(c.Request().Context(), currentUser(c).Username, req.ConfirmTimeout, only)
	var ve *fwconfig.ValidationError
	switch {
	case errors.As(err, &ve):
		return problemsResponse(c, err)
	case errors.Is(err, errPending):
		return errJSON(c, http.StatusConflict, err.Error())
	case err != nil && res != nil:
		return c.JSON(http.StatusBadGateway, map[string]any{"error": err.Error(), "commit": res})
	case err != nil:
		return agentError(c, err)
	}
	return c.JSON(http.StatusOK, res)
}

// handleDeployChanges tells whether the database differs from what is
// deployed, for the "uncommitted changes" banner.
func (s *Server) handleDeployChanges(c *echo.Context) error {
	resp := struct {
		Changed  bool `json:"changed"`
		Deployed bool `json:"deployed"`
		Problems int  `json:"problems"`
	}{}
	live, err := s.liveCommit()
	if err != nil {
		return err
	}
	resp.Deployed = live > 0
	if a := currentAccess(c); !a.readsAll() {
		names, err := s.instanceNames(a.readable())
		if err != nil {
			return err
		}
		resp.Changed, resp.Problems, err = s.instanceChanges(names)
		if err != nil {
			return err
		}
		return c.JSON(http.StatusOK, resp)
	}
	fws, err := s.firewalls()
	if err != nil {
		return err
	}
	for _, fw := range fws {
		changed, problems, err := s.firewallChanged(fw.ID)
		if err != nil {
			return err
		}
		resp.Changed = resp.Changed || changed
		resp.Problems += problems
	}
	return c.JSON(http.StatusOK, resp)
}

// firewallChanged tells whether the database builds another document for
// the firewall than it runs, and how many problems it has.
func (s *Server) firewallChanged(firewallID uint) (bool, int, error) {
	live, err := s.liveDeployment(firewallID)
	if err != nil {
		return false, 0, err
	}
	doc, err := builder.BuildFirewall(s.db, 0, firewallID)
	var ve *fwconfig.ValidationError
	switch {
	case errors.As(err, &ve):
		// What is deployed was valid, so this is a change.
		return true, len(ve.Problems), nil
	case err != nil:
		return false, 0, err
	case live == nil:
		return true, 0, nil
	case live.DocHash != "":
		return live.DocHash != docHash(*doc), 0, nil
	}
	// Older rows only have the redacted document, so key changes go
	// unnoticed there.
	var old fwconfig.Document
	if json.Unmarshal([]byte(live.Document), &old) != nil {
		return true, 0, nil
	}
	return docHash(old) != docHash(redactDoc(*doc)), 0, nil
}

func (s *Server) handleDeployConfirm(c *echo.Context) error {
	deps, err := s.pendingDeployments()
	if err != nil {
		return err
	}
	if len(deps) == 0 {
		return errJSON(c, http.StatusConflict, "no change is waiting for confirmation")
	}
	for i := range deps {
		if !s.mayFinish(currentAccess(c), &deps[i]) {
			return errJSON(c, http.StatusForbidden, "this change deployed virtual firewalls you are not an admin of")
		}
	}
	var errs []string
	for i := range deps {
		dep := &deps[i]
		fw, err := s.finishDeployment(c.Request().Context(), dep, true)
		if err != nil {
			errs = append(errs, firewallName(fw)+err.Error())
			continue
		}
		dep.Status, dep.Message = "confirmed", "confirmed by "+currentUser(c).Username
		s.db.Save(dep)
	}
	if len(errs) > 0 {
		return c.JSON(http.StatusBadGateway, map[string]any{"error": strings.Join(errs, "; ")})
	}
	return c.JSON(http.StatusOK, map[string]any{"commit": deps[0].CommitID, "deployments": deps})
}

func (s *Server) handleDeployRollback(c *echo.Context) error {
	deps, err := s.pendingDeployments()
	if err != nil {
		return err
	}
	if len(deps) == 0 {
		return errJSON(c, http.StatusConflict, "no change is waiting for confirmation")
	}
	for i := range deps {
		if !s.mayFinish(currentAccess(c), &deps[i]) {
			return errJSON(c, http.StatusForbidden, "only a global admin rolls back a change of virtual firewalls you are not an admin of")
		}
	}
	var errs []string
	results := map[string]*agentapi.ApplyResult{}
	for i := range deps {
		dep := &deps[i]
		fw, err := s.finishDeployment(c.Request().Context(), dep, false)
		if err != nil {
			errs = append(errs, firewallName(fw)+err.Error())
			continue
		}
		results[fw.Name] = &agentapi.ApplyResult{RolledBack: true}
		dep.Status, dep.Message = "rolled_back", "rolled back by "+currentUser(c).Username
		s.db.Save(dep)
	}
	if len(errs) > 0 {
		return c.JSON(http.StatusBadGateway, map[string]any{"error": strings.Join(errs, "; ")})
	}
	return c.JSON(http.StatusOK, map[string]any{"commit": deps[0].CommitID, "results": results})
}

// firewallName prefixes an error with its firewall's name, when known.
func firewallName(fw *models.Firewall) string {
	if fw == nil {
		return ""
	}
	return "firewall " + fw.Name + ": "
}

// firewallStatus is one firewall's agent in the merged status.
type firewallStatus struct {
	ID         uint   `json:"id"`
	Name       string `json:"name"`
	Hostname   string `json:"hostname,omitempty"`
	Version    string `json:"version,omitempty"`
	Generation int64  `json:"generation"`
	Error      string `json:"error,omitempty"`
	// VersionMismatch says how the agent's version differs from
	// portitor-web's; empty when they match.
	VersionMismatch string                  `json:"version_mismatch,omitempty"`
	Pending         *agentapi.PendingStatus `json:"pending,omitempty"`
	HA              *agentapi.HAStatus      `json:"ha,omitempty"`
}

// handleAgentStatus merges the firewalls' agent status: their instances,
// leases, NICs and the like together. Pending is the commit waiting for
// confirmation, by its number, with the earliest deadline. With one
// firewall an unreachable agent is an error; with several it is that
// firewall's Error.
func (s *Server) handleAgentStatus(c *echo.Context) error {
	fws, err := s.firewalls()
	if err != nil {
		return err
	}
	var merged *agentapi.Status
	sync := &nicSync{Imported: []string{}, Missing: []missingNIC{}, Problems: []string{}}
	statuses := []firewallStatus{}
	var mismatch string
	for _, fw := range fws {
		fs := firewallStatus{ID: fw.ID, Name: fw.Name}
		st, err := s.firewallStatus(c.Request().Context(), &fw)
		if err != nil {
			if len(fws) == 1 {
				return agentError(c, err)
			}
			fs.Error = err.Error()
			statuses = append(statuses, fs)
			continue
		}
		fs.Hostname, fs.Version, fs.Generation, fs.Pending = st.Hostname, st.Version, st.Generation, st.Pending
		if st.HA != nil && st.HA.Node != "" {
			fs.HA = st.HA
		}
		fs.VersionMismatch = buildinfo.Mismatch(st.Version)
		if mismatch == "" {
			mismatch = fs.VersionMismatch
		}
		statuses = append(statuses, fs)
		fwSync, err := s.syncNICs(fw.ID, st.NICs)
		if err != nil {
			return err
		}
		sync.Imported = append(sync.Imported, fwSync.Imported...)
		sync.Missing = append(sync.Missing, fwSync.Missing...)
		sync.Problems = append(sync.Problems, fwSync.Problems...)
		merged = mergeStatus(merged, st, fw.Name, len(fws) > 1)
	}
	if merged == nil {
		merged = &agentapi.Status{}
		for _, fs := range statuses {
			merged.LastError = joinNonEmpty(merged.LastError, fs.Name+": "+fs.Error)
		}
	}
	merged.Pending = nil
	if deps, err := s.pendingDeployments(); err != nil {
		return err
	} else if len(deps) > 0 {
		for _, fs := range statuses {
			if fs.Pending != nil && (merged.Pending == nil || fs.Pending.Deadline.Before(merged.Pending.Deadline)) {
				merged.Pending = &agentapi.PendingStatus{Generation: deps[0].CommitID, Deadline: fs.Pending.Deadline}
			}
		}
	}
	if merged.Generation, err = s.liveCommit(); err != nil {
		return err
	}
	names, err := s.readableInstanceNames(c)
	if err != nil {
		return err
	}
	if names != nil {
		filterStatus(merged, names)
		sync = nil
		for i := range statuses {
			statuses[i].Hostname, statuses[i].Version, statuses[i].Error, statuses[i].HA = "", "", "", nil
		}
	}
	return c.JSON(http.StatusOK, struct {
		*agentapi.Status
		NICSync         *nicSync         `json:"nic_sync"`
		VersionMismatch string           `json:"version_mismatch,omitempty"`
		Firewalls       []firewallStatus `json:"firewalls"`
	}{merged, sync, mismatch, statuses})
}

// firewallStatus asks the firewall's agent for its status, and settles
// its pending deployment when the agent no longer holds it.
func (s *Server) firewallStatus(ctx context.Context, fw *models.Firewall) (*agentapi.Status, error) {
	a, err := s.newAgent(fw)
	if err != nil {
		return nil, bad(err.Error())
	}
	st, err := a.Status(ctx)
	if err != nil {
		return nil, err
	}
	// A pending deployment that the agent no longer holds was either
	// confirmed elsewhere (the portitor CLI) or rolled back, on timeout or
	// by the CLI.
	if dep, _ := s.latestDeployment(fw.ID); dep != nil && dep.Status == "pending" && st.Pending == nil {
		if st.Generation == dep.Generation {
			dep.Status, dep.Message = "confirmed", "confirmed"
		} else {
			dep.Status, dep.Message = "rolled_back", fmt.Sprintf("rolled back on the firewall or not confirmed in time; agent restored generation %d", st.Generation)
		}
		s.db.Save(dep)
	}
	return st, nil
}

// mergeStatus adds a firewall's status to the merged one. Firewall-wide
// errors are named by their firewall when there are several.
func mergeStatus(into, st *agentapi.Status, name string, several bool) *agentapi.Status {
	if several && st.LastError != "" {
		st.LastError = name + ": " + st.LastError
	}
	if into == nil {
		return st
	}
	into.Instances = append(into.Instances, st.Instances...)
	into.DHCPLeases = append(into.DHCPLeases, st.DHCPLeases...)
	into.DynDNS = append(into.DynDNS, st.DynDNS...)
	into.TunnelBroker = append(into.TunnelBroker, st.TunnelBroker...)
	into.Certificates = append(into.Certificates, st.Certificates...)
	into.ACMEProxy = append(into.ACMEProxy, st.ACMEProxy...)
	into.IPLists = append(into.IPLists, st.IPLists...)
	into.Tasks = append(into.Tasks, st.Tasks...)
	into.NICs = append(into.NICs, st.NICs...)
	for _, p := range st.Programs {
		if !slices.Contains(into.Programs, p) {
			into.Programs = append(into.Programs, p)
		}
	}
	into.LastError = joinNonEmpty(into.LastError, st.LastError)
	into.DryRun = into.DryRun || st.DryRun
	if st.LastApply != nil && (into.LastApply == nil || st.LastApply.After(*into.LastApply)) {
		into.LastApply = st.LastApply
	}
	return into
}

func joinNonEmpty(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	}
	return a + "; " + b
}

// firewallDocs builds each firewall's document for a check or preview,
// leaving out the firewalls only names nothing on. Problems come back as
// one *fwconfig.ValidationError alongside the documents.
func (s *Server) firewallDocs(only map[string]bool) ([]models.Firewall, []*fwconfig.Document, error) {
	all, err := s.firewalls()
	if err != nil {
		return nil, nil, err
	}
	var fws []models.Firewall
	var docs []*fwconfig.Document
	var problems []string
	for _, fw := range all {
		doc, err := s.buildDoc(s.db, &fw, fw.Generation+1, only)
		var ve *fwconfig.ValidationError
		switch {
		case errors.As(err, &ve):
			for _, p := range ve.Problems {
				problems = append(problems, firewallProblem(all, fw, p))
			}
		case err != nil:
			return nil, nil, err
		}
		if doc != nil {
			fws, docs = append(fws, fw), append(docs, doc)
		}
	}
	if len(problems) > 0 {
		return fws, docs, &fwconfig.ValidationError{Problems: problems}
	}
	return fws, docs, nil
}

func (s *Server) handleDeployCheck(c *echo.Context) error {
	st, err := s.settings()
	if err != nil {
		return err
	}
	var names []string
	if q := c.QueryParam("instances"); q != "" {
		names = strings.Split(q, ",")
	}
	only, err := s.chosenScope(currentAccess(c), names, true)
	if err != nil {
		return dbError(c, err)
	}
	_, docs, err := s.firewallDocs(only)
	problems := []string{}
	var ve *fwconfig.ValidationError
	var br *badRequest
	switch {
	case errors.As(err, &ve):
		problems = ve.Problems
	case errors.As(err, &br):
		problems = []string{br.msg}
	case errors.Is(err, errForbidden):
		problems = []string{"you are not an admin of any virtual firewall"}
	case err != nil:
		return err
	}
	counts := map[string]int{"instances": 0, "links": 0}
	for _, doc := range docs {
		counts["links"] += len(doc.Links)
		for _, in := range doc.Instances {
			if only != nil && !only[in.Name] {
				continue
			}
			counts["instances"]++
			counts["interfaces"] += len(in.Interfaces)
			for _, r := range in.Rules {
				if r.Kind != fwconfig.RuleKindComment {
					counts["rules"]++
				}
			}
			counts["nat"] += len(in.NAT)
		}
	}
	if only != nil {
		delete(counts, "links")
	}
	return c.JSON(http.StatusOK, map[string]any{"problems": problems, "counts": counts, "generation": st.LastCommit})
}

// handleDeployPreview renders what a commit would write. With several
// firewalls each file's path starts with its firewall's name ("fw2:/etc/...").
func (s *Server) handleDeployPreview(c *echo.Context) error {
	var req struct {
		Instances []string `json:"instances"`
	}
	_ = c.Bind(&req)
	only, err := s.chosenScope(currentAccess(c), req.Instances, true)
	if err != nil {
		return dbError(c, err)
	}
	fws, docs, err := s.firewallDocs(only)
	if err != nil {
		return problemsResponse(c, err)
	}
	all := &agentapi.RenderResult{Files: []render.File{}, Current: []render.File{}, Rulesets: map[string]string{}}
	for i, fw := range fws {
		a, err := s.newAgent(&fw)
		if err != nil {
			return agentError(c, bad(fmt.Sprintf("firewall %s: %v", fw.Name, err)))
		}
		res, err := a.Render(c.Request().Context(), *docs[i])
		if err != nil {
			return agentError(c, fmt.Errorf("firewall %s: %w", fw.Name, err))
		}
		if only != nil {
			res.Files, res.Current = filterFiles(res.Files, only), filterFiles(res.Current, only)
		}
		prefix := ""
		if len(fws) > 1 {
			prefix = fw.Name + ":"
		}
		for _, f := range res.Files {
			f.Path = prefix + f.Path
			all.Files = append(all.Files, f)
		}
		for _, f := range res.Current {
			f.Path = prefix + f.Path
			all.Current = append(all.Current, f)
		}
		for in, p := range res.Rulesets {
			all.Rulesets[in] = prefix + p
		}
	}
	return c.JSON(http.StatusOK, all)
}

// handleExportNftables downloads one virtual firewall's nftables ruleset as
// the agent renders it: the live one (from=live) or the one a commit would
// load (the default). It is Portitor's output, auto rules included.
func (s *Server) handleExportNftables(c *echo.Context) error {
	name := c.QueryParam("instance")
	if name == "" {
		return errJSON(c, http.StatusBadRequest, "instance is required")
	}
	live := c.QueryParam("from") == "live"
	only, err := s.chosenScope(currentAccess(c), []string{name}, true)
	if err != nil {
		return dbError(c, err)
	}
	a, fw, err := s.instanceAgent(name)
	if err != nil {
		return agentError(c, err)
	}
	doc, err := s.buildDoc(s.db, fw, fw.Generation+1, only)
	if err != nil {
		return problemsResponse(c, err)
	}
	res, err := a.Render(c.Request().Context(), *doc)
	if err != nil {
		return agentError(c, err)
	}
	files := res.Files
	if live {
		files = res.Current
	}
	path := res.Rulesets[name]
	i := slices.IndexFunc(files, func(f render.File) bool { return path != "" && f.Path == path })
	if i < 0 {
		return errJSON(c, http.StatusNotFound, "no nftables ruleset for "+name)
	}
	h := c.Response().Header()
	h.Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name+".nft"))
	return c.Blob(http.StatusOK, "text/plain; charset=utf-8", []byte(files[i].Content))
}

// haPeerOf is the id of the firewall's HA peer, or 0.
func haPeerOf(fws []models.Firewall, fw models.Firewall) uint {
	if fw.HAPrimaryID != nil {
		return *fw.HAPrimaryID
	}
	for _, f := range fws {
		if f.HAPrimaryID != nil && *f.HAPrimaryID == fw.ID {
			return f.ID
		}
	}
	return 0
}

// answers tells whether the firewall's agent answers.
func (s *Server) answers(ctx context.Context, fws []models.Firewall, id uint) bool {
	for _, f := range fws {
		if f.ID == id {
			a, err := s.newAgent(&f)
			if err != nil {
				return false
			}
			_, err = a.Status(ctx)
			return err == nil
		}
	}
	return false
}

func joinLog(lines []string) string { return strings.Join(lines, "\n") }
