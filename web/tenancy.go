// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"gorm.io/gorm"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/builder"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/render"
	"github.com/abundo/portitor/models"
)

// Per-instance deploy. A global admin deploys the whole database. An
// instance admin deploys their instances from the database and everything
// else (other instances, links, IP lists, tasks) as the firewall runs it,
// so they never push another tenant's unfinished changes. "As the firewall
// runs it" is the live deployment's document, kept unredacted next to the
// snapshots (<db dir>/deployed/<generation>.json, 0600, like the database).

func docPath(dir string, gen int64) string {
	return filepath.Join(dir, strconv.FormatInt(gen, 10)+".json")
}

// keepDocument stores the document a deployment applied.
func (s *Server) keepDocument(doc *fwconfig.Document) error {
	dir, err := s.snapshotDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	tmp := docPath(dir, doc.Generation) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, docPath(dir, doc.Generation))
}

// errNoLiveDocument: nothing deployed to build on.
var errNoLiveDocument = bad("a global admin has to deploy the whole configuration once before a virtual firewall admin can deploy")

// liveDocument is the document the firewall runs. Deployments from before
// documents were kept fall back to their database snapshot.
func (s *Server) liveDocument() (*fwconfig.Document, error) {
	live, err := s.liveDeployment()
	if err != nil {
		return nil, err
	}
	if live == nil {
		return nil, errNoLiveDocument
	}
	dir, err := s.snapshotDir()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(docPath(dir, live.Generation))
	if err == nil {
		var doc fwconfig.Document
		if err := json.Unmarshal(b, &doc); err != nil {
			return nil, err
		}
		return &doc, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	snap := snapshotPath(dir, live.Generation)
	if len(live.Instances) > 0 {
		return nil, errNoLiveDocument
	}
	if _, err := os.Stat(snap); err != nil {
		return nil, errNoLiveDocument
	}
	db, err := openSnapshot(snap)
	if err != nil {
		return nil, err
	}
	defer closeDB(db)
	doc, err := builder.Build(db, live.Generation)
	var ve *fwconfig.ValidationError
	if err != nil && !errors.As(err, &ve) {
		return nil, err
	}
	return doc, nil
}

// buildDoc builds the document to deploy from db. With only nil it is the
// whole database; otherwise only those instances come from db and the
// rest from the live document. Problems come back as a
// *fwconfig.ValidationError alongside the document.
func (s *Server) buildDoc(db *gorm.DB, gen int64, only map[string]bool) (*fwconfig.Document, error) {
	if only == nil {
		return builder.Build(db, gen)
	}
	if len(only) == 0 {
		return nil, errForbidden
	}
	live, err := s.liveDocument()
	if err != nil {
		return nil, err
	}
	part, err := builder.BuildInstances(db, gen, only)
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

// mergeInstances is live with the instances of part in place of those of
// the same name; new ones go last.
func mergeInstances(live, part *fwconfig.Document) *fwconfig.Document {
	doc := *live
	doc.Instances = make([]fwconfig.Instance, 0, len(live.Instances)+len(part.Instances))
	done := map[string]bool{}
	for _, in := range live.Instances {
		if i := slices.IndexFunc(part.Instances, func(p fwconfig.Instance) bool { return p.Name == in.Name }); i >= 0 {
			in = part.Instances[i]
			done[in.Name] = true
		}
		doc.Instances = append(doc.Instances, in)
	}
	for _, in := range part.Instances {
		if !done[in.Name] {
			doc.Instances = append(doc.Instances, in)
		}
	}
	return &doc
}

// deployScope is the set of instances the user deploys: nil (everything)
// for a global admin, otherwise the instances they are admin of.
func (s *Server) deployScope(a *access) (map[string]bool, error) {
	if a.isAdmin() {
		return nil, nil
	}
	return s.instanceNames(a.writable())
}

// previewScope is deployScope, or for a user who deploys nothing the
// instances they read (a viewer previews what a deploy would do).
func (s *Server) previewScope(a *access) (map[string]bool, error) {
	if a.readsAll() && len(a.writable()) == 0 {
		return nil, nil
	}
	only, err := s.deployScope(a)
	if err != nil || only == nil || len(only) > 0 {
		return only, err
	}
	return s.instanceNames(a.readable())
}

func sortedNames(set map[string]bool) models.StringList {
	out := models.StringList{}
	for n := range set {
		out = append(out, n)
	}
	slices.Sort(out)
	return out
}

// chosenScope is the scope of a deploy (or, with preview, a preview) of
// the named instances; none named is the default scope (deployScope,
// previewScope). Each must be one the user may deploy (or read).
func (s *Server) chosenScope(a *access, names []string, preview bool) (map[string]bool, error) {
	if len(names) == 0 {
		if preview {
			return s.previewScope(a)
		}
		return s.deployScope(a)
	}
	out := map[string]bool{}
	for _, n := range names {
		var in models.Instance
		if err := s.db.Where("name = ?", n).First(&in).Error; err != nil {
			return nil, bad("no such virtual firewall: " + n)
		}
		if !a.canWrite(in.ID) && !(preview && a.canRead(in.ID)) {
			return nil, bad("you can't deploy virtual firewall " + n)
		}
		out[n] = true
	}
	return out, nil
}

// mayFinish tells whether the user may confirm or roll back dep: a global
// admin any, an instance admin one that deployed only their instances.
func (s *Server) mayFinish(a *access, dep *models.Deployment) bool {
	if a.isAdmin() {
		return true
	}
	if dep == nil || len(dep.Instances) == 0 {
		return false
	}
	mine, err := s.deployScope(a)
	if err != nil {
		return false
	}
	for _, n := range dep.Instances {
		if !mine[n] {
			return false
		}
	}
	return true
}

// instanceChanges tells whether the named instances differ between the
// database and the live document, and how many problems they have.
func (s *Server) instanceChanges(names map[string]bool) (changed bool, problems int, err error) {
	part, err := builder.BuildInstances(s.db, 0, names)
	var ve *fwconfig.ValidationError
	if errors.As(err, &ve) {
		problems = len(ve.Problems)
	} else if err != nil {
		return false, 0, err
	}
	live, err := s.liveDocument()
	if err != nil {
		return true, problems, nil
	}
	for name := range names {
		a, b := live.Instance(name), part.Instance(name)
		if (a == nil) != (b == nil) {
			return true, problems, nil
		}
		if a == nil {
			continue
		}
		ja, _ := json.Marshal(a)
		jb, _ := json.Marshal(b)
		if string(ja) != string(jb) {
			return true, problems, nil
		}
	}
	return problems > 0, problems, nil
}

// filterFiles keeps the rendered files of the named instances.
func filterFiles(files []render.File, names map[string]bool) []render.File {
	out := []render.File{}
	for _, f := range files {
		for n := range names {
			if strings.Contains(f.Path, "/instances/"+n+"/") {
				out = append(out, f)
				break
			}
		}
	}
	return out
}

// ----- the agent's status, one tenant's share -----

func filterStatus(st *agentapi.Status, names map[string]bool) {
	st.Instances = slices.DeleteFunc(st.Instances, func(i agentapi.InstanceStatus) bool { return !names[i.Name] })
	st.DHCPLeases = slices.DeleteFunc(st.DHCPLeases, func(l agentapi.Lease) bool { return !names[l.Instance] })
	st.DynDNS = slices.DeleteFunc(st.DynDNS, func(d agentapi.DynDNSStatus) bool { return !names[d.Instance] })
	st.Certificates = slices.DeleteFunc(st.Certificates, func(c agentapi.CertificateStatus) bool { return !names[c.Instance] })
	st.NICs = []agentapi.NICStatus{}
	st.AntiLockout = nil
	st.LastError = ""
}

func filterLeases(l *agentapi.LeasesResponse, names map[string]bool) {
	l.Client = slices.DeleteFunc(l.Client, func(x agentapi.Lease) bool { return !names[x.Instance] })
	for k := range l.Server {
		if !names[k] {
			delete(l.Server, k)
		}
	}
}

func filterRoutes(t *agentapi.RoutingTableResponse, names map[string]bool) {
	t.Routes = slices.DeleteFunc(t.Routes, func(r agentapi.RouteEntry) bool { return !names[r.Instance] })
}

func filterNeighbours(n *agentapi.NeighboursResponse, names map[string]bool) {
	n.IP = slices.DeleteFunc(n.IP, func(x agentapi.IPNeighbour) bool { return !names[x.Instance] })
	n.LLDP = slices.DeleteFunc(n.LLDP, func(x agentapi.LLDPNeighbour) bool { return !names[x.Instance] })
	n.LLDPPorts = slices.DeleteFunc(n.LLDPPorts, func(x agentapi.LLDPPort) bool { return !names[x.Instance] })
}

func (s *Server) filterRuleCounters(rc *agentapi.RuleCountersResponse, ids []uint, names map[string]bool) error {
	var rules []uint
	if err := s.db.Model(&models.Rule{}).Where("instance_id IN ?", ids).Pluck("id", &rules).Error; err != nil {
		return err
	}
	keep := map[uint32]bool{}
	for _, id := range rules {
		keep[uint32(id)] = true
	}
	for id := range rc.Rules {
		if !keep[id] {
			delete(rc.Rules, id)
		}
	}
	for k := range rc.Drops {
		if !names[k] {
			delete(rc.Drops, k)
		}
	}
	return nil
}

func filterDNSQueryLog(l *agentapi.DNSQueryLogResponse, names map[string]bool) {
	l.Entries = slices.DeleteFunc(l.Entries, func(e agentapi.DNSQueryEntry) bool { return !names[e.Instance] })
}

func filterPacketLog(l *agentapi.PacketLogResponse, names map[string]bool) {
	l.Entries = slices.DeleteFunc(l.Entries, func(e agentapi.PacketLogEntry) bool { return !names[e.Instance] })
}

// filterDeployments keeps a tenant's share of the history: whole deploys
// (their log could tell of other instances, so it goes) and deploys of
// instances they read.
func filterDeployments(deps []models.Deployment, names map[string]bool) []models.Deployment {
	out := []models.Deployment{}
	for _, d := range deps {
		if len(d.Instances) == 0 {
			d.Log = ""
			out = append(out, d)
			continue
		}
		if slices.ContainsFunc(d.Instances, func(n string) bool { return names[n] }) {
			if !slices.ContainsFunc(d.Instances, func(n string) bool { return !names[n] }) {
				out = append(out, d)
				continue
			}
			d.Log = ""
			out = append(out, d)
		}
	}
	return out
}
