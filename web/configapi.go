// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/labstack/echo/v5"

	"github.com/abundo/portitor/internal/builder"
	"github.com/abundo/portitor/internal/confcheck"
	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/schema"
	"github.com/abundo/portitor/models"
)

// The configuration API, on the datastore (RESTCONF-like, RFC 8040's paths
// and RFC 7951's JSON, without its envelope):
//
//	GET    /api/schema                       the compiled schema
//	GET    /api/config/<ds>/<path>           candidate, running or state
//	PUT    /api/config/candidate/<path>      replace (secrets left out kept)
//	PATCH  /api/config/candidate/<path>      merge
//	POST   /api/config/candidate/<list path> a new entry
//	DELETE /api/config/candidate/<path>
//	POST   /api/config/candidate/<entry>?action=rename  {"keys": [...]}
//	POST   /api/config/candidate/<entry>?action=move    {"where": "before", "key": [...]}
//	GET    /api/config/changes               the candidate against running
//	POST   /api/config/discard               the candidate back to running
//
// A path is /-separated steps, an entry's keys after "=", separated by ",",
// each percent-encoded: instance=main/interface=eth0/mtu. A body is what is
// at the path: an object for a container or entry, an array for a whole
// list, a value for a leaf. Secrets are never read back.

// configPrefix starts every configuration path.
const configPrefix = "/api/config/"

// parseConfigPath reads the RESTCONF path after the datastore.
func parseConfigPath(raw string) (datastore.Path, error) {
	var p datastore.Path
	for _, step := range strings.Split(strings.Trim(raw, "/"), "/") {
		if step == "" {
			continue
		}
		name, keys, hasKeys := strings.Cut(step, "=")
		name, err := url.PathUnescape(name)
		if err != nil {
			return nil, err
		}
		if i := strings.IndexByte(name, ':'); i >= 0 {
			if name[:i] != schema.Module {
				return nil, errors.New("unknown module " + name[:i])
			}
			name = name[i+1:]
		}
		e := datastore.Elem{Name: name}
		if hasKeys {
			e.Keys = []string{}
			for _, k := range strings.Split(keys, ",") {
				v, err := url.PathUnescape(k)
				if err != nil {
					return nil, err
				}
				e.Keys = append(e.Keys, v)
			}
		}
		p = append(p, e)
	}
	return p, nil
}

// configRequest is a request's datastore and path.
func configRequest(c *echo.Context) (ds string, p datastore.Path, err error) {
	rest := strings.TrimPrefix(c.Request().URL.EscapedPath(), configPrefix)
	ds, raw, _ := strings.Cut(rest, "/")
	p, err = parseConfigPath(raw)
	return ds, p, err
}

// treeAccessOf is the request user's access to the tree.
func (s *Server) treeAccessOf(c *echo.Context) treeAccess {
	a := currentAccess(c)
	return treeAccess{a: a, read: a.readableNames(), write: a.writableNames(), readOnly: s.isReplica()}
}

func (s *Server) handleSchema(c *echo.Context) error {
	t, err := s.tree()
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, t.schema.Export())
}

func (s *Server) handleConfigGet(c *echo.Context) error {
	ds, p, err := configRequest(c)
	if err != nil {
		return errJSON(c, http.StatusBadRequest, "path: "+err.Error())
	}
	if name := c.QueryParam("action"); name != "" {
		return s.runAction(c, ds, p, name, nil)
	}
	t, err := s.tree()
	if err != nil {
		return err
	}
	ctx := c.Request().Context()
	var tree *datastore.Tree
	switch ds {
	case "candidate":
		tree, err = t.store.Candidate(ctx)
	case "running":
		tree, err = t.store.Running(ctx)
	case "state":
		tree, err = s.stateTree(ctx, currentUser(c))
	default:
		return errJSON(c, http.StatusNotFound, "no datastore "+ds+": candidate, running or state")
	}
	if err != nil {
		return err
	}
	acc := s.treeAccessOf(c)
	if len(p) > 0 && !acc.CanRead(p[:1]) {
		return errJSON(c, http.StatusNotFound, "not found")
	}
	body, err := configJSON(tree.Visible(acc.CanRead), p)
	if err != nil {
		var nf *notFound
		if errors.As(err, &nf) {
			return errJSON(c, http.StatusNotFound, nf.Error())
		}
		return errJSON(c, http.StatusBadRequest, err.Error())
	}
	return c.JSONBlob(http.StatusOK, body)
}

type notFound struct{ what string }

func (e *notFound) Error() string { return e.what + " is not there" }

// configJSON is the JSON of what is at p in t.
func configJSON(t *datastore.Tree, p datastore.Path) ([]byte, error) {
	ss, err := datastore.ResolveAll(t.Root.S, p)
	if err != nil {
		return nil, err
	}
	o := datastore.JSONOptions{SecretsSet: true}
	if len(p) == 0 {
		return t.JSON(o)
	}
	s := ss[len(ss)-1]
	what := p.String(t.Root.S)
	if s.Kind == schema.List && p[len(p)-1].Keys == nil && len(s.Keys) > 0 {
		parent, _, err := t.Find(p[:len(p)-1])
		if err != nil {
			return nil, err
		}
		var b bytes.Buffer
		b.WriteByte('[')
		if parent != nil {
			for i, e := range parent.Lists[s.Name] {
				if i > 0 {
					b.WriteByte(',')
				}
				data, err := datastore.NodeJSON(e, o)
				if err != nil {
					return nil, err
				}
				b.Write(data)
			}
		}
		b.WriteByte(']')
		return b.Bytes(), nil
	}
	n, leaf, err := t.Find(p)
	if err != nil {
		return nil, err
	}
	if n == nil {
		return nil, &notFound{what}
	}
	if leaf == nil {
		return datastore.NodeJSON(n, o)
	}
	if leaf.Secret() {
		return nil, &notFound{what}
	}
	if leaf.Kind == schema.LeafList {
		vs, ok := n.LeafLists[leaf.Name]
		if !ok {
			return nil, &notFound{what}
		}
		return json.Marshal(datastore.LeafValues(leaf, vs))
	}
	v, ok := n.Leaves[leaf.Name]
	if !ok {
		return nil, &notFound{what}
	}
	return json.Marshal(datastore.LeafValue(leaf, v))
}

// handleConfigEdit is every change of the candidate.
func (s *Server) handleConfigEdit(c *echo.Context) error {
	ds, p, err := configRequest(c)
	if err != nil {
		return errJSON(c, http.StatusBadRequest, "path: "+err.Error())
	}
	if ds != "candidate" {
		return errJSON(c, http.StatusMethodNotAllowed, "only the candidate can be changed")
	}
	body, err := io.ReadAll(io.LimitReader(c.Request().Body, 32<<20))
	if err != nil {
		return err
	}
	method, action := c.Request().Method, c.QueryParam("action")
	if method == http.MethodPost && action != "" && action != "rename" && action != "move" {
		return s.runAction(c, ds, p, action, body)
	}
	t, err := s.tree()
	if err != nil {
		return err
	}
	acc := s.treeAccessOf(c)
	var denied string
	var created []string // a POST's new entry's keys
	var warnings []error // what a commit would refuse that was so before
	scope, err := s.deployScope(currentAccess(c))
	if err != nil {
		return err
	}
	err = t.store.Edit(c.Request().Context(), "", func(work *datastore.Tree) error {
		before := work.Clone()
		if method == http.MethodPost && action == "" {
			if body, err = s.assignID(work, p, body); err != nil {
				return err
			}
			created = newEntryKeys(work, p, body)
		}
		if err := applyConfigEdit(work, p, method, action, body); err != nil {
			return err
		}
		warnings, denied, err = s.checkEdit(acc, scope, before, work)
		if err != nil {
			return err
		}
		return nil
	})
	switch {
	case errors.Is(err, errForbidden):
		if acc.readOnly {
			return errJSON(c, http.StatusForbidden, "this is the HA secondary: its configuration is a read-only copy of the primary's")
		}
		return errJSON(c, http.StatusForbidden, "you may not change "+denied)
	case err != nil:
		return configError(c, err)
	}
	status := http.StatusOK
	switch {
	case method == http.MethodPost && action == "":
		status = http.StatusCreated
	case method == http.MethodDelete:
		status = http.StatusNoContent
	}
	// What a commit would refuse now, as warnings: the documents built and
	// checked as the commit does (fwconfig.Validate), for the instances the
	// user deploys. The save stands; the user finishes the change.
	out := map[string]any{}
	if len(warnings) > 0 {
		ws := make([]string, len(warnings))
		for i, w := range warnings {
			ws[i] = w.Error()
		}
		out["warnings"] = ws
	}
	// A new entry: its keys, and its path as Location.
	if created != nil {
		out["keys"] = created
		ep := slices.Clone(p)
		ep[len(ep)-1].Keys = created
		c.Response().Header().Set("Location", configPrefix+ds+"/"+formatConfigPath(ep))
	}
	if len(out) == 0 {
		return c.NoContent(status)
	}
	if status == http.StatusNoContent {
		status = http.StatusOK
	}
	return c.JSON(status, out)
}

// newEntryKeys are the keys of the entry a POST at the list path p makes
// of body, canonical; nil when p is not a list's or the body has no keys.
func newEntryKeys(t *datastore.Tree, p datastore.Path, body []byte) []string {
	ss, err := datastore.ResolveAll(t.Root.S, p)
	if err != nil || len(p) == 0 || p[len(p)-1].Keys != nil {
		return nil
	}
	list := ss[len(ss)-1]
	if list.Kind != schema.List || len(list.Keys) == 0 {
		return nil
	}
	var obj map[string]any
	if json.Unmarshal(body, &obj) != nil {
		return nil
	}
	keys := make([]string, len(list.Keys))
	for i, k := range list.Keys {
		v, ok := obj[k]
		if !ok {
			return nil
		}
		raw := fmt.Sprint(v)
		if f, ok := v.(float64); ok {
			raw = strconv.FormatFloat(f, 'f', -1, 64)
		}
		c, err := list.Child(k).Type.Check(raw)
		if err != nil {
			return nil
		}
		keys[i] = c
	}
	return keys
}

// formatConfigPath writes p as a RESTCONF path, the inverse of
// parseConfigPath.
func formatConfigPath(p datastore.Path) string {
	parts := make([]string, len(p))
	for i, e := range p {
		parts[i] = url.PathEscape(e.Name)
		if e.Keys != nil {
			ks := make([]string, len(e.Keys))
			for j, k := range e.Keys {
				ks[j] = strings.ReplaceAll(url.PathEscape(k), ",", "%2C")
			}
			parts[i] += "=" + strings.Join(ks, ",")
		}
	}
	return strings.Join(parts, "/")
}

// buildProblems are the problems the commit's build finds in tree, for
// the instances only (nil: all).
func (s *Server) buildProblems(tree *datastore.Tree, only map[string]bool) []error {
	_, _, err := s.firewallDocsOf(builder.Input{DB: s.db, Tree: tree}, only)
	var ve *fwconfig.ValidationError
	if !errors.As(err, &ve) {
		return nil
	}
	out := make([]error, len(ve.Problems))
	for i, p := range ve.Problems {
		out[i] = errors.New(p)
	}
	return out
}

// applyConfigEdit makes the change a request asks for in work.
func applyConfigEdit(work *datastore.Tree, p datastore.Path, method, action string, body []byte) error {
	switch {
	case method == http.MethodPost && action == "rename":
		var req struct {
			Keys []string `json:"keys"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			return &datastore.Error{Path: p.String(work.Root.S), Msg: "the body: " + err.Error()}
		}
		return work.Rename(p, req.Keys)
	case method == http.MethodPost && action == "move":
		var req struct {
			Where string   `json:"where"`
			Key   []string `json:"key"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			return &datastore.Error{Path: p.String(work.Root.S), Msg: "the body: " + err.Error()}
		}
		if !slices.Contains([]string{"first", "last", "before", "after"}, req.Where) {
			return &datastore.Error{Path: p.String(work.Root.S), Msg: "where: first, last, before or after"}
		}
		return work.Move(p, req.Where, req.Key)
	case action != "":
		return &datastore.Error{Path: p.String(work.Root.S), Msg: "no action " + action + ": rename or move"}
	case method == http.MethodPut:
		return work.EditJSON(p, datastore.EditReplace, body)
	case method == http.MethodPatch:
		return work.EditJSON(p, datastore.EditMerge, body)
	case method == http.MethodPost:
		return work.EditJSON(p, datastore.EditCreate, body)
	case method == http.MethodDelete:
		if len(p) > 0 && p[len(p)-1].Keys == nil {
			if ss, err := datastore.ResolveAll(work.Root.S, p); err == nil && ss[len(ss)-1].Kind == schema.List && len(ss[len(ss)-1].Keys) > 0 {
				return work.EditJSON(p, datastore.EditReplace, []byte("[]"))
			}
		}
		return work.Delete(p)
	}
	return &datastore.Error{Path: p.String(work.Root.S), Msg: method + " is not a change"}
}

// configError answers a datastore's error: what is wrong where, or a lock.
func configError(c *echo.Context, err error) error {
	var le *datastore.LockedError
	if errors.As(err, &le) {
		return errJSON(c, http.StatusConflict, le.Error())
	}
	var de *datastore.Error
	if errors.As(err, &de) {
		return c.JSON(http.StatusBadRequest, map[string]any{"error": de.Msg, "path": de.Path})
	}
	var ve *datastore.ValidationError
	if errors.As(err, &ve) && len(ve.Problems) == 1 {
		return configError(c, ve.Problems[0])
	}
	if errors.As(err, &ve) {
		problems := make([]string, len(ve.Problems))
		for i, p := range ve.Problems {
			problems[i] = p.Error()
		}
		return c.JSON(http.StatusBadRequest, map[string]any{"error": "the candidate is not valid", "problems": problems})
	}
	return errJSON(c, http.StatusBadRequest, err.Error())
}

// handleConfigChanges is the candidate against running: whether they
// differ, and the difference as the CLI's diff, of what the user reads.
func (s *Server) handleConfigChanges(c *echo.Context) error {
	t, err := s.tree()
	if err != nil {
		return err
	}
	ctx := c.Request().Context()
	cand, err := t.store.Candidate(ctx)
	if err != nil {
		return err
	}
	run, err := t.store.Running(ctx)
	if err != nil {
		return err
	}
	acc := s.treeAccessOf(c)
	cand, run = cand.Visible(acc.CanRead), run.Visible(acc.CanRead)
	var b bytes.Buffer
	datastore.DiffText(&b, run, cand, nil)
	return c.JSON(http.StatusOK, map[string]any{"changed": !datastore.Equal(run, cand), "diff": b.String()})
}

// handleConfigDiscard sets the candidate back to running (Revert).
func (s *Server) handleConfigDiscard(c *echo.Context) error {
	if !currentAccess(c).isAdmin() {
		return errJSON(c, http.StatusForbidden, "only a global admin discards the shared candidate")
	}
	t, err := s.tree()
	if err != nil {
		return err
	}
	if err := t.store.Discard(c.Request().Context(), ""); err != nil {
		return configError(c, err)
	}
	return c.NoContent(http.StatusNoContent)
}

// assignID gives a new entry of a list keyed by a numeric id (rules, NAT
// rules, routes, DNS records, ...) its id when the body has none: one
// above every id the list has had, here or in running, and never one given
// before (a rule's id marks its connections), from the high-water marks in
// ids.json next to the database. The store's lock is held.
func (s *Server) assignID(work *datastore.Tree, p datastore.Path, body []byte) ([]byte, error) {
	ss, err := datastore.ResolveAll(work.Root.S, p)
	if err != nil || len(ss) == 0 || len(p) == 0 || p[len(p)-1].Keys != nil {
		return body, nil
	}
	list := ss[len(ss)-1]
	if list.Kind != schema.List || len(list.Keys) != 1 || !list.Child(list.Keys[0]).Type.Numeric() {
		return body, nil
	}
	key := list.Keys[0]
	var obj map[string]any
	if json.Unmarshal(body, &obj) != nil {
		return body, nil // EditJSON says what is wrong
	}
	if _, ok := obj[key]; ok {
		return body, nil
	}
	if _, ok := obj[schema.Module+":"+key]; ok {
		return body, nil
	}
	t, err := s.tree()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(t.dir, "ids.json")
	if t.idMarks == nil {
		t.idMarks = map[string]uint64{}
		if data, err := os.ReadFile(path); err == nil && t.dir != "" {
			_ = json.Unmarshal(data, &t.idMarks)
		}
	}
	marks := t.idMarks
	next := marks[list.Path()]
	trees := []*datastore.Tree{work}
	if run, err := (treeBackend{s}).Running(context.Background()); err == nil {
		trees = append(trees, run)
	}
	for _, tr := range trees {
		tr.Root.Walk(func(n *datastore.Node) {
			if n.S == list {
				if id, err := strconv.ParseUint(n.Leaf(key), 10, 64); err == nil && id > next {
					next = id
				}
			}
		})
	}
	next++
	marks[list.Path()] = next
	if t.dir != "" {
		data, _ := json.Marshal(marks)
		if err := datastore.WriteFile(path, data); err != nil {
			return nil, err
		}
	}
	obj[key] = next
	return json.Marshal(obj)
}

// newProblems are the problems of after that before didn't have.
func newProblems(before, after []error) []error {
	had := map[string]bool{}
	for _, e := range before {
		had[e.Error()] = true
	}
	var out []error
	for _, e := range after {
		if !had[e.Error()] {
			out = append(out, e)
		}
	}
	return out
}

// firewallProblems are what is wrong with the tree's virtual firewalls by
// what portitor-config alone knows: on a firewall that exists and isn't an
// HA secondary (which runs its primary's), and only one per firewall
// while Settings has virtual firewalls off.
func (s *Server) firewallProblems(tree *datastore.Tree) []error {
	fws, err := s.firewalls()
	if err != nil {
		return []error{err}
	}
	byName := map[string]models.Firewall{}
	for _, fw := range fws {
		byName[fw.Name] = fw
	}
	vfs := true
	if st := tree.Root.Containers["settings"]; st != nil {
		vfs = st.Leaf("virtual-firewalls") == "true"
	}
	var errs []error
	count := map[string]int{}
	for _, in := range tree.Root.Lists["instance"] {
		at := datastore.PathOf(in).String(tree.Root.S)
		name := in.Leaf("firewall")
		fw, ok := byName[name]
		switch {
		case !ok:
			errs = append(errs, &datastore.Error{Path: at, Msg: "firewall: no firewall " + name})
		case fw.HAPrimaryID != nil:
			errs = append(errs, &datastore.Error{Path: at, Msg: "firewall: " + name + " is an HA secondary; it runs its primary's virtual firewalls"})
		}
		count[name]++
		if !vfs && count[name] == 2 {
			errs = append(errs, &datastore.Error{Path: at, Msg: "virtual firewalls are off (Settings): a firewall has its host alone"})
		}
	}
	return errs
}

// checkEdit checks a change of the candidate from before to work: the
// user may make it (denied names a path they may not change), and it adds
// no problem (the schema's, the hooks', the firewalls', the build's).
// What the build finds that was so before comes back as warnings.
func (s *Server) checkEdit(acc treeAccess, scope map[string]bool, before, work *datastore.Tree) (warnings []error, denied string, err error) {
	for _, ch := range datastore.Diff(before, work) {
		if !acc.CanWrite(ch.Path) {
			return nil, ch.Path.String(work.Root.S), errForbidden
		}
	}
	if !acc.a.isAdmin() {
		if err := tenantTreeCheck(before, work, acc.write); err != nil {
			return nil, "", err
		}
	}
	changed := datastore.ChangedEntries(before, work)
	if err := confcheck.Normalize(before, work, changed); err != nil {
		return nil, "", err
	}
	// A save may not make the candidate invalid by the schema where it
	// wasn't: a reference to nothing, a mandatory leaf missing, an entry
	// deleted that something refers to.
	if errs := newProblems(before.Validate(), work.Validate()); len(errs) > 0 {
		return nil, "", &datastore.ValidationError{Problems: errs}
	}
	// What the change breaks, in the entries changed or in those that
	// refer to them.
	if errs := newProblems(append(confcheck.Check(before), s.firewallProblems(before)...),
		append(confcheck.Check(work), s.firewallProblems(work)...)); len(errs) > 0 {
		return nil, "", &datastore.ValidationError{Problems: errs}
	}
	// And what the commit's build would find wrong that it didn't before;
	// what was already wrong is a warning.
	was := s.buildProblems(before, scope)
	warnings = s.buildProblems(work, scope)
	if errs := newProblems(was, warnings); len(errs) > 0 {
		return nil, "", &datastore.ValidationError{Problems: errs}
	}
	return warnings, "", nil
}
