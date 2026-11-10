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
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/labstack/echo/v5"

	"github.com/abundo/portitor/internal/acme"
	"github.com/abundo/portitor/internal/cron"
	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/schema"
	"github.com/abundo/portitor/internal/wgkeys"
	"github.com/abundo/portitor/models"
)

// Actions on the configuration's entries: what is generated or done
// rather than set (a WireGuard interface's new keys, a certificate made or
// renewed, a download started), by the entry's path:
//
//	GET  /api/config/<ds>/<path>?action=<view>      a view (the next free address)
//	POST /api/config/candidate/<path>?action=<do>  an operation or a change
//
// The YANG modules declare them (action, with px:action its kind and its
// typed input and output): the CLI's tools and NETCONF's <action> run them
// through here too (Env.Action). Their handlers are here, by the list's
// schema path and the action's name; the input they get is checked and
// canonical (datastore.ReadValues), and what they answer is the output's
// JSON. A view asked of a whole list (its path without keys) gets the
// list's parent as its entry and answers each entry's output by key, if
// it can (chain).
//
// The GUI's own actions, which answer a file (a client config, a
// download, a bundle), fit no other frontend and are not in YANG
// (guiActions): views, of a GET. Rename and move are every entry's
// (configapi.go).

// actionHandler runs an action.
type actionHandler func(s *Server, c *echo.Context, a *actionCtx) error

// actionCtx is what an action gets: the tree it acts on (a copy for a
// view or operation, the candidate's working copy for a change), the entry
// and its path.
type actionCtx struct {
	tree  *datastore.Tree
	path  datastore.Path
	entry *datastore.Node
	body  []byte
	// list: a view asked of a whole list (its path without keys), whose
	// entry is the list's parent.
	list bool
	// changed, set by a change, makes it the new candidate.
	changed bool
}

// actionHandlers are the YANG actions' handlers, by list path and name
// ("/instance/interface wg-rekey"); TestActionHandlers checks that each
// action has one, and each one its action.
var actionHandlers = map[string]actionHandler{}

func registerAction(listPath, name string, h actionHandler) {
	actionHandlers[listPath+" "+name] = h
}

// guiAction is one of the GUI's own actions: a view (GET) that answers a
// file. write: the user must be allowed to change the entry (it hands out
// its secrets), else to read it.
type guiAction struct {
	write bool
	run   actionHandler
}

var guiActions = map[string]guiAction{}

func registerGUIAction(listPath, name string, a guiAction) {
	guiActions[listPath+" "+name] = a
}

// resolvedAction is an action as runAction runs it.
type resolvedAction struct {
	kind  string       // a schema.Action* kind
	write bool         // the user must be allowed to change the entry
	input *schema.Node // the input's schema; nil for a GUI action
	run   actionHandler
}

// lookupAction is the action named on the entry (or list) at p, if there
// is one.
func lookupAction(t *datastore.Tree, p datastore.Path, name string) (resolvedAction, bool) {
	ss, err := datastore.ResolveAll(t.Root.S, p)
	if err != nil || len(ss) == 0 {
		return resolvedAction{}, false
	}
	list := ss[len(ss)-1]
	key := list.Path() + " " + name
	if a := list.Action(name); a != nil {
		h := actionHandlers[key]
		if h == nil {
			return resolvedAction{}, false
		}
		return resolvedAction{kind: a.Kind, write: a.Writes(), input: a.Input, run: h}, true
	}
	if g, ok := guiActions[key]; ok {
		return resolvedAction{kind: schema.ActionView, write: g.write, run: g.run}, true
	}
	return resolvedAction{}, false
}

// runAction runs the action named on the entry of the request's path.
func (s *Server) runAction(c *echo.Context, ds string, p datastore.Path, name string, body []byte) error {
	t, err := s.tree()
	if err != nil {
		return err
	}
	ctx := c.Request().Context()
	acc := s.treeAccessOf(c)
	var tree *datastore.Tree
	if ds == "running" {
		tree, err = t.store.Running(ctx)
	} else {
		tree, err = t.store.Candidate(ctx)
	}
	if err != nil {
		return err
	}
	a, ok := lookupAction(tree, p, name)
	if !ok {
		return errJSON(c, http.StatusBadRequest, "no action "+name+" here")
	}
	view, op := a.kind == schema.ActionView, a.kind == schema.ActionOperation
	if view != (c.Request().Method == http.MethodGet) {
		return errJSON(c, http.StatusMethodNotAllowed, "action "+name+": the wrong method")
	}
	if a.input != nil {
		in, err := datastore.ReadValues(a.input, body)
		if err != nil {
			return errJSON(c, http.StatusBadRequest, "action "+name+": "+err.Error())
		}
		if body, err = datastore.ValuesJSON(in); err != nil {
			return err
		}
	}
	if len(p) > 0 && !acc.CanRead(p[:1]) {
		return errJSON(c, http.StatusNotFound, "not found")
	}
	if a.write && !acc.CanWrite(p) {
		return errJSON(c, http.StatusForbidden, "you may not change "+p.String(tree.Root.S))
	}
	if view || op {
		find, list := p, false
		if view && len(p) > 0 && p[len(p)-1].Keys == nil {
			find, list = p[:len(p)-1], true
		}
		n, _, err := tree.Find(find)
		if err != nil || n == nil {
			return errJSON(c, http.StatusNotFound, "not found")
		}
		return a.run(s, c, &actionCtx{tree: tree, path: p, entry: n, body: body, list: list})
	}
	if ds != "candidate" {
		return errJSON(c, http.StatusMethodNotAllowed, "only the candidate can be changed")
	}
	// A change: on the candidate's working copy, under its lock, checked
	// as any edit (checkEdit). The action's answer is held until the copy
	// has become the candidate, or is the answer when it changed nothing.
	scope, err := s.deployScope(currentAccess(c))
	if err != nil {
		return err
	}
	rec := httptest.NewRecorder()
	var answered error
	var denied string
	var warnings []error
	err = t.store.Edit(ctx, "", func(work *datastore.Tree) error {
		before := work.Clone()
		n, _, err := work.Find(p)
		if err == nil && n == nil && a.kind == schema.ActionCreate {
			n, err = work.Ensure(p)
		}
		if err != nil || n == nil {
			return &notFound{p.String(work.Root.S)}
		}
		ac := &actionCtx{tree: work, path: p, entry: n, body: body}
		orig := c.Response()
		c.SetResponse(rec)
		answered = a.run(s, c, ac)
		c.SetResponse(orig)
		if answered != nil || rec.Code >= 300 || !ac.changed {
			return errNoChange
		}
		warnings, denied, err = s.checkEdit(acc, scope, before, work)
		return err
	})
	var nf *notFound
	switch {
	case answered != nil:
		return answered
	case errors.Is(err, errNoChange), err == nil:
		return copyRecorded(c, rec, warnings)
	case errors.As(err, &nf):
		return errJSON(c, http.StatusNotFound, nf.Error())
	case errors.Is(err, errForbidden):
		return errJSON(c, http.StatusForbidden, "you may not change "+denied)
	}
	return configError(c, err)
}

// errNoChange ends an Edit that changed nothing.
var errNoChange = errors.New("no change")

// delegate is an action done by a handler that takes the entry's id
// (sqlmap.IDs) as its :id.
func delegate(h echo.HandlerFunc) func(s *Server, c *echo.Context, a *actionCtx) error {
	return func(s *Server, c *echo.Context, a *actionCtx) error {
		id, ok, err := s.entryID(c.Request().Context(), a.path)
		if err != nil {
			return err
		}
		if !ok {
			return errJSON(c, http.StatusNotFound, "not found")
		}
		c.SetPathValues(echo.PathValues{{Name: "id", Value: fmt.Sprint(id)}})
		c.Request().Body = io.NopCloser(bytes.NewReader(a.body))
		return h(c)
	}
}

func init() {
	registerAction("/instance/interface", "wg-rekey", wgRekey)
	registerAction("/instance/interface", "move-to", moveInterface)
	registerAction("/instance/interface", "wg-next-free", delegateM((*Server).handleWgNextFree))
	registerAction("/instance/certificate", "chain", certChain)
	registerAction("/instance/certificate", "renew", delegateM((*Server).handleCertificateRenew))
	registerAction("/instance/certificate", "generate", generateCert)
	registerAction("/instance/ipam-prefix", "next-free", delegateM((*Server).handleNextFree))
	registerAction("/ip-list", "update", delegateM((*Server).handleIPListRefresh))
	registerAction("/ip-list", "schedule", ipListSchedule)
	registerAction("/instance/dns-blocklist", "update", delegateM((*Server).handleDNSBlocklistRefresh))
	registerAction("/task", "run", delegateM((*Server).handleTaskRun))

	registerGUIAction("/instance/interface/wireguard-peer", "client-config", guiAction{write: true, run: delegateM((*Server).handleWgClientConfig)})
	registerGUIAction("/instance/interface", "openvpn-client", guiAction{write: true, run: delegateM((*Server).handleOpenVPNClientConfig)})
	registerGUIAction("/instance/certificate", "download", guiAction{write: true, run: delegateM((*Server).handleCertificateDownload)})
	registerGUIAction("/instance", "bundle", guiAction{write: true, run: delegateM((*Server).handleExportBundle)})
}

// delegateM is delegate for a method of the server.
func delegateM(m func(*Server, *echo.Context) error) func(s *Server, c *echo.Context, a *actionCtx) error {
	return func(s *Server, c *echo.Context, a *actionCtx) error {
		return delegate(func(c *echo.Context) error { return m(s, c) })(s, c, a)
	}
}

// wgRekey gives a WireGuard interface new keys; its peers need the new
// public key.
func wgRekey(s *Server, c *echo.Context, a *actionCtx) error {
	if a.entry.Leaf("kind") != fwconfig.KindWireGuard {
		return errJSON(c, http.StatusBadRequest, "not a WireGuard interface")
	}
	priv, pub, err := wgkeys.Generate()
	if err != nil {
		return err
	}
	a.entry.Leaves["wg-private-key"], a.entry.Leaves["wg-public-key"] = priv, pub
	a.changed = true
	return c.JSON(http.StatusOK, map[string]string{"wg-public-key": pub})
}

// certChain is what an imported certificate's chain says (CA or not,
// issuer, the certification path, validity) and whether it has its key:
// of the entry, or, asked of the whole list, of each by name.
func certChain(s *Server, c *echo.Context, a *actionCtx) error {
	type info struct {
		IsCA      bool       `json:"is-ca"`
		Issuer    string     `json:"issuer,omitempty"`
		Chain     []string   `json:"chain,omitempty"`
		NotBefore *time.Time `json:"not-before,omitempty"`
		NotAfter  *time.Time `json:"not-after,omitempty"`
		HasKey    bool       `json:"has-key"`
	}
	of := func(n *datastore.Node) info {
		in := info{HasKey: n.Leaf("priv-key") != ""}
		if n.Leaf("source") != fwconfig.CertSourceImport {
			return in
		}
		if leaf := fwconfig.ChainLeaf(n.Leaf("full-chain")); leaf != nil {
			in.IsCA, in.Issuer = leaf.IsCA, leaf.Issuer.CommonName
			in.Chain = fwconfig.ChainPath(n.Leaf("full-chain"))
			in.NotBefore, in.NotAfter = &leaf.NotBefore, &leaf.NotAfter
		}
		return in
	}
	if !a.list {
		return c.JSON(http.StatusOK, of(a.entry))
	}
	out := map[string]info{}
	for _, e := range a.entry.Lists["certificate"] {
		out[e.Leaf("name")] = of(e)
	}
	return c.JSON(http.StatusOK, out)
}

// moveInterface moves an interface, with its addresses and peers, to
// another virtual firewall, {"instance": "<name>"}: one change, refused
// as any other when what refers to it in the old one (rules, routes,
// VLANs) would be left without it.
func moveInterface(s *Server, c *echo.Context, a *actionCtx) error {
	var req struct {
		Instance string `json:"instance"`
	}
	if err := json.Unmarshal(a.body, &req); err != nil {
		return errJSON(c, http.StatusBadRequest, "the body: "+err.Error())
	}
	name := a.entry.Leaf("name")
	from := a.entry.Parent.Leaf("name")
	if req.Instance == from {
		return c.NoContent(http.StatusNoContent)
	}
	to := a.tree.Root.Entry("instance", []string{req.Instance})
	if to == nil {
		return errJSON(c, http.StatusBadRequest, "no virtual firewall "+req.Instance)
	}
	if to.Entry("interface", []string{name}) != nil {
		return errJSON(c, http.StatusBadRequest, req.Instance+" has an interface "+name)
	}
	data, err := datastore.NodeJSON(a.entry, datastore.JSONOptions{Secrets: true})
	if err != nil {
		return err
	}
	if err := a.tree.Delete(a.path); err != nil {
		return err
	}
	dst := datastore.Path{{Name: "instance", Keys: []string{req.Instance}}, {Name: "interface"}}
	if err := a.tree.EditJSON(dst, datastore.EditCreate, data); err != nil {
		return err
	}
	a.changed = true
	return c.NoContent(http.StatusNoContent)
}

// generateCert makes a certificate's key and chain here: self-signed, a
// CA (on the firewall's host alone), or signed by a CA of the host of its
// firewall. The certificate is an imported one from then on.
func generateCert(s *Server, c *echo.Context, a *actionCtx) error {
	var g struct {
		Domains    []string `json:"domains"`
		CommonName string   `json:"common-name"`
		KeyType    string   `json:"key-type"`
		Days       int      `json:"days"`
		CA         bool     `json:"ca"`
		SignedBy   string   `json:"signed-by"`
	}
	if err := json.Unmarshal(a.body, &g); err != nil {
		return errJSON(c, http.StatusBadRequest, "the body: "+err.Error())
	}
	in := a.entry.Parent
	if (g.CA || g.SignedBy != "") && !currentAccess(c).isAdmin() {
		return errJSON(c, http.StatusForbidden, "certificate authorities: global admins only")
	}
	if g.CA && in.Leaf("is-default") != "true" {
		return errJSON(c, http.StatusBadRequest, "a CA belongs to the firewall: add it on the firewall's host, not in a virtual firewall")
	}
	san := func(d string) bool {
		_, err := netip.ParseAddr(d)
		return err == nil || fwconfig.ValidDomain(strings.TrimPrefix(d, "*."))
	}
	var names []string
	for _, d := range g.Domains {
		d = dnsName(d)
		if ad, err := netip.ParseAddr(d); err == nil {
			d = ad.Unmap().WithZone("").String()
		} else if d != "" && !san(d) {
			return errJSON(c, http.StatusBadRequest, fmt.Sprintf("domains: %q is neither a DNS name nor an IP address", d))
		}
		if d != "" && !slices.Contains(names, d) {
			names = append(names, d)
		}
	}
	cn := strings.TrimSpace(g.CommonName)
	if !g.CA {
		cn = dnsName(cn)
	}
	req := acme.CertRequest{KeyType: g.KeyType, Days: g.Days, CA: g.CA}
	if g.CA {
		if g.SignedBy != "" {
			return errJSON(c, http.StatusBadRequest, "a CA here is self-signed: it signs server certificates, no other CA")
		}
		if len(names) > 0 {
			return errJSON(c, http.StatusBadRequest, "a CA has no subject alternative names")
		}
		if cn == "" {
			cn = a.entry.Leaf("name")
		}
	} else {
		if cn != "" && !slices.Contains(names, cn) && san(cn) {
			names = slices.Insert(names, 0, cn)
		}
		if len(names) == 0 || len(names) > 100 {
			return errJSON(c, http.StatusBadRequest, "domains: 1-100 DNS names or IP addresses")
		}
		if cn == "" {
			cn = names[0]
		}
	}
	req.CommonName, req.Names = cn, names
	if g.SignedBy != "" {
		ca := hostCA(a.tree, in, g.SignedBy)
		if ca == nil {
			return errJSON(c, http.StatusBadRequest, "signed-by: pick a CA of this firewall")
		}
		req.IssuerChain, req.IssuerKey = ca.Leaf("full-chain"), ca.Leaf("priv-key")
	}
	chain, key, err := acme.MakeCertificate(req)
	if err != nil {
		return errJSON(c, http.StatusBadRequest, err.Error())
	}
	e := a.entry
	for name := range e.Leaves {
		if name != "name" && name != "description" && name != "enabled" {
			delete(e.Leaves, name)
		}
	}
	delete(e.LeafLists, "domains")
	e.Leaves["source"], e.Leaves["full-chain"], e.Leaves["priv-key"] = fwconfig.CertSourceImport, chain, key
	a.changed = true
	return c.NoContent(http.StatusOK)
}

// hostCA is the CA certificate name of the host of in's firewall, or nil.
func hostCA(t *datastore.Tree, in *datastore.Node, name string) *datastore.Node {
	for _, h := range t.Root.Lists["instance"] {
		if h.Leaf("is-default") != "true" || h.Leaf("firewall") != in.Leaf("firewall") {
			continue
		}
		ca := h.Entry("certificate", []string{name})
		if ca == nil || ca.Leaf("source") != fwconfig.CertSourceImport {
			return nil
		}
		if leaf := fwconfig.ChainLeaf(ca.Leaf("full-chain")); leaf == nil || !leaf.IsCA {
			return nil
		}
		return ca
	}
	return nil
}

// ipListSchedule gives an IP list a task downloading it on schedule, on
// each firewall but an HA secondary, named after the list (and the
// firewall, with several).
func ipListSchedule(s *Server, c *echo.Context, a *actionCtx) error {
	var req struct {
		Schedule string `json:"schedule"`
	}
	if err := json.Unmarshal(a.body, &req); err != nil {
		return errJSON(c, http.StatusBadRequest, "the body: "+err.Error())
	}
	req.Schedule = strings.Join(strings.Fields(req.Schedule), " ")
	if _, err := cron.Parse(req.Schedule); err != nil {
		return errJSON(c, http.StatusBadRequest, "refresh schedule: "+err.Error())
	}
	var fws []models.Firewall
	if err := s.db.Where("ha_primary_id IS NULL").Order("id").Find(&fws).Error; err != nil {
		return err
	}
	root, list := a.tree.Root, a.entry.Leaf("name")
	var made []string
	for _, fw := range fws {
		base := list
		if len(fws) > 1 {
			base += "-" + fw.Name
		}
		name := base
		for i := 2; root.Entry("task", []string{name}) != nil; i++ {
			name = fmt.Sprintf("%s-%d", base, i)
		}
		t := root.AddEntry(root.S.Child("task"), map[string]string{"name": name})
		for k, v := range map[string]string{"description": "Downloads @" + list, "enabled": "true", "schedule": req.Schedule,
			"kind": fwconfig.TaskIPList, "ip-list": list, "firewall": fw.Name} {
			t.Leaves[k] = v
		}
		made = append(made, name)
	}
	a.changed = true
	return c.JSON(http.StatusOK, map[string]any{"tasks": made})
}

// configURLPath is p as /api/config's path (RFC 8040):
// instance=main/interface=eth1; parseConfigPath reads it.
func configURLPath(p datastore.Path) string {
	parts := make([]string, len(p))
	for i, e := range p {
		parts[i] = url.PathEscape(e.Name)
		if e.Keys != nil {
			keys := make([]string, len(e.Keys))
			for j, k := range e.Keys {
				keys[j] = strings.ReplaceAll(url.PathEscape(k), ",", "%2C")
			}
			parts[i] += "=" + strings.Join(keys, ",")
		}
	}
	return strings.Join(parts, "/")
}

// actionAs is the CLI's and NETCONF's Env.Action for the user u: the API's
// action, run in-process as u, its output read by the action's schema.
func (s *Server) actionAs(u *models.User) func(ctx context.Context, p datastore.Path, name string, input *datastore.Node, candidate bool) (*datastore.Node, []string, error) {
	return func(ctx context.Context, p datastore.Path, name string, input *datastore.Node, candidate bool) (*datastore.Node, []string, error) {
		t, err := s.tree()
		if err != nil {
			return nil, nil, err
		}
		ss, err := datastore.ResolveAll(t.schema, p)
		if err != nil || len(ss) == 0 || p[len(p)-1].Keys == nil {
			return nil, nil, fmt.Errorf("%s: not an entry", p.CLI())
		}
		a := ss[len(ss)-1].Action(name)
		if a == nil {
			return nil, nil, fmt.Errorf("%s has no action %s", ss[len(ss)-1].Name, name)
		}
		method, ds, body := http.MethodPost, "candidate", []byte(nil)
		if a.Kind == schema.ActionView {
			method = http.MethodGet
			if !candidate {
				ds = "running"
			}
		} else if input != nil {
			if body, err = datastore.ValuesJSON(input); err != nil {
				return nil, nil, err
			}
		}
		rec := s.recordAs(ctx, u, method, "/api/config/"+ds+"/"+configURLPath(p)+"?action="+url.QueryEscape(name), body)
		out, _ := io.ReadAll(rec.Result().Body)
		if rec.Code/100 != 2 {
			return nil, nil, errors.New(apiError(out))
		}
		var warnings []string
		if w := rec.Header().Get("X-Portitor-Warnings"); w != "" {
			warnings = strings.Split(w, "; ")
		}
		output, err := datastore.ReadValues(a.Output, out)
		if err != nil {
			return nil, warnings, fmt.Errorf("action %s answered what its output isn't: %w", name, err)
		}
		return output, warnings, nil
	}
}
