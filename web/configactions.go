// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"slices"
	"strings"

	"github.com/labstack/echo/v5"

	"github.com/abundo/portitor/internal/acme"
	"github.com/abundo/portitor/internal/builder"
	"github.com/abundo/portitor/internal/cron"
	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/datastore/sqlmap"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/wgkeys"
	"github.com/abundo/portitor/models"
)

// Actions on the configuration's entries: what is generated or done
// rather than set (a WireGuard interface's new keys, a certificate made or
// renewed, a peer's client config, a download started), by the entry's
// path:
//
//	GET  /api/config/<ds>/<path>?action=<view>      a view (a client config, the next free address)
//	POST /api/config/candidate/<path>?action=<do>  a change or an operation
//
// An action is registered by the list's schema path; rename and move are
// every entry's (configapi.go).

// configAction is one action of a list's entries.
type configAction struct {
	// view: a GET, of the datastore asked for; else a POST, of the
	// candidate.
	view bool
	// op: a POST that changes no configuration (the agent renews a
	// certificate, downloads an IP list): run on a copy of the candidate,
	// not under its lock.
	op bool
	// write: the user must be allowed to change the entry (else to read
	// it).
	write bool
	// create: a change that makes the entry when it isn't there.
	create bool
	// legacy: a change made by a handler of the CRUD's time in the tables,
	// read into the candidate after (the tables hold it until the API is
	// all on the tree).
	legacy bool
	run    func(s *Server, c *echo.Context, a *actionCtx) error
}

// actionCtx is what an action gets: the tree it acts on (a copy for a
// view, the candidate's working copy for a change), the entry and its
// path.
type actionCtx struct {
	tree  *datastore.Tree
	path  datastore.Path
	entry *datastore.Node
	body  []byte
	// changed, set by a change, makes it the new candidate.
	changed bool
}

var configActions = map[string]map[string]configAction{}

func registerAction(listPath, name string, a configAction) {
	if configActions[listPath] == nil {
		configActions[listPath] = map[string]configAction{}
	}
	configActions[listPath][name] = a
}

// lookupAction is the action named on the entry at p, if there is one.
func lookupAction(t *datastore.Tree, p datastore.Path, name string) (configAction, bool) {
	ss, err := datastore.Resolve(t.Root.S, p)
	if err != nil || len(ss) == 0 {
		return configAction{}, false
	}
	a, ok := configActions[ss[len(ss)-1].Path()][name]
	return a, ok
}

// entryModel decodes the entry at p of tree into dst, a pointer to the
// model of its table, as the code that took a table's row expects it.
func (s *Server) entryModel(tree *datastore.Tree, p datastore.Path, dst any) error {
	t, err := s.tree()
	if err != nil {
		return err
	}
	n, _, err := tree.Find(p)
	if err != nil {
		return err
	}
	if n == nil {
		return &notFound{p.String(tree.Root.S)}
	}
	table := t.mapping.TableOf(n.S)
	if table == "" {
		return fmt.Errorf("%s is not a row of a table", p.String(tree.Root.S))
	}
	rows, idx, err := t.mapping.Rows(s.db, tree)
	if err != nil {
		return err
	}
	id := idx[n]
	for _, r := range rows[table] {
		if fmt.Sprint(r["id"]) == fmt.Sprint(id) {
			slice := reflect.New(reflect.SliceOf(reflect.TypeOf(dst).Elem()))
			if err := builder.DecodeRows([]sqlmap.Row{r}, slice.Interface()); err != nil {
				return err
			}
			reflect.ValueOf(dst).Elem().Set(slice.Elem().Index(0))
			return nil
		}
	}
	return errors.New("no row for " + p.String(tree.Root.S))
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
	if a.view != (c.Request().Method == http.MethodGet) {
		return errJSON(c, http.StatusMethodNotAllowed, "action "+name+": the wrong method")
	}
	if len(p) > 0 && !acc.CanRead(p[:1]) {
		return errJSON(c, http.StatusNotFound, "not found")
	}
	if a.write && !acc.CanWrite(p) {
		return errJSON(c, http.StatusForbidden, "you may not change "+p.String(tree.Root.S))
	}
	if a.view || a.op || a.legacy {
		n, _, err := tree.Find(p)
		if err != nil || n == nil {
			return errJSON(c, http.StatusNotFound, "not found")
		}
		err = a.run(s, c, &actionCtx{tree: tree, path: p, entry: n, body: body})
		if r, rerr := echo.UnwrapResponse(c.Response()); a.legacy && err == nil && rerr == nil && r.Status < 300 {
			if serr := s.syncFromTables(ctx); serr != nil {
				return serr
			}
		}
		return err
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
		if err == nil && n == nil && a.create {
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

// delegate is an action done by a handler of the CRUD's time, which takes
// the entry's row id as its :id: the tables hold the candidate (they are
// kept in step with it until the API is all on the tree).
func delegate(h echo.HandlerFunc) func(s *Server, c *echo.Context, a *actionCtx) error {
	return func(s *Server, c *echo.Context, a *actionCtx) error {
		t, err := s.tree()
		if err != nil {
			return err
		}
		tables, idx, err := t.mapping.Import(s.db)
		if err != nil {
			return err
		}
		n, _, err := tables.Find(a.path)
		if err != nil || n == nil {
			return errJSON(c, http.StatusNotFound, "not found")
		}
		c.SetPathValues(echo.PathValues{{Name: "id", Value: fmt.Sprint(idx[n])}})
		c.Request().Body = io.NopCloser(bytes.NewReader(a.body))
		return h(c)
	}
}

func init() {
	registerAction("/instance/interface/wireguard-peer", "client-config", configAction{view: true, write: true, run: delegateM((*Server).handleWgClientConfig)})
	registerAction("/instance/interface", "wg-next-free", configAction{view: true, run: delegateM((*Server).handleWgNextFree)})
	registerAction("/instance/interface", "openvpn-client", configAction{view: true, write: true, run: delegateM((*Server).handleOpenVPNClientConfig)})
	registerAction("/instance/interface", "wg-rekey", configAction{write: true, run: wgRekey})
	registerAction("/instance/interface", "move-to", configAction{write: true, run: moveInterface})
	registerAction("/instance/certificate", "download", configAction{view: true, write: true, run: delegateM((*Server).handleCertificateDownload)})
	registerAction("/instance/certificate", "renew", configAction{op: true, write: true, run: delegateM((*Server).handleCertificateRenew)})
	registerAction("/instance/ipam-prefix", "next-free", configAction{view: true, run: delegateM((*Server).handleNextFree)})
	registerAction("/ip-list", "refresh", configAction{op: true, run: delegateM((*Server).handleIPListRefresh)})
	registerAction("/instance/dns-blocklist", "refresh", configAction{op: true, write: true, run: delegateM((*Server).handleDNSBlocklistRefresh)})
	registerAction("/task", "run", configAction{op: true, write: true, run: delegateM((*Server).handleTaskRun)})
	registerAction("/instance", "bundle", configAction{view: true, write: true, run: delegateM((*Server).handleExportBundle)})
	registerAction("/instance/certificate", "generate", configAction{write: true, create: true, run: generateCert})
	registerAction("/instance/dns-zone", "records", configAction{write: true, legacy: true, run: delegateM((*Server).handleZoneRecords)})
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
	if len(cn) > 64 || strings.ContainsFunc(cn, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return errJSON(c, http.StatusBadRequest, "common-name: at most 64 characters, no control characters")
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
	if req.KeyType == "" {
		req.KeyType = fwconfig.CertKeyTypes[0]
	}
	if !slices.Contains(fwconfig.CertKeyTypes, req.KeyType) {
		return errJSON(c, http.StatusBadRequest, "key-type: one of "+strings.Join(fwconfig.CertKeyTypes, ", "))
	}
	if g.Days < 1 || g.Days > 36500 {
		return errJSON(c, http.StatusBadRequest, "days: 1-36500")
	}
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

func init() {
	registerAction("/ip-list", "schedule", configAction{write: true, run: ipListSchedule})
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
