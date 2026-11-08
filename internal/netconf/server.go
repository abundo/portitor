// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package netconf is Portitor's NETCONF server (RFC 6241, over SSH as RFC
// 6242's netconf subsystem) on the configuration tree of internal/datastore:
// the candidate (shared with the CLI) and running, edit-config with every
// operation, subtree filters, validate, commit with confirmed-commit,
// locks, and get-schema for the YANG modules. Running is written only by
// a commit, as on SR Linux.
package netconf

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/abundo/portitor/internal/cli"
	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/schema"
	"github.com/abundo/portitor/yang"
)

var sessionIDs atomic.Uint32

// defaultConfirm is a confirmed commit's window without confirm-timeout.
const defaultConfirm = 600

// session is one client's.
type session struct {
	env   *cli.Env
	id    uint32
	owner string // the datastore's name for the session's locks
	f     *framer
}

// capabilities are the server's (RFC 6241 section 8, RFC 6022).
func capabilities(root *schema.Node) []string {
	return []string{
		"urn:ietf:params:netconf:base:1.0",
		"urn:ietf:params:netconf:base:1.1",
		"urn:ietf:params:netconf:capability:candidate:1.0",
		"urn:ietf:params:netconf:capability:confirmed-commit:1.1",
		"urn:ietf:params:netconf:capability:validate:1.1",
		"urn:ietf:params:netconf:capability:rollback-on-error:1.0",
		nsMonitoring + "?module=ietf-netconf-monitoring&revision=2010-10-04",
		schema.Namespace + "?module=" + schema.Module + "&revision=" + root.Revision,
		"urn:portitor:extensions?module=portitor-extensions&revision=" + root.Revision,
	}
}

// Serve runs a NETCONF session for env on rw (an SSH channel) until the
// client closes it.
func Serve(ctx context.Context, env *cli.Env, rw io.ReadWriter) error {
	s := &session{env: env, id: sessionIDs.Add(1), f: newFramer(rw)}
	s.owner = "netconf-" + strconv.Itoa(int(s.id))
	defer env.Store.Release(s.owner)

	var hello strings.Builder
	hello.WriteString(`<?xml version="1.0" encoding="UTF-8"?><hello xmlns="` + nsBase + `"><capabilities>`)
	for _, c := range capabilities(env.Schema) {
		hello.WriteString("<capability>" + escape(c) + "</capability>")
	}
	fmt.Fprintf(&hello, "</capabilities><session-id>%d</session-id></hello>", s.id)
	if err := s.f.write([]byte(hello.String())); err != nil {
		return err
	}
	msg, err := s.f.read()
	if err != nil {
		return err
	}
	h, err := parseXML(msg)
	if err != nil || h.Local != "hello" {
		return errors.New("netconf: the client's first message is not a hello")
	}
	base11 := false
	if caps := h.child("capabilities"); caps != nil {
		for _, c := range caps.Children {
			if c.text() == "urn:ietf:params:netconf:base:1.1" {
				base11 = true
			}
		}
	}
	s.f.chunked = base11
	for {
		msg, err := s.f.read()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if done, err := s.handle(ctx, msg); err != nil || done {
			return err
		}
	}
}

// handle answers one message; done ends the session.
func (s *session) handle(ctx context.Context, msg []byte) (done bool, err error) {
	rpc, perr := parseXML(msg)
	attrs := ""
	if perr == nil {
		for _, a := range rpc.Attrs {
			if a.Name.Space == "xmlns" || a.Name.Local == "xmlns" {
				continue
			}
			attrs += fmt.Sprintf(` %s="%s"`, a.Name.Local, escape(a.Value))
		}
	}
	reply := func(body string) error {
		return s.f.write([]byte(`<?xml version="1.0" encoding="UTF-8"?><rpc-reply xmlns="` + nsBase + `"` + attrs + ">" + body + "</rpc-reply>"))
	}
	switch {
	case perr != nil:
		return false, reply(errorXML(&rpcError{Type: "rpc", Tag: "malformed-message", Message: perr.Error()}))
	case rpc.Local != "rpc" || rpc.Space != nsBase:
		return false, reply(errorXML(&rpcError{Type: "rpc", Tag: "unknown-element", Message: "not an rpc: " + rpc.Local}))
	}
	if _, ok := rpc.attr("", "message-id"); !ok {
		return false, reply(errorXML(&rpcError{Type: "rpc", Tag: "missing-attribute", Message: "an rpc needs its message-id"}))
	}
	if len(rpc.Children) != 1 {
		return false, reply(errorXML(&rpcError{Type: "rpc", Tag: "malformed-message", Message: "an rpc holds one operation"}))
	}
	op := rpc.Children[0]
	body, err := s.operation(ctx, op)
	if err != nil {
		return false, reply(errorXML(asRPCError(err)))
	}
	if err := reply(body); err != nil {
		return true, err
	}
	return op.Local == "close-session", nil
}

func errorXML(e *rpcError) string {
	var b strings.Builder
	b.WriteString("<rpc-error><error-type>" + e.Type + "</error-type><error-tag>" + e.Tag + "</error-tag><error-severity>error</error-severity>")
	if e.Path != "" {
		b.WriteString("<error-path>" + escape(e.Path) + "</error-path>")
	}
	b.WriteString(`<error-message xml:lang="en">` + escape(e.Message) + "</error-message></rpc-error>")
	return b.String()
}

const ok = "<ok/>"

// operation runs an rpc's operation and returns the reply's body.
func (s *session) operation(ctx context.Context, op *elem) (string, error) {
	if op.Space == nsMonitoring && op.Local == "get-schema" {
		return s.getSchema(op)
	}
	if op.Space != nsBase {
		return "", protocolErr("operation-not-supported", "the operation %s (%s)", op.Local, op.Space)
	}
	switch op.Local {
	case "get-config":
		t, err := s.source(ctx, op, "source")
		if err != nil {
			return "", err
		}
		return s.data(t, op.child("filter"), false)
	case "get":
		var t *datastore.Tree
		var err error
		if s.env.State != nil {
			t, err = s.env.State(ctx)
		} else {
			t, err = s.env.Store.Running(ctx)
		}
		if err != nil {
			return "", err
		}
		return s.data(t, op.child("filter"), true)
	case "edit-config":
		return s.editConfig(ctx, op)
	case "copy-config":
		return s.copyConfig(ctx, op)
	case "delete-config":
		return "", protocolErr("operation-not-supported", "running and candidate can't be deleted; delete what is in them")
	case "lock", "unlock":
		ds, err := datastoreOf(op, "target")
		if err != nil {
			return "", err
		}
		if op.Local == "lock" {
			err = s.env.Store.Lock(ctx, s.owner, ds)
		} else {
			err = s.env.Store.Unlock(s.owner, ds)
		}
		if err != nil {
			var le *datastore.LockedError
			if errors.As(err, &le) || op.Local == "lock" {
				return "", protocolErr("lock-denied", "%s", err.Error())
			}
			return "", protocolErr("operation-failed", "%s", err.Error())
		}
		return ok, nil
	case "validate":
		return s.validate(ctx, op)
	case "commit":
		return s.commit(ctx, op)
	case "cancel-commit":
		if s.env.Pending == nil || !s.env.Pending(ctx) {
			return "", appErr("operation-failed", "", "no commit waits for confirmation")
		}
		if _, err := s.env.Rollback(ctx); err != nil {
			return "", err
		}
		return ok, nil
	case "discard-changes":
		if err := s.env.Store.Discard(s.owner); err != nil {
			return "", err
		}
		return ok, nil
	case "close-session":
		return ok, nil
	}
	return "", protocolErr("operation-not-supported", "the operation %s", op.Local)
}

// datastoreOf is the datastore named in op's element where (<target>
// <candidate/></target>).
func datastoreOf(op *elem, where string) (string, error) {
	w := op.child(where)
	if w == nil || len(w.Children) != 1 {
		return "", protocolErr("missing-element", "%s needs its %s", op.Local, where)
	}
	switch name := w.Children[0].Local; name {
	case "candidate", "running":
		return name, nil
	case "startup", "url":
		return "", protocolErr("operation-not-supported", "there is no %s configuration", name)
	default:
		return "", protocolErr("bad-element", "%s %s", where, name)
	}
}

func (s *session) source(ctx context.Context, op *elem, where string) (*datastore.Tree, error) {
	ds, err := datastoreOf(op, where)
	if err != nil {
		return nil, err
	}
	if ds == "candidate" {
		return s.env.Store.Candidate(ctx)
	}
	return s.env.Store.Running(ctx)
}

// data is a <data> reply with what the filter selects of t that the
// user may read; with monitoring, netconf-state's schema list too.
func (s *session) data(t *datastore.Tree, f *elem, monitoring bool) (string, error) {
	if f != nil {
		if ty, ok := f.attr("", "type"); ok && ty != "subtree" {
			return "", protocolErr("operation-not-supported", "filters of type %s", ty)
		}
		t = filter(t, f)
	}
	t = s.visible(t)
	var b strings.Builder
	b.WriteString("<data>")
	writeNode(&b, t.Root, true)
	if monitoring && f != nil {
		for _, c := range f.Children {
			if c.Space == nsMonitoring && c.Local == "netconf-state" {
				b.WriteString(schemaList())
			}
		}
	}
	b.WriteString("</data>")
	return b.String(), nil
}

// visible is t without what the user may not read: by the top-level
// lists and their entries, as the CLI's.
func (s *session) visible(t *datastore.Tree) *datastore.Tree {
	out := t.Clone()
	for name, es := range out.Root.Lists {
		kept := es[:0]
		for _, e := range es {
			if s.env.Access.CanRead(datastore.Path{{Name: name, Keys: e.Keys()}}) {
				kept = append(kept, e)
			}
		}
		if len(kept) == 0 {
			delete(out.Root.Lists, name)
		} else {
			out.Root.Lists[name] = kept
		}
	}
	for name := range out.Root.Containers {
		if !s.env.Access.CanRead(datastore.Path{{Name: name}}) {
			delete(out.Root.Containers, name)
		}
	}
	return out
}

func (s *session) canWrite(p datastore.Path) bool {
	return s.env.ReadOnly == "" && s.env.Access.CanWrite(p)
}

func (s *session) editConfig(ctx context.Context, op *elem) (string, error) {
	ds, err := datastoreOf(op, "target")
	if err != nil {
		return "", err
	}
	if ds != "candidate" {
		return "", protocolErr("operation-not-supported", "running is written by a commit of the candidate")
	}
	defOp := "merge"
	if d := op.child("default-operation"); d != nil {
		defOp = d.text()
		if defOp != "merge" && defOp != "replace" && defOp != "none" {
			return "", protocolErr("bad-element", "default-operation %q", defOp)
		}
	}
	if e := op.child("error-option"); e != nil && !slices.Contains([]string{"stop-on-error", "rollback-on-error"}, e.text()) {
		return "", protocolErr("operation-not-supported", "error-option %s: an edit is all or nothing", e.text())
	}
	cfg := op.child("config")
	if cfg == nil {
		return "", protocolErr("missing-element", "edit-config needs its config (url is not supported)")
	}
	if s.env.ReadOnly != "" {
		return "", &rpcError{Type: "application", Tag: "access-denied", Message: s.env.ReadOnly}
	}
	err = s.env.Store.Edit(ctx, s.owner, func(t *datastore.Tree) error {
		ed := &editor{t: t, canWrite: s.canWrite}
		if defOp != "replace" {
			return ed.apply(nil, t.Root.S, cfg.Children, defOp)
		}
		if !s.canWrite(nil) {
			return &rpcError{Type: "application", Tag: "access-denied", Message: "only a global admin replaces the whole configuration"}
		}
		old := t.Root.Clone(nil)
		_ = t.Delete(nil)
		if err := ed.apply(nil, t.Root.S, cfg.Children, "merge"); err != nil {
			return err
		}
		keepSecrets(old, t.Root)
		return nil
	})
	if err != nil {
		return "", err
	}
	return ok, nil
}

// copyConfig copies running, or an inline config, to the candidate.
func (s *session) copyConfig(ctx context.Context, op *elem) (string, error) {
	ds, err := datastoreOf(op, "target")
	if err != nil {
		return "", err
	}
	if ds != "candidate" {
		return "", protocolErr("operation-not-supported", "running is written by a commit of the candidate")
	}
	if !s.canWrite(nil) {
		return "", &rpcError{Type: "application", Tag: "access-denied", Message: "only a global admin replaces the whole configuration"}
	}
	src := op.child("source")
	if src == nil || len(src.Children) != 1 {
		return "", protocolErr("missing-element", "copy-config needs its source")
	}
	var from *datastore.Tree
	switch src.Children[0].Local {
	case "running":
		if from, err = s.env.Store.Running(ctx); err != nil {
			return "", err
		}
	case "candidate":
		return ok, nil
	case "config":
		from = datastore.New(s.env.Schema)
		ed := &editor{t: from, canWrite: func(datastore.Path) bool { return true }}
		if err := ed.apply(nil, from.Root.S, src.Children[0].Children, "merge"); err != nil {
			return "", err
		}
	default:
		return "", protocolErr("operation-not-supported", "source %s", src.Children[0].Local)
	}
	err = s.env.Store.Edit(ctx, s.owner, func(t *datastore.Tree) error {
		old := t.Root
		t.Root = from.Root.Clone(nil)
		keepSecrets(old, t.Root)
		return nil
	})
	if err != nil {
		return "", err
	}
	return ok, nil
}

func (s *session) validate(ctx context.Context, op *elem) (string, error) {
	src := op.child("source")
	if src == nil || len(src.Children) != 1 {
		return "", protocolErr("missing-element", "validate needs its source")
	}
	switch src.Children[0].Local {
	case "running":
		return ok, nil // what runs passed its commit
	case "candidate":
	case "config":
		t := datastore.New(s.env.Schema)
		ed := &editor{t: t, canWrite: func(datastore.Path) bool { return true }}
		if err := ed.apply(nil, t.Root.S, src.Children[0].Children, "merge"); err != nil {
			return "", err
		}
		if errs := t.Validate(); len(errs) > 0 {
			return "", appErr("invalid-value", "", "%s", joinErrors(errs))
		}
		return ok, nil
	default:
		return "", protocolErr("operation-not-supported", "source %s", src.Children[0].Local)
	}
	_, err := s.env.Store.Commit(ctx, datastore.CommitOptions{User: s.env.User, Owner: s.owner, Only: s.env.Only, Validate: true})
	if err != nil {
		var ve *datastore.ValidationError
		if errors.As(err, &ve) {
			return "", appErr("invalid-value", "", "%s", joinErrors(ve.Problems))
		}
		return "", err
	}
	return ok, nil
}

// commit commits the candidate, or confirms a confirmed commit: a plain
// commit while one waits, with nothing new in the candidate (RFC 6241
// section 8.4).
func (s *session) commit(ctx context.Context, op *elem) (string, error) {
	if s.env.ReadOnly != "" {
		return "", &rpcError{Type: "application", Tag: "access-denied", Message: s.env.ReadOnly}
	}
	if op.child("persist") != nil || op.child("persist-id") != nil {
		return "", protocolErr("operation-not-supported", "persist: a confirmed commit belongs to its session")
	}
	confirmed := op.child("confirmed") != nil
	changed, err := s.env.Store.Changed(ctx)
	if err != nil {
		return "", err
	}
	if !confirmed && !changed && s.env.Pending != nil && s.env.Pending(ctx) {
		if _, err := s.env.Confirm(ctx); err != nil {
			return "", err
		}
		return ok, nil
	}
	o := datastore.CommitOptions{User: s.env.User, Owner: s.owner, Only: s.env.Only}
	if confirmed {
		secs := defaultConfirm
		if t := op.child("confirm-timeout"); t != nil {
			n, err := strconv.Atoi(t.text())
			if err != nil || n < 1 {
				return "", protocolErr("invalid-value", "confirm-timeout %q", t.text())
			}
			secs = n
		}
		o.Confirm = &secs
	} else {
		none := 0
		o.Confirm = &none
	}
	if _, err := s.env.Store.Commit(ctx, o); err != nil {
		var ve *datastore.ValidationError
		if errors.As(err, &ve) {
			return "", appErr("invalid-value", "", "%s", joinErrors(ve.Problems))
		}
		return "", err
	}
	return ok, nil
}

// getSchema answers get-schema (RFC 6022) with a module's or submodule's
// YANG text.
func (s *session) getSchema(op *elem) (string, error) {
	id := op.child("identifier")
	if id == nil {
		return "", protocolErr("missing-element", "get-schema needs its identifier")
	}
	if f := op.child("format"); f != nil && !strings.HasSuffix(f.text(), "yang") {
		return "", appErr("invalid-value", "", "format %s: only yang", f.text())
	}
	data, err := fs.ReadFile(yang.Files, id.text()+".yang")
	if err != nil {
		return "", appErr("invalid-value", "", "no schema %q", id.text())
	}
	return `<data xmlns="` + nsMonitoring + `">` + escape(string(data)) + "</data>", nil
}

// schemaList is netconf-state's schemas (RFC 6022), for get.
func schemaList() string {
	names, _ := fs.Glob(yang.Files, "*.yang")
	root := schema.MustLoad()
	var b strings.Builder
	b.WriteString(`<netconf-state xmlns="` + nsMonitoring + `"><schemas>`)
	for _, n := range names {
		id := strings.TrimSuffix(n, ".yang")
		ns := schema.Namespace
		if id == "portitor-extensions" {
			ns = "urn:portitor:extensions"
		}
		fmt.Fprintf(&b, "<schema><identifier>%s</identifier><version>%s</version><format>yang</format><namespace>%s</namespace><location>NETCONF</location></schema>",
			id, root.Revision, ns)
	}
	b.WriteString("</schemas></netconf-state>")
	return b.String()
}
