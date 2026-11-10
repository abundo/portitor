// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package cli is Portitor's command line, after SR Linux's: the
// configuration's YANG tree (internal/schema) is the command tree, edited
// in a shared candidate (internal/datastore) and committed. Every command,
// help text and completion comes from the schema, so a feature in the YANG
// modules is in the CLI without code here.
//
//	enter candidate
//	instance host interface wan0 mtu 1500
//	instance host interface lan0 {
//	    addresses [ 192.168.1.1/24 ]
//	}
//	diff
//	commit confirmed 120
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/schema"
)

// Access is what a user may see and change, by path.
type Access interface {
	// CanRead reports whether the subtree at p may be shown.
	CanRead(p datastore.Path) bool
	// CanWrite reports whether the subtree at p may be changed.
	CanWrite(p datastore.Path) bool
}

// Env is what a session works with.
type Env struct {
	Store  *datastore.Store
	Schema *schema.Node
	User   string
	Host   string // for the prompt
	Access Access
	// ReadOnly, when set, says why the candidate can't be entered (a
	// viewer, an HA secondary's copy).
	ReadOnly string
	// Only are the virtual firewalls the user's commits deploy (nil: all).
	Only map[string]bool
	// Confirm and Rollback finish a commit that waits for confirmation.
	Confirm  func(ctx context.Context) (string, error)
	Rollback func(ctx context.Context) (string, error)
	// Pending reports whether a commit waits for confirmation.
	Pending func(ctx context.Context) bool
	// State is the running configuration with the state (config false)
	// of the firewalls filled in; nil: no state.
	State func(ctx context.Context) (*datastore.Tree, error)
	// API answers an API request as the user, for show api.
	API func(ctx context.Context, method, path string, body []byte) (int, []byte)
	// Action runs the action named on the entry at p as the user, with
	// its input (datastore.ReadValues of the action's Input), and answers
	// its output and a change's warnings. candidate is a view's datastore
	// (an operation and a change act on the candidate). The CLI's tools
	// and NETCONF's <action> run actions with it.
	Action  func(ctx context.Context, p datastore.Path, name string, input *datastore.Node, candidate bool) (output *datastore.Node, warnings []string, err error)
	Version string
}

// Session is one user's CLI: their mode and place in the tree.
type Session struct {
	id        string // for the datastore's locks
	env       *Env
	out       io.Writer
	candidate bool
	cwd       datastore.Path
	prev      datastore.Path
	blocks    []datastore.Path // contexts of the { } blocks open, for pasted text
	done      bool
}

// NewSession starts a session in running mode at the root.
func NewSession(env *Env, out io.Writer) *Session {
	return &Session{id: NewSessionID("cli"), env: env, out: out}
}

var sessions atomic.Int64

// NewSessionID names a session for the locks: cli-1, netconf-2, ...
func NewSessionID(kind string) string {
	return fmt.Sprintf("%s-%d", kind, sessions.Add(1))
}

// Close ends the session, releasing its locks.
func (s *Session) Close() { s.env.Store.Release(s.id) }

// Done reports whether the user logged out.
func (s *Session) Done() bool { return s.done }

// Prompt is the line above the input: the mode and the context.
func (s *Session) Prompt() string {
	mode := "running"
	if s.candidate {
		mode = "candidate shared default"
	}
	return fmt.Sprintf("--{ %s }--[ %s ]--", mode, s.cwd.CLI())
}

// PromptLine is the input's prompt.
func (s *Session) PromptLine() string {
	host := s.env.Host
	if host == "" {
		host = "portitor"
	}
	return fmt.Sprintf("%s@%s# ", s.env.User, host)
}

func (s *Session) printf(format string, args ...any) {
	fmt.Fprintf(s.out, format, args...)
}

var commands = []struct{ name, help string }{
	{"enter", "enter candidate (edit) or running (read) mode"},
	{"show", "show the configuration here or at a path: [from running|candidate|state] [flat|json|detail] [path]; also deployments, api <path>"},
	{"diff", "show the candidate's changes against running: [flat] [path]"},
	{"commit", "commit the candidate: now (and leave candidate mode), stay, validate, confirmed [seconds]"},
	{"discard", "drop the candidate's changes: now (and leave candidate mode) or stay"},
	{"confirm", "confirm a commit that waits for it"},
	{"rollback", "roll back a commit that waits for confirmation"},
	{"set", "set a leaf, or make an entry: set <path> [value]"},
	{"delete", "delete a leaf, leaf-list value, container or entry: delete <path> [value]"},
	{"rename", "give an entry new keys, rewriting what refers to it: rename <path> to <keys>"},
	{"move", "move an entry of an ordered list: move <path> first|last|before <keys>|after <keys>"},
	{"tools", "run an action of an entry: tools <path> <action> [<input> <value>]..."},
	{"tree", "show the schema below here or a path"},
	{"pwc", "show the present working context"},
	{"back", "go back to the previous context"},
	{"exit", "go up one level; exit all: to the root; at the root, log out"},
	{"quit", "log out"},
	{"help", "this list"},
}

// Exec runs one line.
func (s *Session) Exec(ctx context.Context, line string) error {
	toks, _, err := lex(line)
	if err != nil {
		return err
	}
	if len(toks) == 0 {
		return nil
	}
	if toks[0].is("}") {
		if len(s.blocks) == 0 {
			return errors.New("no block is open")
		}
		s.cwd = s.blocks[len(s.blocks)-1]
		s.blocks = s.blocks[:len(s.blocks)-1]
		return s.Exec(ctx, rest(line, 1))
	}
	if cmd := s.commandOf(toks[0]); cmd != "" {
		return s.command(ctx, cmd, toks[1:])
	}
	return s.statement(ctx, toks, false)
}

// rest is line without its first n words.
func rest(line string, n int) string {
	toks, _, _ := lex(line)
	if len(toks) <= n {
		return ""
	}
	var parts []string
	for _, t := range toks[n:] {
		if t.quoted {
			parts = append(parts, datastore.Quote(t.text))
		} else {
			parts = append(parts, t.text)
		}
	}
	return strings.Join(parts, " ")
}

// commandOf is the command a first word names, or "" for a path: a
// command's name, a child's name or prefix, or a command's prefix, in
// that order.
func (s *Session) commandOf(t token) string {
	if t.quoted || t.text == "/" {
		return ""
	}
	for _, c := range commands {
		if c.name == t.text {
			return c.name
		}
	}
	if t.text == "logout" {
		return "quit"
	}
	if _, err := childOf(s.schemaHere(), t); err == nil {
		return ""
	}
	return matchCommand(t.text)
}

func matchCommand(w string) string {
	var found []string
	for _, c := range commands {
		if c.name == w {
			return w
		}
		if strings.HasPrefix(c.name, w) {
			found = append(found, c.name)
		}
	}
	if len(found) == 1 {
		return found[0]
	}
	return ""
}

func (s *Session) schemaHere() *schema.Node {
	ss, err := datastore.Resolve(s.env.Schema, s.cwd)
	if err != nil || len(ss) == 0 {
		return s.env.Schema
	}
	return ss[len(ss)-1]
}

// parsed is a path statement.
type parsed struct {
	path    datastore.Path // absolute, to the node or leaf
	node    *schema.Node   // what it ends at
	values  []string
	bracket bool // values in [ ]
	open    bool // ends with {
	valued  bool // values given
	list    bool // ends at a list's name, without its keys (path ends before it)
}

// parsePath reads a path (absolute after "/", else from the context) and
// what follows it: a leaf's value, a leaf-list's values, or {.
func (s *Session) parsePath(toks []token) (parsed, error) {
	var p parsed
	at := s.env.Schema
	path := datastore.Path{}
	if len(toks) > 0 && toks[0].is("/") {
		toks = toks[1:]
	} else {
		path = slices.Clone(s.cwd)
		at = s.schemaHere()
	}
	p.node = at
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		if t.is("{") {
			if i != len(toks)-1 {
				return p, errors.New("{ ends the line")
			}
			p.open = true
			break
		}
		if at.Kind == schema.Leaf || at.Kind == schema.LeafList {
			return p, fmt.Errorf("%s takes no more than its value", at.Name)
		}
		c, err := childOf(at, t)
		if err != nil {
			return p, err
		}
		e := datastore.Elem{Name: c.Name}
		switch c.Kind {
		case schema.List:
			if i == len(toks)-1 {
				// The list as a whole, for info, diff and tree.
				p.path, p.node, p.list = path, c, true
				return p, nil
			}
			if i+len(c.Keys) >= len(toks) {
				return p, fmt.Errorf("%s needs its key: %s", c.Name, strings.Join(c.Keys, " "))
			}
			for _, k := range toks[i+1 : i+1+len(c.Keys)] {
				if !k.quoted && (k.text == "{" || k.text == "[" || k.text == "]" || k.text == "}") {
					return p, fmt.Errorf("%s needs its key: %s", c.Name, strings.Join(c.Keys, " "))
				}
				e.Keys = append(e.Keys, k.text)
			}
			i += len(c.Keys)
		case schema.Leaf:
			vals := toks[i+1:]
			if len(vals) > 1 {
				return p, fmt.Errorf("%s takes one value (quote one with spaces)", c.Name)
			}
			if len(vals) == 1 {
				p.values, p.valued = []string{vals[0].text}, true
			}
			i = len(toks)
		case schema.LeafList:
			vals := toks[i+1:]
			if len(vals) > 0 && vals[0].is("[") {
				if !vals[len(vals)-1].is("]") {
					return p, errors.New("[ without ]")
				}
				p.bracket = true
				vals = vals[1 : len(vals)-1]
			}
			for _, v := range vals {
				p.values = append(p.values, v.text)
			}
			p.valued = p.bracket || len(p.values) > 0
			i = len(toks)
		}
		path = append(path, e)
		at = c
		p.node = c
	}
	p.path = path
	return p, nil
}

// schemaPath walks names alone (no keys) from the context, or the root
// after "/": tree's path.
func (s *Session) schemaPath(toks []token) (*schema.Node, error) {
	at := s.schemaHere()
	if len(toks) > 0 && toks[0].is("/") {
		at, toks = s.env.Schema, toks[1:]
	}
	for _, t := range toks {
		c, err := childOf(at, t)
		if err != nil {
			return nil, err
		}
		at = c
	}
	return at, nil
}

// childOf is the child of at a word names: its name, or a prefix of one
// name alone.
func childOf(at *schema.Node, t token) (*schema.Node, error) {
	if c := at.Child(t.text); c != nil {
		return c, nil
	}
	var found []*schema.Node
	for _, c := range at.Children {
		if strings.HasPrefix(c.Name, t.text) && !c.IsKey() {
			found = append(found, c)
		}
	}
	switch len(found) {
	case 1:
		return found[0], nil
	case 0:
		return nil, fmt.Errorf("%s has no %q", describe(at), t.text)
	}
	names := make([]string, len(found))
	for i, c := range found {
		names[i] = c.Name
	}
	return nil, fmt.Errorf("%q is ambiguous: %s", t.text, strings.Join(names, ", "))
}

func describe(n *schema.Node) string {
	if n.Parent == nil {
		return "the root"
	}
	return n.Name
}

// statement runs a path statement: navigate to a container or entry (made
// in candidate mode), or set a leaf. With set, it never navigates.
func (s *Session) statement(ctx context.Context, toks []token, set bool) error {
	p, err := s.parsePath(toks)
	if err != nil {
		return err
	}
	if p.list {
		return fmt.Errorf("%s needs its key: %s", p.node.Name, strings.Join(p.node.Keys, " "))
	}
	switch p.node.Kind {
	case schema.Leaf, schema.LeafList:
		if !p.valued {
			if set {
				return fmt.Errorf("%s needs a value", p.node.Name)
			}
			return s.info(ctx, p.path, "", s.candidate)
		}
		return s.edit(ctx, p.path, func(t *datastore.Tree) error {
			switch {
			case p.node.Kind == schema.Leaf:
				return t.Set(p.path, p.values[0])
			case p.bracket:
				return t.SetList(p.path, p.values)
			}
			for _, v := range p.values {
				if err := t.Add(p.path, v); err != nil {
					return err
				}
			}
			return nil
		})
	}
	if len(p.path) == 0 && !p.open {
		s.prev, s.cwd = s.cwd, nil
		return nil
	}
	if s.candidate && !s.hasState(p.path) {
		if err := s.edit(ctx, p.path, func(t *datastore.Tree) error {
			_, err := t.Ensure(p.path)
			return err
		}); err != nil {
			return err
		}
	} else {
		t, err := s.treeAt(ctx, false, p.path)
		if err != nil {
			return err
		}
		if n, _, err := t.Find(p.path); err != nil || n == nil {
			return fmt.Errorf("%s is not in the running configuration", p.path.CLI())
		}
	}
	if set {
		return nil
	}
	if p.open {
		s.blocks = append(s.blocks, s.cwd)
	} else {
		s.prev = s.cwd
	}
	s.cwd = p.path
	return nil
}

func (s *Session) edit(ctx context.Context, p datastore.Path, fn func(*datastore.Tree) error) error {
	if !s.candidate {
		return errors.New("this is running mode: enter candidate to change the configuration")
	}
	if !s.env.Access.CanWrite(p) {
		return fmt.Errorf("you may not change %s", p.CLI())
	}
	return s.env.Store.Edit(ctx, s.id, fn)
}

// tree is the configuration a command shows: the candidate in candidate
// mode, else running.
func (s *Session) tree(ctx context.Context, candidate bool) (*datastore.Tree, error) {
	if candidate {
		return s.env.Store.Candidate(ctx)
	}
	return s.env.Store.Running(ctx)
}

// treeAt is the tree to read at p: the state when p is in it.
func (s *Session) treeAt(ctx context.Context, candidate bool, p datastore.Path) (*datastore.Tree, error) {
	if s.hasState(p) {
		return s.stateTree(ctx)
	}
	return s.tree(ctx, candidate)
}

func (s *Session) stateTree(ctx context.Context) (*datastore.Tree, error) {
	if s.env.State == nil {
		return nil, errors.New("there is no state here")
	}
	return s.env.State(ctx)
}

// hasState reports whether p goes into the state (config false).
func (s *Session) hasState(p datastore.Path) bool {
	ss, _ := datastore.Resolve(s.env.Schema, p)
	return slices.ContainsFunc(ss, func(n *schema.Node) bool { return n.State })
}

func (s *Session) command(ctx context.Context, cmd string, args []token) error {
	words := make([]string, len(args))
	for i, a := range args {
		words[i] = a.text
	}
	arg := func(i int) string {
		if i < len(words) {
			return words[i]
		}
		return ""
	}
	switch cmd {
	case "help":
		for _, c := range commands {
			s.printf("  %-10s %s\n", c.name, c.help)
		}
		s.printf("  A path of the tree goes there (an entry is made in candidate mode); a path to a leaf\n  and a value sets it. ? lists what may follow, Tab completes.\n")
	case "enter":
		switch {
		case strings.HasPrefix("candidate", arg(0)) && arg(0) != "":
			if s.env.ReadOnly != "" {
				return errors.New(s.env.ReadOnly)
			}
			s.candidate = true
		case strings.HasPrefix("running", arg(0)) && arg(0) != "":
			s.candidate = false
		default:
			return errors.New("enter candidate or enter running")
		}
	case "pwc":
		s.printf("%s\n", s.Prompt())
	case "back":
		s.cwd, s.prev = s.prev, s.cwd
	case "exit":
		switch {
		case arg(0) == "all":
			s.prev, s.cwd = s.cwd, nil
		case len(s.cwd) == 0:
			s.done = true
		default:
			s.prev, s.cwd = s.cwd, s.cwd[:len(s.cwd)-1]
		}
	case "quit":
		s.done = true
	case "set":
		if len(args) == 0 {
			return errors.New("set what?")
		}
		return s.statement(ctx, args, true)
	case "delete":
		return s.delete(ctx, args)
	case "rename":
		return s.rename(ctx, args)
	case "move":
		return s.move(ctx, args)
	case "diff":
		return s.diff(ctx, args)
	case "tools":
		return s.tools(ctx, args)
	case "tree":
		n, err := s.schemaPath(args)
		if err != nil {
			return err
		}
		writeTree(s.out, n, "", 0)
	case "commit":
		return s.commit(ctx, words)
	case "discard":
		if !s.candidate {
			return errors.New("this is running mode")
		}
		if err := s.env.Store.Discard(ctx, s.id); err != nil {
			return err
		}
		s.printf("The candidate's changes are discarded.\n")
		if arg(0) != "stay" {
			s.candidate = false
		}
	case "confirm":
		msg, err := s.env.Confirm(ctx)
		if err != nil {
			return err
		}
		s.printf("%s\n", msg)
	case "rollback":
		msg, err := s.env.Rollback(ctx)
		if err != nil {
			return err
		}
		s.printf("%s\n", msg)
	case "show":
		if s.showSystem(args) {
			return s.show(ctx, words)
		}
		return s.infoCommand(ctx, args)
	}
	return nil
}

func (s *Session) delete(ctx context.Context, args []token) error {
	p, err := s.parsePath(args)
	if err != nil {
		return err
	}
	if len(p.path) == 0 || p.list {
		return errors.New("delete what? Name an entry (a list's keys), a leaf or a container")
	}
	return s.edit(ctx, p.path, func(t *datastore.Tree) error {
		if p.node.Kind == schema.LeafList && p.valued {
			return t.Delete(p.path, p.values...)
		}
		if p.node.Kind == schema.Leaf && p.valued {
			if n, _, _ := t.Find(p.path); n == nil || n.Leaves[p.node.Name] != p.values[0] {
				return fmt.Errorf("%s is not %s", p.path.CLI(), p.values[0])
			}
		}
		if p.node.Kind == schema.List {
			if n, _, _ := t.Find(p.path); n != nil {
				if using := t.Using(n); len(using) > 0 {
					s.printf("Warning: still named by\n  %s\nCommit fails until those change too.\n", strings.Join(using, "\n  "))
				}
			}
		}
		return t.Delete(p.path)
	})
}

// splitAt cuts args at the word w.
func splitAt(args []token, w string) ([]token, []token, bool) {
	for i, a := range args {
		if a.is(w) {
			return args[:i], args[i+1:], true
		}
	}
	return args, nil, false
}

func (s *Session) rename(ctx context.Context, args []token) error {
	from, to, ok := splitAt(args, "to")
	if !ok || len(to) == 0 {
		return errors.New("rename <path> to <new keys>")
	}
	p, err := s.parsePath(from)
	if err != nil {
		return err
	}
	if p.node.Kind != schema.List {
		return errors.New("rename takes a list entry")
	}
	keys := make([]string, len(to))
	for i, t := range to {
		keys[i] = t.text
	}
	err = s.edit(ctx, p.path, func(t *datastore.Tree) error { return t.Rename(p.path, keys) })
	if err == nil && slices.EqualFunc(s.cwd, p.path, elemEqual) {
		s.cwd[len(s.cwd)-1].Keys = keys
	}
	return err
}

func elemEqual(a, b datastore.Elem) bool { return a.Name == b.Name && slices.Equal(a.Keys, b.Keys) }

func (s *Session) move(ctx context.Context, args []token) error {
	for _, where := range []string{"first", "last", "before", "after"} {
		path, ref, ok := splitAt(args, where)
		if !ok {
			continue
		}
		p, err := s.parsePath(path)
		if err != nil {
			return err
		}
		if p.node.Kind != schema.List {
			return errors.New("move takes a list entry")
		}
		keys := make([]string, len(ref))
		for i, t := range ref {
			keys[i] = t.text
		}
		return s.edit(ctx, p.path, func(t *datastore.Tree) error { return t.Move(p.path, where, keys) })
	}
	return errors.New("move <path> first|last|before <keys>|after <keys>")
}

func (s *Session) infoCommand(ctx context.Context, args []token) error {
	candidate := s.candidate
	fromState := false
	format := ""
	for len(args) > 0 && !args[0].quoted {
		switch args[0].text {
		case "from":
			if len(args) < 2 {
				return errors.New("show from running|candidate|state")
			}
			switch {
			case strings.HasPrefix("running", args[1].text):
				candidate = false
			case strings.HasPrefix("candidate", args[1].text):
				candidate = true
			case strings.HasPrefix("state", args[1].text):
				fromState = true
			default:
				return errors.New("show from running|candidate|state")
			}
			args = args[2:]
			continue
		case "flat", "json", "detail":
			format = args[0].text
			args = args[1:]
			continue
		}
		break
	}
	p, err := s.parsePath(args)
	if err != nil {
		return err
	}
	if p.list {
		return s.infoList(ctx, p, format, candidate, fromState)
	}
	return s.infoFrom(ctx, p.path, format, candidate, fromState)
}

// infoList shows the entries of a list.
func (s *Session) infoList(ctx context.Context, p parsed, format string, candidate, fromState bool) error {
	t, err := s.treeAt(ctx, candidate, append(slices.Clone(p.path), datastore.Elem{Name: p.node.Name}))
	if fromState {
		t, err = s.stateTree(ctx)
	}
	if err != nil {
		return err
	}
	t = s.visible(t)
	n, _, err := t.Find(p.path)
	if err != nil || n == nil {
		return err
	}
	for _, e := range n.Lists[p.node.Name] {
		switch format {
		case "flat":
			datastore.Flat(s.out, e)
		case "json":
			data, err := datastore.NodeJSON(e, datastore.JSONOptions{Indent: true})
			if err != nil {
				return err
			}
			s.out.Write(append(data, '\n'))
		default:
			head := e.S.Name
			for _, k := range e.Keys() {
				head += " " + datastore.Quote(k)
			}
			s.printf("%s {\n", head)
			var b bytes.Buffer
			datastore.Text(&b, e, datastore.TextOptions{Defaults: format == "detail"})
			for _, l := range strings.SplitAfter(b.String(), "\n") {
				if l != "" {
					s.printf("    %s", l)
				}
			}
			s.printf("}\n")
		}
	}
	return nil
}

// info shows the configuration at p.
func (s *Session) info(ctx context.Context, p datastore.Path, format string, candidate bool) error {
	return s.infoFrom(ctx, p, format, candidate, false)
}

// infoFrom shows the configuration at p, or with fromState the running
// configuration and the state.
func (s *Session) infoFrom(ctx context.Context, p datastore.Path, format string, candidate, fromState bool) error {
	t, err := s.treeAt(ctx, candidate, p)
	if fromState {
		t, err = s.stateTree(ctx)
	}
	if err != nil {
		return err
	}
	t = s.visible(t)
	n, leaf, err := t.Find(p)
	if err != nil {
		return err
	}
	if n == nil {
		return nil // nothing there
	}
	if leaf != nil {
		switch {
		case leaf.Secret():
			if _, ok := n.Leaves[leaf.Name]; ok {
				s.printf("# %s is set (secret)\n", leaf.Name)
			}
		case leaf.Kind == schema.Leaf:
			if v, ok := n.Leaves[leaf.Name]; ok {
				s.printf("%s %s\n", leaf.Name, datastore.Quote(v))
			} else if leaf.HasDefault {
				s.printf("# %s %s (default)\n", leaf.Name, datastore.Quote(leaf.Default))
			}
		default:
			if vs, ok := n.LeafLists[leaf.Name]; ok {
				q := make([]string, len(vs))
				for i, v := range vs {
					q[i] = datastore.Quote(v)
				}
				s.printf("%s [ %s ]\n", leaf.Name, strings.Join(q, " "))
			}
		}
		return nil
	}
	switch format {
	case "flat":
		datastore.Flat(s.out, n)
	case "json":
		data, err := datastore.NodeJSON(n, datastore.JSONOptions{Indent: true})
		if err != nil {
			return err
		}
		s.out.Write(append(data, '\n'))
	default:
		datastore.Text(s.out, n, datastore.TextOptions{Defaults: format == "detail"})
	}
	return nil
}

// visible is t without what the user may not read.
func (s *Session) visible(t *datastore.Tree) *datastore.Tree {
	out := t.Clone()
	// Access is by the top-level lists and their entries (virtual
	// firewalls, shared objects).
	prune := func(n *datastore.Node, p datastore.Path) {
		for name, es := range n.Lists {
			kept := es[:0]
			for _, e := range es {
				ep := append(slices.Clone(p), datastore.Elem{Name: name, Keys: e.Keys()})
				if s.env.Access.CanRead(ep) {
					kept = append(kept, e)
				}
			}
			if len(kept) == 0 {
				delete(n.Lists, name)
			} else {
				n.Lists[name] = kept
			}
		}
		for name := range n.Containers {
			if !s.env.Access.CanRead(append(slices.Clone(p), datastore.Elem{Name: name})) {
				delete(n.Containers, name)
			}
		}
	}
	prune(out.Root, nil)
	return out
}

func (s *Session) diff(ctx context.Context, args []token) error {
	flat := false
	if len(args) > 0 && args[0].is("flat") {
		flat, args = true, args[1:]
	}
	p, err := s.parsePath(args)
	if err != nil {
		return err
	}
	run, err := s.env.Store.Running(ctx)
	if err != nil {
		return err
	}
	cand, err := s.env.Store.Candidate(ctx)
	if err != nil {
		return err
	}
	run, cand = s.visible(run), s.visible(cand)
	if !flat {
		datastore.DiffText(s.out, run, cand, p.path)
		return nil
	}
	for _, c := range datastore.Diff(run, cand) {
		if !hasPrefix(c.Path, p.path) {
			continue
		}
		s.printf("%s\n", flatChange(c, s.env.Schema))
	}
	return nil
}

func hasPrefix(p, prefix datastore.Path) bool {
	return len(p) >= len(prefix) && slices.EqualFunc(p[:len(prefix)], prefix, elemEqual)
}

// flatChange writes a change as the command that makes it.
func flatChange(c datastore.Change, root *schema.Node) string {
	ss, _ := datastore.Resolve(root, c.Path)
	secret := len(ss) > 0 && ss[len(ss)-1].Secret()
	switch c.Op {
	case datastore.OpSet:
		if secret {
			return "# set / " + c.Path.CLI() + " (secret)"
		}
		return "set / " + c.Path.CLI() + " " + datastore.Quote(c.New)
	case datastore.OpList:
		q := make([]string, len(c.Values))
		for i, v := range c.Values {
			q[i] = datastore.Quote(v)
		}
		return "set / " + c.Path.CLI() + " [ " + strings.Join(q, " ") + " ]"
	case datastore.OpCreate:
		return "set / " + c.Path.CLI()
	case datastore.OpDelete:
		return "delete / " + c.Path.CLI()
	case datastore.OpOrder:
		var keys []string
		for _, k := range c.Order {
			keys = append(keys, strings.Join(k, " "))
		}
		return "# order of / " + c.Path.CLI() + ": " + strings.Join(keys, ", ")
	}
	return ""
}

func (s *Session) commit(ctx context.Context, words []string) error {
	if !s.candidate {
		return errors.New("this is running mode: enter candidate first")
	}
	o := datastore.CommitOptions{User: s.env.User, Owner: s.id, Only: s.env.Only}
	how := "stay"
	if len(words) > 0 {
		how = words[0]
	}
	switch {
	case how == "now" || how == "stay":
	case how == "validate":
		o.Validate = true
	case how == "confirmed":
		secs := 0
		if len(words) > 1 {
			n, err := strconv.Atoi(words[1])
			if err != nil || n < 1 {
				return errors.New("commit confirmed [seconds]")
			}
			secs = n
		}
		if secs > 0 {
			o.Confirm = &secs
		}
	default:
		return errors.New("commit now|stay|validate|confirmed [seconds]")
	}
	changed, err := s.env.Store.Changed(ctx)
	if err != nil {
		return err
	}
	if !changed && !o.Validate {
		s.printf("The candidate has no changes of its own; committing what the configuration holds.\n")
	}
	msg, err := s.env.Store.Commit(ctx, o)
	if msg != "" {
		s.printf("%s\n", msg)
	}
	if err != nil {
		return err
	}
	if how == "now" {
		s.candidate = false
	}
	return nil
}

// showSystem tells whether show's first word is one of its own (deployments,
// api) rather than the start of a path: a node here of that name wins.
func (s *Session) showSystem(args []token) bool {
	if len(args) == 0 || args[0].quoted || !slices.Contains([]string{"deployments", "api"}, args[0].text) {
		return false
	}
	_, err := childOf(s.schemaHere(), args[0])
	return err != nil
}

func (s *Session) show(ctx context.Context, words []string) error {
	if len(words) == 0 {
		return errors.New("show deployments|api <path>")
	}
	switch {
	case strings.HasPrefix("deployments", words[0]):
		code, body := s.env.API(ctx, "GET", "/api/deployments", nil)
		if code/100 != 2 {
			return fmt.Errorf("%d: %s", code, body)
		}
		var deps []struct {
			CommitID   int64  `json:"commit_id"`
			FirewallID uint   `json:"firewall_id"`
			Username   string `json:"username"`
			Status     string `json:"status"`
			Message    string `json:"message"`
			CreatedAt  string `json:"created_at"`
		}
		if err := json.Unmarshal(body, &deps); err != nil {
			return err
		}
		s.printf("%-7s %-9s %-12s %-12s %-25s %s\n", "commit", "firewall", "user", "status", "time", "message")
		for _, d := range deps {
			s.printf("%-7d %-9d %-12s %-12s %-25s %s\n", d.CommitID, d.FirewallID, d.Username, d.Status, d.CreatedAt, d.Message)
		}
	case strings.HasPrefix("api", words[0]):
		if len(words) < 2 || !strings.HasPrefix(words[1], "/api/") {
			return errors.New("show api /api/<path>: the answer of a GET of the API")
		}
		code, body := s.env.API(ctx, "GET", words[1], nil)
		var pretty bytes.Buffer
		if json.Indent(&pretty, body, "", "  ") == nil {
			body = pretty.Bytes()
		}
		if code/100 != 2 {
			return fmt.Errorf("%d: %s", code, body)
		}
		s.out.Write(append(body, '\n'))
	default:
		return errors.New("show deployments|api <path>")
	}
	return nil
}

// writeTree writes the schema below n, to depth levels (0: all).
func writeTree(w io.Writer, n *schema.Node, ind string, depth int) {
	for _, c := range n.Children {
		switch c.Kind {
		case schema.List:
			keys := make([]string, len(c.Keys))
			for i, k := range c.Keys {
				keys[i] = "<" + k + ">"
			}
			fmt.Fprintf(w, "%s+-- %s %s\n", ind, c.Name, strings.Join(keys, " "))
			writeTree(w, c, ind+"|   ", depth)
		case schema.Container:
			fmt.Fprintf(w, "%s+-- %s\n", ind, c.Name)
			writeTree(w, c, ind+"|   ", depth)
		case schema.Leaf:
			if c.IsKey() {
				continue
			}
			fmt.Fprintf(w, "%s+-- %s: %s\n", ind, c.Name, c.Type)
		case schema.LeafList:
			fmt.Fprintf(w, "%s+-- %s*: %s\n", ind, c.Name, c.Type)
		}
	}
}
