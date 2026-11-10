// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package schema compiles Portitor's YANG modules (package yang) into the
// tree every frontend walks: the CLI's commands, help and completion, the
// datastore's checks, NETCONF and the API. A node knows its kind, keys,
// type, default, description and Portitor's extensions (px:secret, and the
// table mapping of dev/design-model-driven.md).
package schema

import (
	"fmt"
	"io/fs"
	"math"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"

	goyang "github.com/openconfig/goyang/pkg/yang"

	"github.com/abundo/portitor/yang"
)

// Module is the module the configuration is in; its JSON names are
// qualified with it (RFC 7951).
const Module = "portitor"

// Namespace is the module's XML namespace (NETCONF).
const Namespace = "urn:portitor:config"

// Kind is a node's kind.
type Kind uint8

const (
	Container Kind = iota
	List
	Leaf
	LeafList
)

func (k Kind) String() string {
	return [...]string{"container", "list", "leaf", "leaf-list"}[k]
}

// Node is a schema node. The root is a container named after the module.
type Node struct {
	Name     string
	Kind     Kind
	Parent   *Node
	Children []*Node // keys first, then in the modules' order
	byName   map[string]*Node

	Keys          []string // a list's key leaves
	OrderedByUser bool     // a list or leaf-list

	Type       *Type // a leaf's or leaf-list's
	Default    string
	HasDefault bool
	Mandatory  bool

	Description string
	// State is a config false node, or one below it: read-only, filled
	// from the firewalls.
	State bool
	// Revision is the module's newest revision, on the root.
	Revision string
	// Ext holds Portitor's extensions by name without the prefix
	// ("secret": "", "table": "rules").
	Ext map[string]string
	// Actions are a list's actions (YANG 1.1), by name.
	Actions []*Action
}

// Action is an action of a list's entries: what is done or generated
// rather than set (new keys, a certificate made, a download started),
// which every frontend runs: the API's ?action=, the CLI's tools and
// NETCONF's <action>.
type Action struct {
	Name        string
	Description string
	// Kind is its px:action: ActionView, ActionOperation, ActionChange or
	// ActionCreate.
	Kind string
	// Input and Output are containers of the action's leaves (and lists),
	// never nil; their Parent is nil.
	Input, Output *Node
}

// The kinds of actions (px:action).
const (
	// ActionView answers from the configuration (the datastore asked),
	// changing nothing.
	ActionView = "view"
	// ActionOperation has the firewalls do something with the entry
	// (renew a certificate, download a list); it changes no
	// configuration.
	ActionOperation = "operation"
	// ActionChange changes the candidate, as an edit.
	ActionChange = "change"
	// ActionCreate is a change that makes the entry when it isn't there.
	ActionCreate = "create"
)

// Writes reports whether running the action takes the right to change
// the entry; a view takes the right to read it.
func (a *Action) Writes() bool { return a.Kind != ActionView }

// Action is the action of n named name, or nil.
func (n *Node) Action(name string) *Action {
	for _, a := range n.Actions {
		if a.Name == name {
			return a
		}
	}
	return nil
}

// Child is the child named name, or nil.
func (n *Node) Child(name string) *Node { return n.byName[name] }

// Secret reports whether the leaf is a secret: written, never read back.
func (n *Node) Secret() bool {
	_, ok := n.Ext["secret"]
	return ok
}

// IsKey reports whether n is a key leaf of its list.
func (n *Node) IsKey() bool {
	return n.Parent != nil && n.Parent.Kind == List && slices.Contains(n.Parent.Keys, n.Name)
}

// IsDir reports whether n holds other nodes (a container or list).
func (n *Node) IsDir() bool { return n.Kind == Container || n.Kind == List }

// Path is n's schema path, /instance/interface/mtu.
func (n *Node) Path() string {
	if n.Parent == nil {
		return "/"
	}
	var parts []string
	for x := n; x.Parent != nil; x = x.Parent {
		parts = append(parts, x.Name)
	}
	slices.Reverse(parts)
	return "/" + strings.Join(parts, "/")
}

// Find walks a schema path from n (names, "/" separated).
func (n *Node) Find(path string) *Node {
	x := n
	for _, p := range strings.Split(strings.Trim(path, "/"), "/") {
		if p == "" {
			continue
		}
		if x = x.Child(p); x == nil {
			return nil
		}
	}
	return x
}

// Walk calls fn for n and every node below it, parents first.
func (n *Node) Walk(fn func(*Node)) {
	fn(n)
	for _, c := range n.Children {
		c.Walk(fn)
	}
}

// Type is a leaf's type, resolved to its base.
type Type struct {
	Kind     string // the YANG base type: string, boolean, int32, enumeration, union, leafref, ...
	Enums    []string
	Ranges   []Range
	Lengths  []Range
	Patterns []*regexp.Regexp
	Path     string // a leafref's path
	Union    []*Type
	// Format is the typedef of portitor-types.yang the type is, whose
	// values Go checks and makes canonical (formats.go); "" for none.
	Format string
	// Typedef is the name of the type as the leaf uses it: a typedef's
	// ("counter"), or the base type's.
	Typedef string
}

// Range is an inclusive range of a number or a length.
type Range struct{ Min, Max float64 }

// Numeric reports whether the type is an integer or decimal64.
func (t *Type) Numeric() bool {
	return strings.HasPrefix(t.Kind, "int") || strings.HasPrefix(t.Kind, "uint") || t.Kind == "decimal64"
}

// Leafrefs are the leafref paths of the type (itself, or members of a
// union).
func (t *Type) Leafrefs() []string {
	switch t.Kind {
	case "leafref":
		return []string{t.Path}
	case "union":
		var out []string
		for _, u := range t.Union {
			out = append(out, u.Leafrefs()...)
		}
		return out
	}
	return nil
}

// Check checks v against the type and returns its canonical form. A
// leafref's value is checked only to be a name here; that its target
// exists is the datastore's check.
func (t *Type) Check(v string) (string, error) {
	switch t.Kind {
	case "string":
		if f := formats[t.Format]; f != nil {
			var err error
			if v, err = f(strings.TrimSpace(v)); err != nil {
				return "", err
			}
		}
		if err := checkLength(t.Lengths, len([]rune(v))); err != nil {
			return "", err
		}
		for _, p := range t.Patterns {
			if !p.MatchString(v) {
				return "", fmt.Errorf("%q doesn't match %s", v, p.String())
			}
		}
		if strings.ContainsAny(v, "\x00") {
			return "", fmt.Errorf("a NUL character")
		}
		return v, nil
	case "boolean":
		switch v {
		case "true", "false":
			return v, nil
		}
		return "", fmt.Errorf("%q is not true or false", v)
	case "enumeration":
		if slices.Contains(t.Enums, v) {
			return v, nil
		}
		return "", fmt.Errorf("%q is not one of %s", v, strings.Join(t.Enums, ", "))
	case "union":
		// The members that check a value first, so that it is canonical
		// (an address shortened) if one takes it; a leafref takes any
		// name, and validation looks for its target.
		var errs []string
		for _, leafrefs := range []bool{false, true} {
			for _, u := range t.Union {
				if (u.Kind == "leafref") != leafrefs {
					continue
				}
				if c, err := u.Check(v); err == nil {
					return c, nil
				} else {
					errs = append(errs, err.Error())
				}
			}
		}
		return "", fmt.Errorf("%s", strings.Join(errs, "; or "))
	case "leafref":
		if v == "" {
			return "", fmt.Errorf("an empty name")
		}
		return v, nil
	case "empty":
		return "", nil
	case "decimal64":
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return "", fmt.Errorf("%q is not a number", v)
		}
		if err := checkRange(t.Ranges, f); err != nil {
			return "", err
		}
		return strconv.FormatFloat(f, 'f', -1, 64), nil
	}
	if t.Numeric() {
		bits, _ := strconv.Atoi(strings.TrimLeft(t.Kind, "uint"))
		var f float64
		var c string
		if strings.HasPrefix(t.Kind, "uint") {
			n, err := strconv.ParseUint(v, 10, bits)
			if err != nil {
				return "", fmt.Errorf("%q is not a whole number from 0 to %d", v, uint64(math.MaxUint64)>>(64-bits))
			}
			f, c = float64(n), strconv.FormatUint(n, 10)
		} else {
			n, err := strconv.ParseInt(v, 10, bits)
			if err != nil {
				return "", fmt.Errorf("%q is not a whole number of %d bits", v, bits)
			}
			f, c = float64(n), strconv.FormatInt(n, 10)
		}
		if err := checkRange(t.Ranges, f); err != nil {
			return "", err
		}
		return c, nil
	}
	return v, nil
}

func checkRange(rs []Range, f float64) error {
	if len(rs) == 0 {
		return nil
	}
	for _, r := range rs {
		if f >= r.Min && f <= r.Max {
			return nil
		}
	}
	return fmt.Errorf("%v is out of range %s", f, rangeString(rs))
}

func checkLength(rs []Range, n int) error {
	if len(rs) == 0 {
		return nil
	}
	if checkRange(rs, float64(n)) != nil {
		return fmt.Errorf("a length of %d, not %s", n, rangeString(rs))
	}
	return nil
}

func rangeString(rs []Range) string {
	parts := make([]string, len(rs))
	for i, r := range rs {
		if r.Min == r.Max {
			parts[i] = strconv.FormatFloat(r.Min, 'f', -1, 64)
		} else {
			parts[i] = strconv.FormatFloat(r.Min, 'f', -1, 64) + ".." + strconv.FormatFloat(r.Max, 'f', -1, 64)
		}
	}
	return strings.Join(parts, " | ")
}

// String describes the type for help: "int32", "true|false", "accept|drop".
func (t *Type) String() string {
	switch t.Kind {
	case "enumeration":
		return strings.Join(t.Enums, "|")
	case "boolean":
		return "true|false"
	case "union":
		var parts []string
		for _, u := range t.Union {
			if s := u.String(); !slices.Contains(parts, s) {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, " or ")
	case "leafref":
		parts := strings.Split(t.Path, "/")
		if len(parts) >= 2 {
			return "a " + parts[len(parts)-2] + "'s " + parts[len(parts)-1]
		}
		return "a reference"
	}
	if len(t.Ranges) > 0 {
		return t.Kind + " " + rangeString(t.Ranges)
	}
	return t.Kind
}

var (
	once     sync.Once
	compiled *Node
	loadErr  error
)

// Load returns the compiled schema of the embedded modules.
func Load() (*Node, error) {
	once.Do(func() { compiled, loadErr = compile(yang.Files) })
	return compiled, loadErr
}

// MustLoad is Load for tests and programs that can't run without it.
func MustLoad() *Node {
	n, err := Load()
	if err != nil {
		panic(err)
	}
	return n
}

func compile(files fs.FS) (*Node, error) {
	ms := goyang.NewModules()
	names, err := fs.Glob(files, "*.yang")
	if err != nil {
		return nil, err
	}
	for _, name := range names {
		data, err := fs.ReadFile(files, name)
		if err != nil {
			return nil, err
		}
		if err := ms.Parse(string(data), name); err != nil {
			return nil, err
		}
	}
	if errs := ms.Process(); len(errs) > 0 {
		return nil, fmt.Errorf("yang: %v", errs)
	}
	m, errs := ms.GetModule(Module)
	if len(errs) > 0 {
		return nil, fmt.Errorf("yang: %v", errs)
	}
	root := &Node{Name: Module, Kind: Container, byName: map[string]*Node{}, Ext: map[string]string{}, Description: m.Description}
	if mod, ok := m.Node.(*goyang.Module); ok {
		for _, r := range mod.Revision {
			if r.Name > root.Revision {
				root.Revision = r.Name
			}
		}
	}
	if err := addChildren(root, m, fileRanks(names)); err != nil {
		return nil, err
	}
	return root, nil
}

// fileRanks orders the modules' files for the order of children that
// come from groupings: the main module, then its submodules as included.
func fileRanks(names []string) map[string]int {
	order := []string{"portitor.yang", "portitor-system.yang", "portitor-interfaces.yang", "portitor-routing.yang",
		"portitor-firewall.yang", "portitor-services.yang", "portitor-objects.yang", "portitor-state.yang"}
	ranks := map[string]int{}
	for i, n := range order {
		ranks[n] = i
	}
	sort.Strings(names)
	for _, n := range names {
		if _, ok := ranks[n]; !ok {
			ranks[n] = len(ranks)
		}
	}
	return ranks
}

type position struct {
	file      int
	line, col int
}

func positionOf(e *goyang.Entry, ranks map[string]int) position {
	if e.Node == nil || e.Node.Statement() == nil {
		return position{file: math.MaxInt}
	}
	loc := e.Node.Statement().Location() // file:line:col
	parts := strings.Split(loc, ":")
	if len(parts) < 3 {
		return position{file: math.MaxInt}
	}
	line, _ := strconv.Atoi(parts[len(parts)-2])
	col, _ := strconv.Atoi(parts[len(parts)-1])
	return position{ranks[strings.Join(parts[:len(parts)-2], ":")], line, col}
}

func addChildren(n *Node, e *goyang.Entry, ranks map[string]int) error {
	entries := make([]*goyang.Entry, 0, len(e.Dir))
	for _, c := range e.Dir {
		if c.IsChoice() || c.IsCase() {
			return fmt.Errorf("%s: choice and case are not supported", c.Path())
		}
		if c.RPC != nil {
			if n.Kind != List {
				return fmt.Errorf("%s: an action belongs to a list's entries", c.Path())
			}
			a, err := convertAction(c, ranks)
			if err != nil {
				return err
			}
			n.Actions = append(n.Actions, a)
			continue
		}
		entries = append(entries, c)
	}
	slices.SortFunc(n.Actions, func(a, b *Action) int { return strings.Compare(a.Name, b.Name) })
	sort.Slice(entries, func(i, j int) bool {
		ki, kj := slices.Index(n.Keys, entries[i].Name), slices.Index(n.Keys, entries[j].Name)
		if ki >= 0 || kj >= 0 {
			if ki < 0 {
				return false
			}
			if kj < 0 {
				return true
			}
			return ki < kj
		}
		pi, pj := positionOf(entries[i], ranks), positionOf(entries[j], ranks)
		if pi.file != pj.file {
			return pi.file < pj.file
		}
		if pi.line != pj.line {
			return pi.line < pj.line
		}
		return pi.col < pj.col
	})
	for _, c := range entries {
		child, err := convert(c, ranks, n.State || c.Config == goyang.TSFalse)
		if err != nil {
			return err
		}
		child.Parent = n
		n.Children = append(n.Children, child)
		n.byName[child.Name] = child
	}
	return nil
}

func convert(e *goyang.Entry, ranks map[string]int, state bool) (*Node, error) {
	n := &Node{Name: e.Name, Description: strings.Join(strings.Fields(e.Description), " "), byName: map[string]*Node{}, Ext: map[string]string{}, State: state}
	for _, x := range e.Exts {
		if name, ok := strings.CutPrefix(x.Keyword, "px:"); ok {
			n.Ext[name] = x.Argument
		}
	}
	switch {
	case e.IsList():
		n.Kind = List
		n.Keys = strings.Fields(e.Key)
		if e.ListAttr != nil {
			n.OrderedByUser = e.ListAttr.OrderedByUser
		}
		if len(n.Keys) == 0 && !state {
			return nil, fmt.Errorf("%s: a list of configuration needs a key", e.Path())
		}
	case e.IsLeafList():
		n.Kind = LeafList
		if e.ListAttr != nil {
			n.OrderedByUser = e.ListAttr.OrderedByUser
		}
	case e.IsLeaf():
		n.Kind = Leaf
		if len(e.Default) > 0 {
			n.Default, n.HasDefault = e.Default[0], true
		}
		n.Mandatory = e.Mandatory == goyang.TSTrue
	default:
		n.Kind = Container
	}
	if n.Kind == Leaf || n.Kind == LeafList {
		t, err := convertType(e.Type)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.Path(), err)
		}
		n.Type = t
		if !n.HasDefault && e.Type.HasDefault && n.Kind == Leaf {
			n.Default, n.HasDefault = e.Type.Default, true
		}
		return n, nil
	}
	if err := addChildren(n, e, ranks); err != nil {
		return nil, err
	}
	for _, k := range n.Keys {
		if n.Child(k) == nil || n.Child(k).Kind != Leaf {
			return nil, fmt.Errorf("%s: key %s is not a leaf", e.Path(), k)
		}
	}
	return n, nil
}

// convertAction is an action's schema; its leaves are checked as any
// configuration's.
func convertAction(e *goyang.Entry, ranks map[string]int) (*Action, error) {
	a := &Action{Name: e.Name, Description: strings.Join(strings.Fields(e.Description), " ")}
	for _, x := range e.Exts {
		if x.Keyword == "px:action" {
			a.Kind = x.Argument
		}
	}
	switch a.Kind {
	case ActionView, ActionOperation, ActionChange, ActionCreate:
	default:
		return nil, fmt.Errorf("%s: px:action is view, operation, change or create, not %q", e.Path(), a.Kind)
	}
	io := func(name string, y *goyang.Entry) (*Node, error) {
		if y == nil {
			return &Node{Name: name, Kind: Container, byName: map[string]*Node{}, Ext: map[string]string{}}, nil
		}
		n, err := convert(y, ranks, false)
		if err != nil {
			return nil, err
		}
		n.Name, n.Kind = name, Container
		return n, nil
	}
	var err error
	if a.Input, err = io("input", e.RPC.Input); err != nil {
		return nil, err
	}
	if a.Output, err = io("output", e.RPC.Output); err != nil {
		return nil, err
	}
	return a, nil
}

func convertType(y *goyang.YangType) (*Type, error) {
	if y == nil {
		return nil, fmt.Errorf("no type")
	}
	t := &Type{Kind: goyang.TypeKindToName[y.Kind], Path: y.Path, Typedef: y.Name}
	if _, ok := formats[y.Name]; ok && t.Kind == "string" {
		t.Format = y.Name
	}
	if y.Enum != nil {
		// In the module's order: by value.
		vm := y.Enum.ValueMap()
		vals := make([]int64, 0, len(vm))
		for v := range vm {
			vals = append(vals, v)
		}
		slices.Sort(vals)
		for _, v := range vals {
			t.Enums = append(t.Enums, vm[v])
		}
	}
	t.Ranges = ranges(y.Range)
	if full, ok := builtinRange(t.Kind); ok && len(t.Ranges) == 1 && t.Ranges[0] == full {
		t.Ranges = nil // the type's own range, which Check knows
	}
	t.Lengths = ranges(y.Length)
	for _, p := range y.Pattern {
		re, err := regexp.Compile("^(?:" + p + ")$")
		if err != nil {
			return nil, fmt.Errorf("pattern %q: %w", p, err)
		}
		t.Patterns = append(t.Patterns, re)
	}
	for _, u := range y.Type {
		ut, err := convertType(u)
		if err != nil {
			return nil, err
		}
		t.Union = append(t.Union, ut)
	}
	switch t.Kind {
	case "binary", "bits", "identityref", "instance-identifier":
		return nil, fmt.Errorf("type %s is not supported", t.Kind)
	}
	return t, nil
}

// builtinRange is an integer type's range.
func builtinRange(kind string) (Range, bool) {
	switch kind {
	case "int8", "int16", "int32", "int64":
		bits, _ := strconv.Atoi(kind[3:])
		return Range{-math.Pow(2, float64(bits-1)), math.Pow(2, float64(bits-1)) - 1}, true
	case "uint8", "uint16", "uint32", "uint64":
		bits, _ := strconv.Atoi(kind[4:])
		return Range{0, math.Pow(2, float64(bits)) - 1}, true
	}
	return Range{}, false
}

func ranges(r goyang.YangRange) []Range {
	var out []Range
	for _, x := range r {
		out = append(out, Range{number(x.Min), number(x.Max)})
	}
	return out
}

func number(n goyang.Number) float64 {
	f := float64(n.Value) / math.Pow10(int(n.FractionDigits))
	if n.Negative {
		f = -f
	}
	return f
}
