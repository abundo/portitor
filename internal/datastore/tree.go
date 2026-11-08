// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package datastore is the configuration as a tree of the YANG schema
// (internal/schema): a candidate that sessions edit and commit, checked
// against the schema (types, keys, mandatory leaves, leafrefs), with
// diffs, renames that follow references, and the JSON of RFC 7951. Every
// frontend (the CLI, NETCONF, the API) edits it through this package.
package datastore

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/abundo/portitor/internal/schema"
)

// Node is a container, the root or a list entry. Leaves and leaf-lists
// are values of their node; a list's entries are kept in order.
type Node struct {
	S      *schema.Node
	Parent *Node // the container or entry above; nil at the root

	Leaves     map[string]string
	LeafLists  map[string][]string
	Containers map[string]*Node
	Lists      map[string][]*Node
}

func newNode(s *schema.Node, parent *Node) *Node {
	return &Node{S: s, Parent: parent, Leaves: map[string]string{}, LeafLists: map[string][]string{},
		Containers: map[string]*Node{}, Lists: map[string][]*Node{}}
}

// Tree is a configuration.
type Tree struct {
	Root *Node
	// Renamed lists the entries Rename renamed since the tree became the
	// candidate, for Store.OnChange (data outside the tree that names
	// them); a clone starts without.
	Renamed []Renamed
}

// Renamed is an entry renamed: its path before, and its new keys.
type Renamed struct {
	Path Path
	Keys []string
}

// New is an empty configuration of the schema root.
func New(root *schema.Node) *Tree {
	return &Tree{Root: newNode(root, nil)}
}

// IsEntry reports whether n is a list entry.
func (n *Node) IsEntry() bool { return n.S.Kind == schema.List }

// Keys are an entry's key values, in key order.
func (n *Node) Keys() []string {
	out := make([]string, len(n.S.Keys))
	for i, k := range n.S.Keys {
		out[i] = n.Leaves[k]
	}
	return out
}

// Entry finds the entry of list name with keys.
func (n *Node) Entry(name string, keys []string) *Node {
	for _, e := range n.Lists[name] {
		if slices.Equal(e.Keys(), keys) {
			return e
		}
	}
	return nil
}

// Empty reports whether n holds nothing but its keys.
func (n *Node) Empty() bool {
	if len(n.LeafLists) > 0 || len(n.Lists) > 0 {
		return false
	}
	for _, c := range n.Containers {
		if !c.Empty() {
			return false
		}
	}
	for k := range n.Leaves {
		if !slices.Contains(n.S.Keys, k) {
			return false
		}
	}
	return true
}

// Leaf is a leaf's value, or its default when absent ("" without one).
func (n *Node) Leaf(name string) string {
	if v, ok := n.Leaves[name]; ok {
		return v
	}
	if s := n.S.Child(name); s != nil {
		return s.Default
	}
	return ""
}

// Clone copies n and everything below it, with parent as its parent.
func (n *Node) Clone(parent *Node) *Node {
	c := newNode(n.S, parent)
	for k, v := range n.Leaves {
		c.Leaves[k] = v
	}
	for k, v := range n.LeafLists {
		c.LeafLists[k] = slices.Clone(v)
	}
	for k, v := range n.Containers {
		c.Containers[k] = v.Clone(c)
	}
	for k, es := range n.Lists {
		out := make([]*Node, len(es))
		for i, e := range es {
			out[i] = e.Clone(c)
		}
		c.Lists[k] = out
	}
	return c
}

// Clone copies the tree.
func (t *Tree) Clone() *Tree { return &Tree{Root: t.Root.Clone(nil)} }

// Elem is a step of a path: a container, a list entry (with its keys),
// or a leaf or leaf-list at the end.
type Elem struct {
	Name string
	Keys []string
}

// Path is a path from the root.
type Path []Elem

// String writes p as XPath: /instance[name=host]/interface[name=wan0]/mtu.
// Keys need their schema names; String uses the schema root of s.
func (p Path) String(s *schema.Node) string {
	var b strings.Builder
	x := s
	for _, e := range p {
		b.WriteString("/" + e.Name)
		if x != nil {
			x = x.Child(e.Name)
		}
		for i, k := range e.Keys {
			name := fmt.Sprint(i)
			if x != nil && i < len(x.Keys) {
				name = x.Keys[i]
			}
			fmt.Fprintf(&b, "[%s=%s]", name, quoteKey(k))
		}
	}
	if b.Len() == 0 {
		return "/"
	}
	return b.String()
}

func quoteKey(k string) string {
	if strings.ContainsAny(k, "[]= /'\"") || k == "" {
		return "'" + strings.ReplaceAll(k, "'", "\\'") + "'"
	}
	return k
}

// CLI writes p as the CLI's words: instance host interface wan0 mtu.
func (p Path) CLI() string {
	var parts []string
	for _, e := range p {
		parts = append(parts, e.Name)
		for _, k := range e.Keys {
			parts = append(parts, Quote(k))
		}
	}
	return strings.Join(parts, " ")
}

// Quote quotes a word for the CLI when it needs it.
func Quote(s string) string {
	if s == "" || strings.ContainsAny(s, " \t\"'{}[]#;|\\") {
		return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
	}
	return s
}

// PathOf is the path of n.
func PathOf(n *Node) Path {
	var p Path
	for x := n; x != nil && x.Parent != nil; x = x.Parent {
		e := Elem{Name: x.S.Name}
		if x.IsEntry() {
			e.Keys = x.Keys()
		}
		p = append(p, e)
	}
	slices.Reverse(p)
	return p
}

// Error is a problem at a path.
type Error struct {
	Path string
	Msg  string
}

func (e *Error) Error() string {
	if e.Path == "" || e.Path == "/" {
		return e.Msg
	}
	return e.Path + ": " + e.Msg
}

func errAt(t *Tree, p Path, format string, args ...any) error {
	return &Error{Path: p.String(t.Root.S), Msg: fmt.Sprintf(format, args...)}
}

// Resolve walks p's schema: the nodes of its steps, from the root's
// children. It checks names and key counts, not that entries exist.
func Resolve(root *schema.Node, p Path) ([]*schema.Node, error) {
	out := make([]*schema.Node, 0, len(p))
	s := root
	for i, e := range p {
		c := s.Child(e.Name)
		if c == nil {
			return nil, fmt.Errorf("%s has no %q", nameOf(s), e.Name)
		}
		switch c.Kind {
		case schema.List:
			if len(e.Keys) != len(c.Keys) {
				return nil, fmt.Errorf("%s takes %d key(s): %s", c.Name, len(c.Keys), strings.Join(c.Keys, " "))
			}
		case schema.Leaf, schema.LeafList:
			if i != len(p)-1 {
				return nil, fmt.Errorf("%s is a %s", c.Name, c.Kind)
			}
			fallthrough
		default:
			if len(e.Keys) > 0 {
				return nil, fmt.Errorf("%s is not a list", c.Name)
			}
		}
		out = append(out, c)
		s = c
	}
	return out, nil
}

// ResolveAll is Resolve for a path that may end at a whole list: its last
// step a list without keys.
func ResolveAll(root *schema.Node, p Path) ([]*schema.Node, error) {
	if len(p) > 0 && p[len(p)-1].Keys == nil {
		parent := root
		ss, err := Resolve(root, p[:len(p)-1])
		if err != nil {
			return nil, err
		}
		if len(ss) > 0 {
			parent = ss[len(ss)-1]
		}
		if c := parent.Child(p[len(p)-1].Name); c != nil && c.Kind == schema.List && len(c.Keys) > 0 {
			return append(ss, c), nil
		}
	}
	return Resolve(root, p)
}

func nameOf(s *schema.Node) string {
	if s.Parent == nil {
		return "the configuration"
	}
	return s.Name
}

// writable refuses a path into the state (config false), which only the
// firewalls fill.
func writable(ss []*schema.Node) error {
	for _, s := range ss {
		if s.State {
			return fmt.Errorf("%s is state, read-only", s.Name)
		}
	}
	return nil
}

// Find returns the node p ends at (its parent's node, and the leaf's
// schema, for a leaf or leaf-list), or nil when an entry or container is
// missing.
func (t *Tree) Find(p Path) (node *Node, leaf *schema.Node, err error) {
	ss, err := Resolve(t.Root.S, p)
	if err != nil {
		return nil, nil, err
	}
	n := t.Root
	for i, e := range p {
		switch ss[i].Kind {
		case schema.Container:
			c := n.Containers[e.Name]
			if c == nil {
				return nil, nil, nil
			}
			n = c
		case schema.List:
			if n = n.Entry(e.Name, e.Keys); n == nil {
				return nil, nil, nil
			}
		default:
			return n, ss[i], nil
		}
	}
	return n, nil, nil
}

// Ensure returns the node at p (a container or entry), creating what is
// missing along it. New entries' keys are checked against their types.
func (t *Tree) Ensure(p Path) (*Node, error) {
	ss, err := Resolve(t.Root.S, p)
	if err != nil {
		return nil, err
	}
	if err := writable(ss); err != nil {
		return nil, err
	}
	n := t.Root
	for i, e := range p {
		switch ss[i].Kind {
		case schema.Container:
			c := n.Containers[e.Name]
			if c == nil {
				c = newNode(ss[i], n)
				n.Containers[e.Name] = c
			}
			n = c
		case schema.List:
			en := n.Entry(e.Name, e.Keys)
			if en == nil {
				en = newNode(ss[i], n)
				for k, name := range ss[i].Keys {
					if e.Keys[k] == "" {
						return nil, errAt(t, p[:i+1], "%s: a key can't be empty", name)
					}
					v, err := ss[i].Child(name).Type.Check(e.Keys[k])
					if err != nil {
						return nil, errAt(t, p[:i+1], "%s: %v", name, err)
					}
					en.Leaves[name] = v
				}
				// The canonical keys may name an entry that exists.
				if old := n.Entry(e.Name, en.Keys()); old != nil {
					en = old
				} else {
					n.insert(en)
				}
			}
			n = en
		default:
			return nil, errAt(t, p, "%s is a %s, not a container or list entry", e.Name, ss[i].Kind)
		}
	}
	return n, nil
}

// insert adds the entry e to its list in n: at the end of an ordered-by
// user list, else in key order.
func (n *Node) insert(e *Node) {
	es := n.Lists[e.S.Name]
	if e.S.OrderedByUser || len(e.S.Keys) == 0 {
		n.Lists[e.S.Name] = append(es, e)
		return
	}
	i, _ := slices.BinarySearchFunc(es, e.Keys(), func(x *Node, keys []string) int { return CompareKeys(x.Keys(), keys) })
	n.Lists[e.S.Name] = slices.Insert(es, i, e)
}

// CompareKeys orders entries of a list ordered by the system: key by key,
// numbers as numbers.
func CompareKeys(a, b []string) int {
	for i := range min(len(a), len(b)) {
		if c := compareKey(a[i], b[i]); c != 0 {
			return c
		}
	}
	return len(a) - len(b)
}

func compareKey(a, b string) int {
	x, errA := strconv.ParseFloat(a, 64)
	y, errB := strconv.ParseFloat(b, 64)
	switch {
	case errA == nil && errB == nil && x != y:
		if x < y {
			return -1
		}
		return 1
	case errA == nil && errB != nil:
		return -1
	case errA != nil && errB == nil:
		return 1
	}
	return strings.Compare(a, b)
}

// AddEntry adds an entry of the list s to n with the leaves given (its
// keys among them), unchecked, as an import does: Validate checks it.
func (n *Node) AddEntry(s *schema.Node, leaves map[string]string) *Node {
	e := newNode(s, n)
	for k, v := range leaves {
		e.Leaves[k] = v
	}
	n.insert(e)
	return e
}

// AddContainer returns the container s of n, made when missing.
func (n *Node) AddContainer(s *schema.Node) *Node {
	if c := n.Containers[s.Name]; c != nil {
		return c
	}
	c := newNode(s, n)
	n.Containers[s.Name] = c
	return c
}

// Referenced is the entry a reference of holder's leaf names by value:
// one of its own instance before a global one; nil when none.
func (t *Tree) Referenced(holder *Node, leaf *schema.Node, value string) *Node {
	for _, tg := range t.targets(holder, leaf) {
		if tg.entry.Leaves[tg.leaf] == value {
			return tg.entry
		}
	}
	return nil
}

// splitLeaf is p's node path and its last step, which must be a leaf or
// leaf-list.
func (t *Tree) splitLeaf(p Path, kinds ...schema.Kind) (Path, *schema.Node, error) {
	if len(p) == 0 {
		return nil, nil, fmt.Errorf("no leaf named")
	}
	ss, err := Resolve(t.Root.S, p)
	if err != nil {
		return nil, nil, err
	}
	if err := writable(ss); err != nil {
		return nil, nil, err
	}
	leaf := ss[len(ss)-1]
	if !slices.Contains(kinds, leaf.Kind) {
		return nil, nil, errAt(t, p, "%s is a %s", leaf.Name, leaf.Kind)
	}
	return p[:len(p)-1], leaf, nil
}

// Set sets a leaf. A key can't be set: Rename changes it.
func (t *Tree) Set(p Path, value string) error {
	np, leaf, err := t.splitLeaf(p, schema.Leaf)
	if err != nil {
		return err
	}
	if leaf.IsKey() {
		return errAt(t, p, "%s is a key; rename the entry to change it", leaf.Name)
	}
	v, err := leaf.Type.Check(value)
	if err != nil {
		return errAt(t, p, "%v", err)
	}
	n, err := t.Ensure(np)
	if err != nil {
		return err
	}
	n.Leaves[leaf.Name] = v
	return nil
}

// SetList replaces a leaf-list's values (none removes it).
func (t *Tree) SetList(p Path, values []string) error {
	np, leaf, err := t.splitLeaf(p, schema.LeafList)
	if err != nil {
		return err
	}
	out := make([]string, 0, len(values))
	for _, v := range values {
		c, err := leaf.Type.Check(v)
		if err != nil {
			return errAt(t, p, "%v", err)
		}
		if slices.Contains(out, c) {
			return errAt(t, p, "%q twice", c)
		}
		out = append(out, c)
	}
	n, err := t.Ensure(np)
	if err != nil {
		return err
	}
	if len(out) == 0 {
		delete(n.LeafLists, leaf.Name)
	} else {
		n.LeafLists[leaf.Name] = out
	}
	return nil
}

// Add adds a value to a leaf-list, at its end, if it isn't there.
func (t *Tree) Add(p Path, value string) error {
	np, leaf, err := t.splitLeaf(p, schema.LeafList)
	if err != nil {
		return err
	}
	v, err := leaf.Type.Check(value)
	if err != nil {
		return errAt(t, p, "%v", err)
	}
	n, err := t.Ensure(np)
	if err != nil {
		return err
	}
	if !slices.Contains(n.LeafLists[leaf.Name], v) {
		n.LeafLists[leaf.Name] = append(n.LeafLists[leaf.Name], v)
	}
	return nil
}

// Delete removes what p names: a leaf (back to its default), a leaf-list,
// a container or a list entry. With value, only that value of a
// leaf-list. Deleting what isn't there is an error.
func (t *Tree) Delete(p Path, value ...string) error {
	if len(p) == 0 {
		t.Root = newNode(t.Root.S, nil)
		return nil
	}
	ss, err := Resolve(t.Root.S, p)
	if err != nil {
		return err
	}
	if err := writable(ss); err != nil {
		return err
	}
	last := ss[len(ss)-1]
	parent, _, err := t.Find(p[:len(p)-1])
	if err != nil {
		return err
	}
	if parent == nil {
		return errAt(t, p, "not found")
	}
	name := p[len(p)-1].Name
	switch last.Kind {
	case schema.Leaf:
		if last.IsKey() {
			return errAt(t, p, "%s is a key; delete the entry", name)
		}
		if _, ok := parent.Leaves[name]; !ok {
			return errAt(t, p, "not set")
		}
		delete(parent.Leaves, name)
	case schema.LeafList:
		vals, ok := parent.LeafLists[name]
		if !ok {
			return errAt(t, p, "not set")
		}
		if len(value) == 0 {
			delete(parent.LeafLists, name)
			break
		}
		for _, v := range value {
			i := slices.Index(vals, v)
			if i < 0 {
				return errAt(t, p, "has no %q", v)
			}
			vals = slices.Delete(vals, i, i+1)
		}
		if len(vals) == 0 {
			delete(parent.LeafLists, name)
		} else {
			parent.LeafLists[name] = vals
		}
	case schema.Container:
		if parent.Containers[name] == nil {
			return errAt(t, p, "not set")
		}
		delete(parent.Containers, name)
	case schema.List:
		es := parent.Lists[name]
		i := slices.IndexFunc(es, func(e *Node) bool { return slices.Equal(e.Keys(), p[len(p)-1].Keys) })
		if i < 0 {
			return errAt(t, p, "not found")
		}
		es = slices.Delete(es, i, i+1)
		if len(es) == 0 {
			delete(parent.Lists, name)
		} else {
			parent.Lists[name] = es
		}
	}
	t.prune(parent)
	return nil
}

// prune removes containers left empty above n.
func (t *Tree) prune(n *Node) {
	for n != nil && n.Parent != nil && n.S.Kind == schema.Container && n.Empty() {
		delete(n.Parent.Containers, n.S.Name)
		n = n.Parent
	}
}

// Move moves an entry of an ordered-by user list: where is first, last,
// before or after (the entry with keys ref).
func (t *Tree) Move(p Path, where string, ref []string) error {
	n, _, err := t.Find(p)
	if err != nil {
		return err
	}
	if n == nil || !n.IsEntry() {
		return errAt(t, p, "not found")
	}
	if !n.S.OrderedByUser {
		return errAt(t, p, "%s is ordered by the system", n.S.Name)
	}
	es := n.Parent.Lists[n.S.Name]
	i := slices.Index(es, n)
	es = slices.Delete(slices.Clone(es), i, i+1)
	switch where {
	case "first":
		es = slices.Insert(es, 0, n)
	case "last":
		es = append(es, n)
	case "before", "after":
		j := slices.IndexFunc(es, func(e *Node) bool { return slices.Equal(e.Keys(), ref) })
		if j < 0 {
			return errAt(t, p, "no %s %s to move %s", n.S.Name, strings.Join(ref, " "), where)
		}
		if where == "after" {
			j++
		}
		es = slices.Insert(es, j, n)
	default:
		return fmt.Errorf("move: first, last, before or after")
	}
	n.Parent.Lists[n.S.Name] = es
	return nil
}

// Rename gives an entry new keys and rewrites the leafrefs (and px:global-ref
// leaves) that name it, as a rename in the GUI rewrites references.
func (t *Tree) Rename(p Path, keys []string) error {
	n, _, err := t.Find(p)
	if err != nil {
		return err
	}
	if n == nil || !n.IsEntry() {
		return errAt(t, p, "not found")
	}
	if len(keys) != len(n.S.Keys) {
		return errAt(t, p, "%s takes %d key(s)", n.S.Name, len(n.S.Keys))
	}
	newKeys := make([]string, len(keys))
	for i, k := range n.S.Keys {
		v, err := n.S.Child(k).Type.Check(keys[i])
		if err != nil {
			return errAt(t, p, "%s: %v", k, err)
		}
		newKeys[i] = v
	}
	if n.Parent.Entry(n.S.Name, newKeys) != nil {
		return errAt(t, p, "%s %s exists", n.S.Name, strings.Join(newKeys, " "))
	}
	old := n.Keys()
	// Each key leaf that references point at: rewrite them first, while
	// their targets still resolve.
	for i, k := range n.S.Keys {
		if old[i] == newKeys[i] {
			continue
		}
		t.eachRef(func(holder *Node, leaf *schema.Node, value string, set func(string)) {
			if value == old[i] && slices.ContainsFunc(t.targets(holder, leaf), func(tg target) bool { return tg.entry == n && tg.leaf == k }) {
				// A key that refers: its entry is renamed too.
				var was Path
				if holder.IsEntry() && slices.Contains(holder.S.Keys, leaf.Name) {
					was = PathOf(holder)
				}
				set(newKeys[i])
				if was != nil {
					t.Renamed = append(t.Renamed, Renamed{Path: was, Keys: holder.Keys()})
				}
			}
		})
	}
	for i, k := range n.S.Keys {
		n.Leaves[k] = newKeys[i]
	}
	t.Renamed = append(t.Renamed, Renamed{Path: slices.Clone(p), Keys: newKeys})
	return nil
}

// eachRef calls fn for every value of a leaf or leaf-list that may refer
// to an entry: of a leafref type (or union with one), or px:global-ref.
func (t *Tree) eachRef(fn func(holder *Node, leaf *schema.Node, value string, set func(string))) {
	var walk func(n *Node)
	walk = func(n *Node) {
		for name, v := range n.Leaves {
			s := n.S.Child(name)
			if s == nil || !isRef(s) {
				continue
			}
			fn(n, s, v, func(nv string) { n.Leaves[name] = nv })
		}
		for name, vs := range n.LeafLists {
			s := n.S.Child(name)
			if s == nil || !isRef(s) {
				continue
			}
			for i, v := range vs {
				fn(n, s, v, func(nv string) { n.LeafLists[name][i] = nv })
			}
		}
		for _, c := range n.Containers {
			walk(c)
		}
		for _, es := range n.Lists {
			for _, e := range es {
				walk(e)
			}
		}
	}
	walk(t.Root)
}

func isRef(s *schema.Node) bool {
	if _, ok := s.Ext["global-ref"]; ok {
		return true
	}
	return len(s.Type.Leafrefs()) > 0
}

// A target is a leaf a reference may name: the leaf of an entry (a key)
// or of a container.
type target struct {
	entry *Node
	leaf  string
}

// targets are what the leaf of holder may refer to, by its leafref paths
// (and px:global-ref, with the entries marked global in other instances).
func (t *Tree) targets(holder *Node, leaf *schema.Node) []target {
	var out []target
	for _, path := range leaf.Type.Leafrefs() {
		out = append(out, evalPath(holder, path)...)
	}
	if path, ok := leaf.Ext["global-ref"]; ok {
		out = append(out, evalPath(holder, path)...)
		out = append(out, t.globals(holder, path)...)
	}
	return out
}

// globals are the entries the px:global-ref path names in every instance
// but holder's, of those with global true.
func (t *Tree) globals(holder *Node, path string) []target {
	// The path climbs to the instance entry, then down to the list.
	ups, rest := splitUps(path)
	inst := holder
	for i := 1; i < ups && inst != nil; i++ {
		inst = inst.Parent
	}
	if inst == nil || inst.Parent == nil {
		return nil
	}
	var out []target
	for _, other := range inst.Parent.Lists[inst.S.Name] {
		if other == inst {
			continue
		}
		for _, tg := range descend(other, rest) {
			if tg.entry.Leaf("global") == "true" {
				out = append(out, tg)
			}
		}
	}
	return out
}

func splitUps(path string) (int, []string) {
	ups := 0
	parts := strings.Split(path, "/")
	for len(parts) > 0 && parts[0] == ".." {
		ups++
		parts = parts[1:]
	}
	return ups, parts
}

// evalPath evaluates a relative leafref path from the node holding the
// leaf: the first ".." is the holder, each further one its parent; then
// down by names to the leaf.
func evalPath(holder *Node, path string) []target {
	ups, rest := splitUps(path)
	if ups == 0 || len(rest) == 0 {
		return nil
	}
	n := holder
	for i := 1; i < ups; i++ {
		if n = n.Parent; n == nil {
			return nil
		}
	}
	return descend(n, rest)
}

func descend(n *Node, names []string) []target {
	if len(names) == 1 {
		if _, ok := n.Leaves[names[0]]; ok {
			return []target{{n, names[0]}}
		}
		return nil
	}
	var out []target
	if c := n.Containers[names[0]]; c != nil {
		out = append(out, descend(c, names[1:])...)
	}
	for _, e := range n.Lists[names[0]] {
		out = append(out, descend(e, names[1:])...)
	}
	return out
}

// RefValues are the values a leaf of holder may take by its references,
// for completion: the names its leafrefs point at.
func (t *Tree) RefValues(holder *Node, leaf *schema.Node) []string {
	var out []string
	for _, tg := range t.targets(holder, leaf) {
		if v := tg.entry.Leaves[tg.leaf]; !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

// Visible is a copy of t without what canRead refuses: by the top-level
// lists and their entries, and the top-level containers.
func (t *Tree) Visible(canRead func(Path) bool) *Tree {
	out := t.Clone()
	for name, es := range out.Root.Lists {
		kept := es[:0]
		for _, e := range es {
			if canRead(Path{{Name: name, Keys: e.Keys()}}) {
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
		if !canRead(Path{{Name: name}}) {
			delete(out.Root.Containers, name)
		}
	}
	return out
}
