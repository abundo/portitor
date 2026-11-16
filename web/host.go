// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"encoding/json"
	"net/url"
	"strings"

	"github.com/abundo/portitor/internal/datastore"
)

// The firewall's host, the default instance, is the configuration's top
// level (since 1.1.0): its name is the leaf host-name, its lists and leaves
// the top level's. The virtual firewalls are the instance list. These name
// either by its name, as the API's ?instance= and the rows do.

// hostName is the tree's host's name, "" before it has one.
func hostName(t *datastore.Tree) string { return t.Root.Leaf("host-name") }

// isHostName reports whether name is the tree's host's.
func isHostName(t *datastore.Tree, name string) bool {
	return name != "" && name == hostName(t)
}

// instPath is the path of the instance named name: the top level (an
// empty path) for the host, else its instance entry.
func instPath(t *datastore.Tree, name string) datastore.Path {
	if isHostName(t, name) {
		return datastore.Path{}
	}
	return datastore.Path{{Name: "instance", Keys: []string{name}}}
}

// instNode is the node of the instance named name: the top level for the
// host, its entry for a virtual firewall, nil for neither.
func instNode(t *datastore.Tree, name string) *datastore.Node {
	if isHostName(t, name) {
		return t.Root
	}
	return t.Root.Entry("instance", []string{name})
}

// instNodes are the host (when it has a name) and every virtual firewall.
func instNodes(t *datastore.Tree) []*datastore.Node {
	var out []*datastore.Node
	if hostName(t) != "" {
		out = append(out, t.Root)
	}
	return append(out, t.Root.Lists["instance"]...)
}

// nodeName is the name of an instNodes node.
func nodeName(n *datastore.Node) string {
	if n.Parent == nil {
		return n.Leaf("host-name")
	}
	return n.Leaf("name")
}

// isHostNode reports whether n (of instNodes) is the host.
func isHostNode(n *datastore.Node) bool { return n.Parent == nil }

// instPathString is instPath in the API's form (instance=blue/, or "" for
// the host), to put before a list's name.
func instPathString(t *datastore.Tree, name string) string {
	if isHostName(t, name) {
		return ""
	}
	return "instance=" + url.PathEscape(name) + "/"
}

// hostAsEntry is the host of t as an instance entry named after it (the
// shape of 1.0.0, without is-default), in a tree of its own: what a bundle
// of the host holds. The firewall's DNS templates (the top level's) go with
// it as its own.
func hostAsEntry(t *datastore.Tree) (*datastore.Node, error) {
	data, err := datastore.NodeJSON(t.Root, datastore.JSONOptions{Secrets: true})
	if err != nil {
		return nil, err
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err != nil {
		return nil, err
	}
	inst := t.Root.S.Child("instance")
	entry := map[string]json.RawMessage{}
	for k, v := range obj {
		local := k
		if i := strings.IndexByte(k, ':'); i >= 0 {
			local = k[i+1:]
		}
		switch {
		case local == "host-name":
			entry["name"] = v
		case local == "name" || local == "firewall" || local == "instance":
		case inst.Child(local) != nil && !inst.Child(local).State:
			entry[local] = v
		}
	}
	body, err := json.Marshal(entry)
	if err != nil {
		return nil, err
	}
	out := datastore.New(t.Root.S)
	if err := out.EditJSON(datastore.Path{{Name: "instance"}}, datastore.EditCreate, body); err != nil {
		return nil, err
	}
	return out.Root.Entry("instance", []string{hostName(t)}), nil
}

// entryAsHost makes the instance entry in work's host: its members the top
// level's, named name.
func entryAsHost(work *datastore.Tree, in *datastore.Node, name string) error {
	data, err := datastore.NodeJSON(in, datastore.JSONOptions{Secrets: true})
	if err != nil {
		return err
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	top := map[string]json.RawMessage{}
	for k, v := range obj {
		if k == "name" || k == "firewall" || k == "is-default" {
			continue
		}
		top["portitor:"+k] = v
	}
	top["portitor:host-name"], _ = json.Marshal(name)
	body, err := json.Marshal(top)
	if err != nil {
		return err
	}
	return work.ReadJSON(datastore.Path{}, body)
}

// walkInstance calls fn for n and every node below it of the instance: for
// the host (the top level), only what an instance has too, not the virtual
// firewalls or the top level's own lists.
func walkInstance(n *datastore.Node, fn func(*datastore.Node)) {
	if !isHostNode(n) {
		n.Walk(fn)
		return
	}
	fn(n)
	inst := n.S.Child("instance")
	for name, es := range n.Lists {
		if name == "instance" || inst.Child(name) == nil {
			continue
		}
		for _, e := range es {
			e.Walk(fn)
		}
	}
	for name, c := range n.Containers {
		if inst.Child(name) != nil {
			c.Walk(fn)
		}
	}
}
