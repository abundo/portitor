// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package datastore

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// Migrations bring the RFC 7951 JSON of a whole tree of an earlier release
// to this one's shape, by the module's name (the schema root's): each one
// takes the top-level object and reports whether it changed it. They run
// wherever a whole tree is read (UnmarshalJSON): the candidate, the kept
// commits, copies, backups, bundles. Each must leave a tree of this
// release's shape alone, so reading one twice is reading it once.
var migrations = map[string][]func(obj map[string]json.RawMessage) (bool, error){
	"portitor": {hostToRoot},
}

// Migrate is data, a whole tree's JSON of the module, in this release's
// shape, and whether a migration changed it.
func Migrate(module string, data []byte) ([]byte, bool, error) {
	ms := migrations[module]
	if len(ms) == 0 {
		return data, false, nil
	}
	var obj map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&obj); err != nil || obj == nil {
		return data, false, nil // readObject says what is wrong with it
	}
	changed := false
	for _, m := range ms {
		c, err := m(obj)
		if err != nil {
			return nil, false, err
		}
		changed = changed || c
	}
	if !changed {
		return data, false, nil
	}
	out, err := json.Marshal(obj)
	return out, true, err
}

// hostToRoot (1.1.0): the firewall's host was the instance with is-default
// true; its configuration is the top level now, its name host-name, and
// its firewall the tree's (one per tree). Its lists join those of the
// same name there (the firewall's DNS templates, which were the top
// level's already).
func hostToRoot(obj map[string]json.RawMessage) (bool, error) {
	const pfx = "portitor:"
	raw, ok := obj[pfx+"instance"]
	if !ok {
		return false, nil
	}
	var insts []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &insts); err != nil {
		return false, nil // readObject says what is wrong with it
	}
	host := -1
	for i, in := range insts {
		if string(in["is-default"]) == "true" {
			if host >= 0 {
				return false, fmt.Errorf("the configuration has two hosts (default virtual firewalls): this release keeps one firewall's configuration")
			}
			host = i
		}
	}
	if host < 0 {
		return false, nil
	}
	if _, ok := obj[pfx+"host-name"]; ok {
		return false, fmt.Errorf("the configuration has its host at the top level and as a virtual firewall")
	}
	for name, v := range insts[host] {
		switch name {
		case "is-default", "firewall":
			continue
		case "name":
			obj[pfx+"host-name"] = v
			continue
		}
		key := pfx + name
		if strings.Contains(name, ":") {
			key = name
		}
		have, ok := obj[key]
		if !ok {
			obj[key] = v
			continue
		}
		// Lists of the same name: the host's entries join the top
		// level's (keys are unique across both: confcheck kept them so).
		var a, b []json.RawMessage
		if json.Unmarshal(have, &a) != nil || json.Unmarshal(v, &b) != nil {
			return false, fmt.Errorf("the host's %s and the top level's can't be joined", name)
		}
		joined, err := json.Marshal(append(a, b...))
		if err != nil {
			return false, err
		}
		obj[key] = joined
	}
	insts = append(insts[:host], insts[host+1:]...)
	if len(insts) == 0 {
		delete(obj, pfx+"instance")
	} else {
		b, err := json.Marshal(insts)
		if err != nil {
			return false, err
		}
		obj[pfx+"instance"] = b
	}
	return true, nil
}

// MigrateIDPaths moves the kept ids' paths of a tree hostToRoot moved: an
// entry of the host instance (named host) is now at the top level, and the
// host's own row is the top level's ("/"). It reports whether it moved
// any; paths of this release's shape are left alone.
func MigrateIDPaths(paths []string, host string, move func(from, to string)) bool {
	if host == "" {
		return false
	}
	prefix := "/instance[name=" + quoteKey(host) + "]"
	moved := false
	for _, p := range paths {
		switch {
		case p == prefix:
			move(p, "/")
		case strings.HasPrefix(p, prefix+"/"):
			move(p, strings.TrimPrefix(p, prefix))
		default:
			continue
		}
		moved = true
	}
	return moved
}
