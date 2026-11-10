// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package netconf

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/schema"
)

// action runs a YANG action (RFC 7950 section 7.15.2): <action> holds the
// path to the entry as elements, each list's keys as its key leaves, and
// innermost the action's element with its input leaves. It acts on the
// candidate, as edit-config does, a view too. The reply holds the output's
// leaves, or <ok/> for none.
func (s *session) action(ctx context.Context, op *elem) (string, error) {
	if s.env.Action == nil {
		return "", protocolErr("operation-not-supported", "actions")
	}
	if len(op.Children) != 1 {
		return "", protocolErr("missing-element", "action holds the path to one entry")
	}
	at, e := s.env.Schema, op.Children[0]
	var p datastore.Path
	for {
		if e.Space != schema.Namespace {
			return "", protocolErr("unknown-namespace", "%s (%s)", e.Local, e.Space)
		}
		c := at.Child(e.Local)
		if c == nil {
			if at.Kind == schema.List {
				if a := at.Action(e.Local); a != nil {
					return s.runAction(ctx, p, a, e)
				}
			}
			return "", appErr("unknown-element", p.String(s.env.Schema), "%s has no %s", nameOf(at), e.Local)
		}
		el := datastore.Elem{Name: c.Name}
		var next []*elem
		switch c.Kind {
		case schema.List:
			el.Keys = make([]string, len(c.Keys))
			for i, k := range c.Keys {
				ke := e.child(k)
				if ke == nil {
					return "", appErr("missing-element", p.String(s.env.Schema), "%s needs its key %s", c.Name, k)
				}
				el.Keys[i] = ke.text()
			}
			for _, x := range e.Children {
				if kc := c.Child(x.Local); kc == nil || !kc.IsKey() {
					next = append(next, x)
				}
			}
		case schema.Container:
			next = e.Children
		default:
			return "", appErr("bad-element", p.String(s.env.Schema), "%s is a leaf, not the way to an action", c.Name)
		}
		p = append(p, el)
		if len(next) != 1 {
			return "", appErr("missing-element", p.String(s.env.Schema), "the path goes on to one node or the action")
		}
		at, e = c, next[0]
	}
}

// runAction runs a with the input in its element e, as the API's action
// (Env.Action), which checks the user's access.
func (s *session) runAction(ctx context.Context, p datastore.Path, a *schema.Action, e *elem) (string, error) {
	obj := map[string]any{}
	for _, x := range e.Children {
		c := a.Input.Child(x.Local)
		switch {
		case c == nil:
			return "", appErr("unknown-element", p.String(s.env.Schema), "%s has no input %s", a.Name, x.Local)
		case c.Kind == schema.Leaf:
			obj[c.Name] = x.text()
		case c.Kind == schema.LeafList:
			vals, _ := obj[c.Name].([]string)
			obj[c.Name] = append(vals, x.text())
		default:
			return "", appErr("bad-element", p.String(s.env.Schema), "%s: only leaves are input", x.Local)
		}
	}
	data, err := json.Marshal(obj)
	if err != nil {
		return "", err
	}
	input, err := datastore.ReadValues(a.Input, data)
	if err != nil {
		return "", appErr("invalid-value", p.String(s.env.Schema), "%s: %s", a.Name, err.Error())
	}
	out, _, err := s.env.Action(ctx, p, a.Name, input, true)
	if err != nil {
		return "", appErr("operation-failed", p.String(s.env.Schema), "%s", err.Error())
	}
	var b strings.Builder
	writeNode(&b, out, true)
	if b.Len() == 0 {
		return ok, nil
	}
	return b.String(), nil
}
