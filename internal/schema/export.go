// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package schema

import "strings"

// Exported is a schema node as the GUI gets it (GET /api/schema): what it
// needs to build forms and tables, without the mapping onto the tables.
type Exported struct {
	Name          string      `json:"name"`
	Kind          string      `json:"kind"`
	Keys          []string    `json:"keys,omitempty"`
	OrderedByUser bool        `json:"ordered_by_user,omitempty"`
	Type          *ExportType `json:"type,omitempty"`
	Default       *string     `json:"default,omitempty"`
	Mandatory     bool        `json:"mandatory,omitempty"`
	Description   string      `json:"description,omitempty"`
	State         bool        `json:"state,omitempty"`
	Secret        bool        `json:"secret,omitempty"`
	// UI holds the px:ui-* hints (px:ui-widget "tags" is ui.widget).
	UI       map[string]string `json:"ui,omitempty"`
	Children []*Exported       `json:"children,omitempty"`
}

// ExportType is a leaf's type.
type ExportType struct {
	Base     string        `json:"base"`
	Enums    []string      `json:"enums,omitempty"`
	Ranges   [][2]float64  `json:"ranges,omitempty"`
	Lengths  [][2]float64  `json:"lengths,omitempty"`
	Patterns []string      `json:"patterns,omitempty"`
	Path     string        `json:"path,omitempty"`
	Union    []*ExportType `json:"union,omitempty"`
}

// Export is the tree below n.
func (n *Node) Export() *Exported {
	e := &Exported{
		Name: n.Name, Kind: n.Kind.String(), Keys: n.Keys, OrderedByUser: n.OrderedByUser,
		Mandatory: n.Mandatory, Description: n.Description, State: n.State, Secret: n.Secret(),
	}
	if n.HasDefault {
		d := n.Default
		e.Default = &d
	}
	if n.Type != nil {
		e.Type = n.Type.export()
	}
	for k, v := range n.Ext {
		if name, ok := strings.CutPrefix(k, "ui-"); ok {
			if e.UI == nil {
				e.UI = map[string]string{}
			}
			e.UI[name] = v
		}
	}
	for _, c := range n.Children {
		e.Children = append(e.Children, c.Export())
	}
	return e
}

func (t *Type) export() *ExportType {
	e := &ExportType{Base: t.Kind, Enums: t.Enums, Path: t.Path}
	for _, r := range t.Ranges {
		e.Ranges = append(e.Ranges, [2]float64{r.Min, r.Max})
	}
	for _, r := range t.Lengths {
		e.Lengths = append(e.Lengths, [2]float64{r.Min, r.Max})
	}
	for _, p := range t.Patterns {
		e.Patterns = append(e.Patterns, p.String())
	}
	for _, u := range t.Union {
		e.Union = append(e.Union, u.export())
	}
	return e
}
