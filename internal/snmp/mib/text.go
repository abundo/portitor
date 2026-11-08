// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package mib

import (
	"fmt"
	"strings"

	"github.com/abundo/portitor/internal/schema"
)

// ModuleName is the MIB module's name.
const ModuleName = "PORTITOR-MIB"

// Text is the MIB module (SMIv2) of m, its module identity at m.Base;
// revision is the YANG modules' (YYYY-MM-DD).
func (m *MIB) Text(revision string) string {
	b := &strings.Builder{}
	date := strings.ReplaceAll(revision, "-", "") + "0000Z"
	w := func(format string, args ...any) { fmt.Fprintf(b, format, args...) }
	w("-- SPDX-FileCopyrightText: 2026 The Portitor contributors\n")
	w("-- SPDX-License-Identifier: AGPL-3.0-or-later\n\n")
	w("-- Generated from Portitor's YANG modules (yang/portitor-state.yang) by\n")
	w("-- portitor-config mib. Do not edit.\n\n")
	w("%s DEFINITIONS ::= BEGIN\n\n", ModuleName)
	w("IMPORTS\n")
	w("    MODULE-IDENTITY, OBJECT-TYPE, Integer32, Unsigned32, Counter64\n        FROM SNMPv2-SMI\n")
	w("    MODULE-COMPLIANCE, OBJECT-GROUP\n        FROM SNMPv2-CONF\n")
	w("    TruthValue, DisplayString\n        FROM SNMPv2-TC\n")
	w("    CounterBasedGauge64\n        FROM HCNUM-TC;\n\n")
	w("portitorMIB MODULE-IDENTITY\n")
	w("    LAST-UPDATED \"%s\"\n", date)
	w("    ORGANIZATION \"The Portitor contributors\"\n")
	w("    CONTACT-INFO \"https://github.com/abundo/portitor\"\n")
	w("    DESCRIPTION\n        \"Portitor's state, read-only: what the firewalls run and see,\n")
	w("        as the YANG module portitor's config false nodes. A list is a\n")
	w("        table indexed by its keys and its parents' (a list without keys\n")
	w("        by its row number); a leaf-list is one string, its values\n")
	w("        separated by commas.\"\n")
	w("    REVISION \"%s\"\n    DESCRIPTION \"From the YANG modules' revision %s.\"\n", date, revision)
	oid := make([]string, len(m.Base))
	for i, n := range m.Base {
		oid[i] = fmt.Sprint(n)
	}
	// iso, then numbers: ASN.1's name form for the first arc.
	w("    ::= { iso %s }\n\n", strings.Join(oid[1:], " "))

	for _, g := range m.Groups {
		w("%s OBJECT IDENTIFIER ::= { portitorMIB %d }\n\n", g.Name, g.Num)
		for _, c := range g.Scalars {
			object(b, c.Name, c.Leaf, "read-only", "", g.Name, c.Num)
		}
	}
	for _, t := range m.Tables {
		entryType := strings.ToUpper(t.Stem[:1]) + t.Stem[1:] + "Entry"
		w("%s OBJECT-TYPE\n    SYNTAX SEQUENCE OF %s\n    MAX-ACCESS not-accessible\n    STATUS current\n", t.Name, entryType)
		w("    DESCRIPTION\n        %s\n    ::= { portitorMIB %d }\n\n", quote(t.List.Description, t.List.Path()), t.Num)
		var index []string
		for _, c := range t.Columns {
			if c.Index >= 0 {
				index = append(index, c.Name)
			}
		}
		w("%sEntry OBJECT-TYPE\n    SYNTAX %s\n    MAX-ACCESS not-accessible\n    STATUS current\n", t.Stem, entryType)
		w("    DESCRIPTION\n        \"A row of %s.\"\n    INDEX { %s }\n    ::= { %s 1 }\n\n", t.List.Path(), strings.Join(index, ", "), t.Name)
		w("%s ::= SEQUENCE {\n", entryType)
		for i, c := range t.Columns {
			sep := ","
			if i == len(t.Columns)-1 {
				sep = ""
			}
			w("    %s %s%s\n", c.Name, seqSyntax(c), sep)
		}
		w("}\n\n")
		for _, c := range t.Columns {
			access := "read-only"
			if c.Index >= 0 {
				access = "not-accessible"
			}
			object(b, c.Name, c.Leaf, access, columnSyntax(c), t.Stem+"Entry", c.Num)
		}
	}
	// Conformance: one group of every object, and the compliance with it.
	var objects []string
	for _, g := range m.Groups {
		for _, c := range g.Scalars {
			objects = append(objects, c.Name)
		}
	}
	for _, t := range m.Tables {
		for _, c := range t.Columns {
			if c.Index < 0 {
				objects = append(objects, c.Name)
			}
		}
	}
	w("ptConformance OBJECT IDENTIFIER ::= { portitorMIB %d }\n\n", m.Conformance)
	w("ptStateGroup OBJECT-GROUP\n    OBJECTS {\n        %s\n    }\n", strings.Join(objects, ",\n        "))
	w("    STATUS current\n    DESCRIPTION\n        \"Portitor's state.\"\n    ::= { ptConformance 1 }\n\n")
	w("ptCompliance MODULE-COMPLIANCE\n    STATUS current\n    DESCRIPTION\n        \"An agent with Portitor's state.\"\n")
	w("    MODULE -- this module\n        MANDATORY-GROUPS { ptStateGroup }\n    ::= { ptConformance 2 }\n\n")
	w("END\n")
	return b.String()
}

// columnSyntax is a column's syntax: an index's is restricted, as SMIv2
// asks (a number is Unsigned32, as indexSubIDs encodes it, a row number
// from 1, a string sized).
func columnSyntax(c *Column) string {
	if c.Index < 0 {
		s, _ := Syntax(c.Leaf)
		return s
	}
	switch base := seqSyntax(c); {
	case c.Leaf == nil:
		return "Unsigned32 (1..4294967295)"
	case base == "Unsigned32":
		return "Unsigned32 (0..4294967295)"
	default:
		return "DisplayString (SIZE (0..64))"
	}
}

// seqSyntax is a column's type in its entry's SEQUENCE, without a subtype.
func seqSyntax(c *Column) string {
	if c.Index >= 0 {
		if c.Leaf == nil || c.Leaf.Type.Numeric() {
			return "Unsigned32"
		}
		return "DisplayString"
	}
	s, _ := Syntax(c.Leaf)
	return s
}

func object(b *strings.Builder, name string, leaf *schema.Node, access, syntax, parent string, num uint32) {
	if syntax == "" {
		syntax, _ = Syntax(leaf)
	}
	desc, what := "", "a row number"
	if leaf != nil {
		desc, what = leaf.Description, leaf.Path()
	}
	fmt.Fprintf(b, "%s OBJECT-TYPE\n    SYNTAX %s\n    MAX-ACCESS %s\n    STATUS current\n", name, syntax, access)
	fmt.Fprintf(b, "    DESCRIPTION\n        %s\n    ::= { %s %d }\n\n", quote(desc, what), parent, num)
}

// quote is a DESCRIPTION: the YANG description and the node's path, in
// double quotes (which it may not hold).
func quote(desc, path string) string {
	desc = strings.ReplaceAll(strings.TrimSpace(desc), `"`, "'")
	if desc == "" {
		return fmt.Sprintf("%q", path)
	}
	return `"` + desc + " (" + path + `)"`
}
