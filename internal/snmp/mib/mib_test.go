// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package mib

import (
	"encoding/json"
	"flag"
	"os"
	"strings"
	"testing"

	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/schema"
	"github.com/abundo/portitor/internal/snmp/agentx"
)

var update = flag.Bool("update", false, "number new state nodes in oids.json and write the MIB")

const mibFile = "../../../deploy/mib/PORTITOR-MIB.txt"

func defaultMIB(t *testing.T, assign bool) (*MIB, Registry) {
	t.Helper()
	reg, err := LoadRegistry()
	if err != nil {
		t.Fatal(err)
	}
	base, _ := agentx.ParseOID(DefaultBase)
	return New(schema.MustLoad(), base, reg, assign), reg
}

// Every state node has its number, and the MIB file is the modules'.
func TestRegistryAndMIB(t *testing.T) {
	m, reg := defaultMIB(t, *update)
	root := schema.MustLoad()
	text := m.Text(root.Revision)
	if *update {
		data, _ := json.MarshalIndent(reg, "", "  ")
		if err := os.WriteFile("oids.json", append(data, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(mibFile, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	if miss := m.Missing(); len(miss) > 0 {
		t.Fatalf("state nodes without an OID (go test ./internal/snmp/mib -update): %v", miss)
	}
	if old, err := os.ReadFile(mibFile); err != nil || string(old) != text {
		t.Errorf("%s is not the modules' (go test ./internal/snmp/mib -update)", mibFile)
	}
	seen := map[string]bool{}
	names := func(n string) {
		if seen[n] || len(n) > 64 {
			t.Errorf("descriptor %q: used twice or longer than 64", n)
		}
		seen[n] = true
	}
	for _, g := range m.Groups {
		names(g.Name)
		for _, c := range g.Scalars {
			names(c.Name)
		}
	}
	for _, tb := range m.Tables {
		names(tb.Name)
		names(tb.Stem + "Entry")
		for _, c := range tb.Columns {
			names(c.Name)
		}
		if !strings.HasPrefix(tb.Name, "pt") {
			t.Errorf("table %s", tb.Name)
		}
	}
}

// A state tree's objects: a scalar, and a row of a table under an instance,
// indexed by the instance's name and the interface's.
func TestSnapshot(t *testing.T) {
	m, _ := defaultMIB(t, false)
	root := schema.MustLoad()
	tree := datastore.New(root)
	datastore.Fill(tree.Root.AddContainer(root.Child("system-state")), map[string]any{"hostname": "fw1", "host": map[string]any{"mem_total": 1 << 34}})
	in := tree.Root.AddEntry(root.Child("instance"), map[string]string{"name": "main"})
	datastore.FillList(in.AddContainer(in.S.Child("state")), "interfaces", []map[string]any{
		{"name": "eth0", "mtu": 1500, "rx_bytes": 7, "addresses": []string{"192.0.2.1/24", "2001:db8::1/64"}},
	})
	snap := m.Snapshot(tree)
	col := func(table, name string) agentx.OID {
		for _, tb := range m.Tables {
			if tb.Name == table {
				for _, c := range tb.Columns {
					if c.Name == name {
						return m.Base.Append(tb.Num, 1, c.Num)
					}
				}
			}
		}
		t.Fatalf("no %s.%s", table, name)
		return nil
	}
	scalar := func(name string) agentx.OID {
		for _, c := range m.Groups[0].Scalars {
			if c.Name == name {
				return m.Base.Append(m.Groups[0].Num, c.Num, 0)
			}
		}
		t.Fatalf("no %s", name)
		return nil
	}
	idx := agentx.OID{4, 'm', 'a', 'i', 'n', 4, 'e', 't', 'h', '0'}
	for oid, want := range map[string]any{
		scalar("ptSystemStateHostname").String():                                                   "fw1",
		scalar("ptSystemStateHostMemTotal").String():                                               uint64(1 << 34),
		append(col("ptInstanceInterfacesTable", "ptInstanceInterfacesMtu"), idx...).String():       int64(1500),
		append(col("ptInstanceInterfacesTable", "ptInstanceInterfacesRxBytes"), idx...).String():   uint64(7),
		append(col("ptInstanceInterfacesTable", "ptInstanceInterfacesAddresses"), idx...).String(): "192.0.2.1/24, 2001:db8::1/64",
	} {
		o, _ := agentx.ParseOID(oid)
		v, ok := snap.Get(o)
		got := v.Data
		if b, isBytes := got.([]byte); isBytes {
			got = string(b)
		}
		if !ok || got != want {
			t.Errorf("%s: %v %v, want %v", oid, ok, got, want)
		}
	}
	// A walk visits them in order, from the base.
	var prev agentx.OID
	n := 0
	for o := m.Base; ; n++ {
		vb, ok := snap.Next(o, false, nil)
		if !ok {
			break
		}
		if prev != nil && vb.Name.Compare(prev) <= 0 {
			t.Fatalf("out of order: %s after %s", vb.Name, prev)
		}
		prev, o = vb.Name, vb.Name
	}
	if n != len(snap) || n < 5 {
		t.Errorf("walked %d of %d", n, len(snap))
	}
}
