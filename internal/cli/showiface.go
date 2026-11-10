// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package cli

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/abundo/portitor/internal/datastore"
)

// showInterface is show interface [name]: the virtual firewalls' devices
// from the state (each instance's state/interfaces), with the admin state
// and description of a configured one from the running configuration. Without
// a name a table of them all, with one each such device's detail and
// counters. Inside a virtual firewall (where there is no interface node, as
// under its bgp), that one's alone.
func (s *Session) showInterface(ctx context.Context, words []string) error {
	if len(words) > 2 {
		return errors.New("show interface [name]")
	}
	name := ""
	if len(words) == 2 {
		name = words[1]
	}
	t, err := s.stateTree(ctx)
	if err != nil {
		return err
	}
	only := ""
	if len(s.cwd) > 0 && s.cwd[0].Name == "instance" && len(s.cwd[0].Keys) > 0 {
		only = s.cwd[0].Keys[0]
	}
	type device struct {
		vf     string
		state  *datastore.Node // state/interfaces entry
		config *datastore.Node // the instance's interface entry, nil when made for one
	}
	var devs []device
	vfs := 0
	for _, inst := range t.Root.Lists["instance"] {
		vf := inst.Leaves["name"]
		if only != "" && vf != only {
			continue
		}
		st := inst.Containers["state"]
		if st == nil || !s.env.Access.CanRead(datastore.PathOf(st)) {
			continue
		}
		vfs++
		for _, d := range st.Lists["interfaces"] {
			if name != "" && d.Leaves["name"] != name {
				continue
			}
			devs = append(devs, device{vf, d, inst.Entry("interface", []string{d.Leaves["name"]})})
		}
	}
	if name != "" && len(devs) == 0 {
		return fmt.Errorf("no interface %s", name)
	}
	admin := func(c *datastore.Node) string {
		switch {
		case c == nil:
			return "-"
		case c.Leaf("enabled") == "false":
			return "disable"
		}
		return "enable"
	}
	or := func(v, none string) string {
		if v == "" {
			return none
		}
		return v
	}

	if name == "" {
		w := tabwriter.NewWriter(s.out, 0, 0, 2, ' ', 0)
		cols := "Name\tKind\tAdmin\tOper\tMTU\tMAC\tAddresses\n"
		if vfs > 1 {
			cols = "VF\t" + cols
		}
		fmt.Fprint(w, cols)
		for _, d := range devs {
			addrs := d.state.LeafLists["addresses"]
			first := ""
			if len(addrs) > 0 {
				first = addrs[0]
			}
			row := []string{d.state.Leaves["name"], or(d.state.Leaves["kind"], "-"), admin(d.config),
				or(d.state.Leaves["state"], "-"), or(d.state.Leaves["mtu"], "-"), or(d.state.Leaves["mac"], "-"), first}
			if vfs > 1 {
				row = append([]string{d.vf}, row...)
			}
			fmt.Fprintln(w, strings.Join(row, "\t"))
			for _, a := range addrs[min(1, len(addrs)):] {
				fmt.Fprintln(w, strings.Repeat("\t", len(row)-1)+a)
			}
		}
		return w.Flush()
	}

	for i, d := range devs {
		if i > 0 {
			s.printf("\n")
		}
		w := tabwriter.NewWriter(s.out, 0, 0, 2, ' ', 0)
		fmt.Fprintf(w, "instance %s interface %s\n", d.vf, d.state.Leaves["name"])
		if d.config != nil && d.config.Leaves["description"] != "" {
			fmt.Fprintf(w, "  description\t%s\n", d.config.Leaves["description"])
		}
		fmt.Fprintf(w, "  kind\t%s\n", or(d.state.Leaves["kind"], "-"))
		fmt.Fprintf(w, "  admin-state\t%s\n", admin(d.config))
		fmt.Fprintf(w, "  oper-state\t%s\n", or(d.state.Leaves["state"], "-"))
		fmt.Fprintf(w, "  mtu\t%s\n", or(d.state.Leaves["mtu"], "-"))
		fmt.Fprintf(w, "  mac\t%s\n", or(d.state.Leaves["mac"], "-"))
		addrs := d.state.LeafLists["addresses"]
		if len(addrs) == 0 {
			addrs = []string{"-"}
		}
		for j, a := range addrs {
			label := ""
			if j == 0 {
				label = "addresses"
			}
			fmt.Fprintf(w, "  %s\t%s\n", label, a)
		}
		if err := w.Flush(); err != nil {
			return err
		}
		rows := [][3]string{{"counters", "rx", "tx"}}
		for _, c := range []string{"bytes", "packets", "errors", "dropped"} {
			rows = append(rows, [3]string{c, or(d.state.Leaves["rx-"+c], "0"), or(d.state.Leaves["tx-"+c], "0")})
		}
		rows = append(rows,
			[3]string{"over-errors", or(d.state.Leaves["rx-over-errors"], "0"), ""},
			[3]string{"multicast", or(d.state.Leaves["rx-multicast"], "0"), ""},
			[3]string{"carrier-errors", "", or(d.state.Leaves["tx-carrier-errors"], "0")},
			[3]string{"collisions", "", or(d.state.Leaves["tx-collisions"], "0")})
		var wl, wn int
		for _, r := range rows {
			wl, wn = max(wl, len(r[0])), max(wn, len(r[1]), len(r[2]))
		}
		for _, r := range rows {
			s.printf("%s\n", strings.TrimRight(fmt.Sprintf("  %-*s  %*s  %*s", wl, r[0], wn, r[1], wn, r[2]), " "))
		}
	}
	return nil
}

// interfaceItems completes show interface's name from the running
// configuration's interfaces (the state would ask the firewalls), of the
// virtual firewall here or of all.
func (s *Session) interfaceItems(ctx context.Context) []Item {
	t, err := s.tree(ctx, false)
	if err != nil {
		return nil
	}
	only := ""
	if len(s.cwd) > 0 && s.cwd[0].Name == "instance" && len(s.cwd[0].Keys) > 0 {
		only = s.cwd[0].Keys[0]
	}
	var items []Item
	for _, inst := range t.Root.Lists["instance"] {
		vf := inst.Leaves["name"]
		if only != "" && vf != only {
			continue
		}
		for _, e := range inst.Lists["interface"] {
			n := e.Leaves["name"]
			if s.env.Access.CanRead(datastore.PathOf(e)) && !slices.ContainsFunc(items, func(it Item) bool { return it.Word == n }) {
				items = append(items, Item{n, "interface of " + vf})
			}
		}
	}
	return items
}
