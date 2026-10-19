// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"

	"github.com/abundo/portitor/internal/fwconfig"
)

// Policy routes (fwconfig.PolicyRoute): the ruleset marks the packets of
// the i-th, and the agent keeps, per IP version it routes, a rule "fwmark
// <mark> lookup <table>" at preference fwconfig.PolicyRouteTable(i) and
// the default route in that table, both proto RouteProto. The rules at
// those preferences and the routes in those tables are the agent's.

// policyRoute is the route of one policy route in one IP version.
type policyRoute struct {
	table, mark  int
	gateway, dev string
	fam          string // "-4", "-6"
}

// policyRoutes are the routes the instance's policy routes want in one IP
// version ("-4", "-6").
func policyRoutes(in *fwconfig.Instance, fam string) []policyRoute {
	version := "ipv4"
	if fam == "-6" {
		version = "ipv6"
	}
	var out []policyRoute
	for i, p := range in.PolicyRoutes {
		gw := p.Gateway(version)
		if !p.Routed() || (len(p.Gateways) > 0 && gw == "") || !slices.Contains(p.MarkedFamilies(), version) {
			continue
		}
		out = append(out, policyRoute{table: fwconfig.PolicyRouteTable(i), mark: fwconfig.PolicyRouteMark(i), gateway: gw, dev: p.Interface, fam: fam})
	}
	return out
}

// planPolicyRules removes the agent's rules at the policy routes'
// preferences that aren't wanted and adds the missing ones, of one IP
// version.
func planPolicyRules(ns, fam string, want []policyRoute, have []ipRule) []command {
	key := func(pref int, mark uint64, table string) string { return fmt.Sprintf("%d|%#x|%s", pref, mark, table) }
	wanted := map[string]bool{}
	for _, r := range want {
		wanted[key(r.table, uint64(r.mark), strconv.Itoa(r.table))] = true
	}
	var cmds []command
	present := map[string]bool{}
	for _, r := range have {
		if r.Protocol != RouteProto || !fwconfig.IsPolicyRoutePref(r.Priority) {
			continue
		}
		mark, _ := strconv.ParseUint(r.Fwmark, 0, 32)
		if k := key(r.Priority, mark, r.Table); wanted[k] && !present[k] {
			present[k] = true
			continue
		}
		args := []string{fam, "rule", "del", "pref", strconv.Itoa(r.Priority)}
		if r.Fwmark != "" {
			args = append(args, "fwmark", r.Fwmark)
		}
		cmds = append(cmds, ipCmd(ns, append(args, "lookup", r.Table, "proto", RouteProto)...))
	}
	for _, r := range want {
		table := strconv.Itoa(r.table)
		if k := key(r.table, uint64(r.mark), table); !present[k] {
			present[k] = true
			cmds = append(cmds, ipCmd(ns, fam, "rule", "add", "pref", table, "fwmark", fmt.Sprintf("%#x", r.mark), "lookup", table, "proto", RouteProto))
		}
	}
	return cmds
}

// tableRoute is a route of `ip -j route show table all`, with its table.
type tableRoute struct {
	Dst     string `json:"dst"`
	Gateway string `json:"gateway"`
	Dev     string `json:"dev"`
	Table   string `json:"table"`
}

// planPolicyTables removes the agent's routes in the policy routes' tables
// (have: the agent's routes of all tables) that aren't wanted and adds the
// missing default routes, of one IP version.
func planPolicyTables(ns, fam string, want []policyRoute, have []tableRoute) []command {
	routeArgs := func(verb, table, gw, dev string) []string {
		args := []string{fam, "route", verb, "default"}
		if gw != "" {
			args = append(args, "via", gw)
		}
		if dev != "" {
			args = append(args, "dev", dev)
		}
		return append(args, "table", table, "proto", RouteProto)
	}
	// A route that names no interface takes its gateway's.
	matches := func(w policyRoute, r tableRoute) bool {
		return r.Table == strconv.Itoa(w.table) && r.Dst == "default" && r.Gateway == w.gateway && (w.dev == "" || r.Dev == w.dev)
	}
	var cmds []command
	present := map[int]bool{}
	for _, r := range have {
		t, err := strconv.Atoi(r.Table)
		if err != nil || !fwconfig.IsPolicyRoutePref(t) {
			continue
		}
		keep := false
		for _, w := range want {
			if !present[w.table] && matches(w, r) {
				present[w.table], keep = true, true
				break
			}
		}
		if !keep {
			cmds = append(cmds, ipCmd(ns, routeArgs("del", r.Table, r.Gateway, r.Dev)...))
		}
	}
	for _, w := range want {
		if !present[w.table] {
			cmds = append(cmds, ipCmd(ns, routeArgs("replace", strconv.Itoa(w.table), w.gateway, w.dev)...))
		}
	}
	return cmds
}

// applyPolicyRoutes keeps the policy routes' rules and tables in step with
// the instance's policy routes. A route that can't be added (its gateway
// unreachable now) is a soft error: its packets take the main table.
func (a *Agent) applyPolicyRoutes(ctx context.Context, in *fwconfig.Instance, ns string) error {
	var errs []error
	for _, fam := range []string{"-4", "-6"} {
		want := policyRoutes(in, fam)
		out, err := a.run.Run(ctx, ns, "ip", "-N", "-j", fam, "rule", "show")
		if err != nil {
			return err
		}
		rules, err := parseRules(out)
		if err != nil {
			return err
		}
		if out, err = a.run.Run(ctx, ns, "ip", "-N", "-j", fam, "route", "show", "table", "all", "proto", RouteProto); err != nil {
			return err
		}
		var routes []tableRoute
		if len(out) > 0 {
			if err := json.Unmarshal(out, &routes); err != nil {
				return fmt.Errorf("parse ip -j route output: %w", err)
			}
		}
		// The table first, so a rule never sends packets to a stale route.
		errs = append(errs, a.doEach(ctx, planPolicyTables(ns, fam, want, routes)))
		if err := a.doAll(ctx, planPolicyRules(ns, fam, want, rules)); err != nil {
			return err
		}
	}
	return errors.Join(errs...)
}
