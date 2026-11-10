// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strconv"

	"github.com/abundo/portitor/internal/fwconfig"
)

// The host's own traffic on an HA pair. The main table points at traffic
// interfaces, which a closed gate cuts off, so what comes from the
// management address always uses table fwconfig.HAMgmtTable, and on a
// closed host everything the host itself sends does too, but for the
// routes in main more specific than a default route (the HA link's).
// NTP, apt, ACME and syslog then work on the standby. With the peer as the
// gateway (Interface.HAGatewayPeer) the table is the closed host's alone:
// the open one forwards for it. Forwarded traffic is
// not touched: the gate drops it. The rules are proto 99, the agent's.
const (
	haSourcePref   = 1000 // from <management address> lookup the table
	haMainPref     = 1001 // iif lo lookup main suppress_prefixlength 0
	haCatchAllPref = 1002 // iif lo lookup the table
)

// haMgmt is the management interface, of one IP version: the gateway's.
type haMgmt struct {
	dev     string
	gateway string
	addrs   []netip.Prefix
	// peer: the gateway is the peer's management address, used only while
	// closed: the open host's own traffic leaves by its traffic interfaces,
	// and what it sends from its management address too.
	peer bool
}

// haMgmtOf is the document's management routing, nil outside a pair.
func haMgmtOf(doc *fwconfig.Document) *haMgmt {
	if doc.HA == nil {
		return nil
	}
	var ifc *fwconfig.Interface
	for i := range doc.Instances {
		if doc.Instances[i].Default {
			ifc = doc.Instances[i].HAInterface(fwconfig.HARoleManagement)
		}
	}
	if ifc == nil {
		return nil
	}
	gw, err := netip.ParseAddr(ifc.HAGateway)
	if err != nil {
		return nil
	}
	m := &haMgmt{dev: ifc.Name, gateway: ifc.HAGateway, peer: ifc.HAGatewayPeer}
	for _, s := range ifc.Addresses {
		if p, err := fwconfig.ParseInterfaceAddress(s); err == nil && p.Addr().Is4() == gw.Is4() {
			m.addrs = append(m.addrs, p)
		}
	}
	return m
}

// haOwnLinks are the interfaces with an HA role.
func haOwnLinks(doc *fwconfig.Document) map[string]bool {
	own := map[string]bool{}
	for i := range doc.Instances {
		for _, ifc := range doc.Instances[i].Interfaces {
			if ifc.HARole != "" {
				own[ifc.Name] = true
			}
		}
	}
	return own
}

func (m *haMgmt) family() string {
	if len(m.addrs) > 0 && m.addrs[0].Addr().Is6() {
		return "-6"
	}
	return "-4"
}

// planHARules makes the rules at the prefs above what m wants: closed
// adds the rules of a closed host. have is the host's rules of one IP
// version; fam says which one, and m is nil or of another version when it
// wants none.
func planHARules(fam string, m *haMgmt, closed bool, have []ipRule) []command {
	table := strconv.Itoa(fwconfig.HAMgmtTable)
	type rule struct {
		pref int
		src  string
		args []string
	}
	var want []rule
	if m != nil && m.family() == fam {
		for _, a := range m.addrs {
			if m.peer && !closed {
				break
			}
			want = append(want, rule{haSourcePref, a.Addr().String(), []string{"from", a.Addr().String(), "lookup", table}})
		}
		if closed {
			want = append(want, rule{haMainPref, "", []string{"iif", "lo", "lookup", "main", "suppress_prefixlength", "0"}},
				rule{haCatchAllPref, "", []string{"iif", "lo", "lookup", table}})
		}
	}
	key := func(pref int, src string) string { return strconv.Itoa(pref) + "|" + src }
	wanted := map[string]bool{}
	for _, r := range want {
		wanted[key(r.pref, r.src)] = true
	}
	var cmds []command
	present := map[string]bool{}
	for _, r := range have {
		if r.Protocol != RouteProto || r.Priority < haSourcePref || r.Priority > haCatchAllPref {
			continue
		}
		src := r.Src
		if src == "all" {
			src = ""
		}
		if k := key(r.Priority, src); wanted[k] && !present[k] {
			present[k] = true
			continue
		}
		args := []string{fam, "rule", "del", "pref", strconv.Itoa(r.Priority)}
		if src != "" {
			args = append(args, "from", src)
		}
		cmds = append(cmds, ipCmd("", args...))
	}
	for _, r := range want {
		if !present[key(r.pref, r.src)] {
			cmds = append(cmds, ipCmd("", append(append([]string{fam, "rule", "add", "pref", strconv.Itoa(r.pref)}, r.args...), "proto", RouteProto)...))
		}
	}
	return cmds
}

// planHARoutes makes table fwconfig.HAMgmtTable what m wants; have are the
// agent's routes of all tables, of one IP version.
func planHARoutes(fam string, m *haMgmt, have []tableRoute) []command {
	table := strconv.Itoa(fwconfig.HAMgmtTable)
	type route struct{ dst, gateway, src string }
	var want []route
	if m != nil && m.family() == fam && len(m.addrs) > 0 {
		for _, a := range m.addrs {
			want = append(want, route{a.Masked().String(), "", a.Addr().String()})
		}
		want = append(want, route{"default", m.gateway, m.addrs[0].Addr().String()})
	}
	var cmds []command
	present := map[string]bool{}
	for _, r := range have {
		if r.Table != table {
			continue
		}
		if slices.ContainsFunc(want, func(w route) bool { return w.dst == r.Dst && w.gateway == r.Gateway }) && m != nil && r.Dev == m.dev {
			present[r.Dst] = true
			continue
		}
		cmds = append(cmds, ipCmd("", fam, "route", "del", r.Dst, "table", table, "proto", RouteProto))
	}
	for _, w := range want {
		if present[w.dst] {
			continue
		}
		args := []string{fam, "route", "add", w.dst}
		if w.gateway != "" {
			args = append(args, "via", w.gateway)
		}
		cmds = append(cmds, ipCmd("", append(args, "dev", m.dev, "src", w.src, "table", table, "proto", RouteProto)...))
	}
	return cmds
}

// ownLinks are the host's HA link and management interface, which the
// takeover doesn't announce.
func (h *haManager) ownLinks() map[string]bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.own
}

// setMgmt follows the applied document, and applyMgmt the host's state.
func (h *haManager) setMgmt(m *haMgmt, own map[string]bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.mgmt, h.own = m, own
}

// applyMgmt keeps the management routing, in the root namespace.
func (h *haManager) applyMgmt(ctx context.Context, run Runner) error {
	h.rules.Lock()
	defer h.rules.Unlock()
	h.mu.Lock()
	m, closed := h.mgmt, h.cfg != nil && !h.active
	h.mu.Unlock()
	for _, fam := range []string{"-4", "-6"} {
		out, err := run.Run(ctx, "", "ip", "-j", fam, "route", "show", "table", "all", "proto", RouteProto)
		if err != nil {
			return err
		}
		var routes []tableRoute
		if len(out) > 0 {
			if err := json.Unmarshal(out, &routes); err != nil {
				return fmt.Errorf("parse ip -j route output: %w", err)
			}
		}
		for _, c := range planHARoutes(fam, m, routes) {
			if _, err := run.RunInput(ctx, c.Netns, c.Stdin, c.Name, c.Args...); err != nil {
				return err
			}
		}
		out, err = run.Run(ctx, "", "ip", "-N", "-j", fam, "rule", "show")
		if err != nil {
			return err
		}
		rules, err := parseRules(out)
		if err != nil {
			return err
		}
		for _, c := range planHARules(fam, m, closed, rules) {
			if _, err := run.RunInput(ctx, c.Netns, c.Stdin, c.Name, c.Args...); err != nil {
				return err
			}
		}
	}
	return nil
}
