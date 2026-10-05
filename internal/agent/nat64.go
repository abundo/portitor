// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/abundo/portitor/internal/fwconfig"
)

// NAT64 runs in Jool, one instance (fwconfig.JoolInstance) in each
// namespace that translates. Jool doesn't say how its instance was made,
// so the agent keeps the NAT64 it applied in <state>/nat64.json and makes
// the instance again when that changes, or when it isn't running (after a
// reboot, or a namespace made again; the agent applies at start).
//
// Each interface with 464XLAT has a loop device (fwconfig.NAT64Devices): a
// dummy device whose tc egress filter redirects what it sends to what it
// receives, a routing table with the default route to it, and a rule that
// looks the table up for what Jool sends from the device's pool4 address
// (from <address> iif lo); the route to the address is the device, in
// main. The rules are the agent's by protocol (RouteProto).

func (a *Agent) nat64File(in *fwconfig.Instance) string {
	return filepath.Join(a.cfg.Paths.InstanceState(in.Name), "nat64.json")
}

// applyNAT64 makes the instance's Jool instance and loop devices match
// in.NAT64. Its ruleset, with the NAT64 chain, is loaded before, and stale
// loop devices are removed with the other stale devices.
func (a *Agent) applyNAT64(ctx context.Context, in *fwconfig.Instance, ns string) error {
	devs := in.NAT64Devices()
	links, err := a.links(ctx, ns)
	if err != nil {
		return err
	}
	redirect := map[string]string{}
	for _, d := range devs {
		if l, ok := links[d.Name]; ok && l.kind() == "dummy" {
			out, err := a.run.Run(ctx, ns, "tc", "-j", "filter", "show", "dev", d.Name, "egress")
			if err != nil {
				return err
			}
			if redirect[d.Name], err = parseRedirect(out); err != nil {
				return err
			}
		}
	}
	if err := a.doAll(ctx, planNAT64Devices(ns, devs, links, redirect)); err != nil {
		return err
	}
	out, err := a.run.Run(ctx, ns, "ip", "-N", "-j", "-4", "rule", "show")
	if err != nil {
		return err
	}
	rules, err := parseRules(out)
	if err != nil {
		return err
	}
	if out, err = a.run.Run(ctx, ns, "ip", "-j", "-4", "route", "show", "table", "all", "proto", RouteProto); err != nil {
		return err
	}
	var routes []ipTableRoute
	if len(out) > 0 {
		if err := json.Unmarshal(out, &routes); err != nil {
			return fmt.Errorf("parse ip -j route output: %w", err)
		}
	}
	if err := a.doAll(ctx, planNAT64Rules(ns, devs, rules, routes)); err != nil {
		return err
	}

	var have *fwconfig.NAT64
	if readJSON(a.nat64File(in), &have) != nil {
		have = nil // none applied, or unreadable: made again
	}
	// An error is no Jool instance: the module isn't loaded, or jool isn't
	// installed, which matters only when one is wanted (checkPrograms).
	out, err = a.run.Run(ctx, ns, "jool", "-i", fwconfig.JoolInstance, "instance", "status")
	running := err == nil && strings.Contains(string(out), "Running")
	var pool4 []string
	if running {
		for _, proto := range nat64Protos {
			out, err := a.run.Run(ctx, ns, "jool", "-i", fwconfig.JoolInstance, "pool4", "display", proto, "--csv", "--no-headers")
			if err != nil {
				return err
			}
			pool4 = append(pool4, parsePool4(out)...)
		}
	}
	if err := a.doAll(ctx, planNAT64(ns, in.NAT64, have, running, pool4)); err != nil {
		return err
	}
	if in.NAT64 == nil {
		if err := os.Remove(a.nat64File(in)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	return writeJSON(a.nat64File(in), in.NAT64, 0o644)
}

var nat64Protos = []string{"--tcp", "--udp", "--icmp"}

// pool4Entry is a pool4 entry as parsePool4 lists it.
func pool4Entry(proto string, mark int, addr string) string {
	return fmt.Sprintf("%s %d %s 1-65535", strings.TrimPrefix(proto, "--"), mark, addr)
}

// parsePool4 reads `jool pool4 display --csv --no-headers`: mark,
// protocol, address, min port, max port, ...
func parsePool4(data []byte) []string {
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		f := strings.Split(line, ",")
		if len(f) < 5 {
			continue
		}
		mark, err := strconv.Atoi(f[0])
		if err != nil {
			continue
		}
		e := pool4Entry(strings.ToLower(f[1]), mark, f[2])
		out = append(out, strings.TrimSuffix(e, "1-65535")+f[3]+"-"+f[4])
	}
	return out
}

// planNAT64 removes the Jool instance when NAT64 is off or changed, and
// makes it when NAT64 is on and it isn't running as wanted. have is the
// NAT64 last applied, nil when unknown; pool4 is the running instance's
// pool4 (parsePool4), which must be the loop devices' (an agent from before
// them left it empty).
func planNAT64(ns string, want, have *fwconfig.NAT64, running bool, pool4 []string) []command {
	jool := func(args ...string) command { return command{Netns: ns, Name: "jool", Args: args} }
	devs := (&fwconfig.Instance{NAT64: want}).NAT64Devices()
	var wantPool []string
	for _, d := range devs {
		for _, proto := range nat64Protos {
			wantPool = append(wantPool, pool4Entry(proto, d.Mark, d.Address))
		}
	}
	slices.Sort(wantPool)
	pool4 = slices.Sorted(slices.Values(pool4))
	same := running && want.Equal(have) && slices.Equal(pool4, wantPool)
	var cmds []command
	if running && !same {
		cmds = append(cmds, jool("instance", "remove", fwconfig.JoolInstance))
	}
	if want == nil || same {
		return cmds
	}
	cmds = append(cmds,
		command{Name: "modprobe", Args: []string{"jool"}},
		jool("instance", "add", fwconfig.JoolInstance, "--netfilter", "--pool6", want.Prefix),
	)
	// Each loop device's address is the NAT64's alone: every port (ICMP
	// id), which Jool wants given, for the packets with its mark.
	for _, d := range devs {
		for _, proto := range nat64Protos {
			cmds = append(cmds, jool("-i", fwconfig.JoolInstance, "pool4", "add", proto, "--mark", strconv.Itoa(d.Mark), d.Address, "1-65535"))
		}
	}
	return cmds
}

// planNAT64Devices creates the loop devices that are missing or of
// another kind, redirects what each sends to what it receives (redirect
// is where each one's egress filter redirects to now), turns IPv6 off on
// the new ones and brings them up.
func planNAT64Devices(ns string, devs []fwconfig.NAT64Device, have map[string]ipLink, redirect map[string]string) []command {
	var cmds []command
	for _, d := range devs {
		l, ok := have[d.Name]
		if ok && l.kind() != "dummy" {
			cmds = append(cmds, ipCmd(ns, "link", "del", "dev", d.Name))
			ok = false
		}
		if !ok {
			cmds = append(cmds,
				ipCmd(ns, "link", "add", "name", d.Name, "type", "dummy"),
				command{Netns: ns, Name: "sysctl", Args: []string{"-q", "-w", "net.ipv6.conf." + d.Name + ".disable_ipv6=1"}},
			)
			l = ipLink{}
		}
		if redirect[d.Name] != d.Name {
			if !ok || redirect[d.Name] == "" {
				cmds = append(cmds, tcCmd(ns, "qdisc", "replace", "dev", d.Name, "clsact"))
			}
			cmds = append(cmds, tcCmd(ns, "filter", "replace", "dev", d.Name, "egress", "pref", shapeFilterPref,
				"matchall", "action", "mirred", "ingress", "redirect", "dev", d.Name))
		}
		if !l.up() {
			cmds = append(cmds, ipCmd(ns, "link", "set", "dev", d.Name, "up"))
		}
	}
	return cmds
}

// ipRule is the subset of `ip -N -j rule show` the agent reads.
type ipRule struct {
	Priority int    `json:"priority"`
	Src      string `json:"src"`
	Iif      string `json:"iif"`
	Table    string `json:"table"`
	Protocol string `json:"protocol"`
}

func parseRules(data []byte) ([]ipRule, error) {
	var rules []ipRule
	if len(data) > 0 {
		if err := json.Unmarshal(data, &rules); err != nil {
			return nil, fmt.Errorf("parse ip -j rule output: %w", err)
		}
	}
	return rules, nil
}

// ipTableRoute is a route of `ip -j route show table all`.
type ipTableRoute struct {
	Dst   string `json:"dst"`
	Dev   string `json:"dev"`
	Table string `json:"table"`
}

// planNAT64Rules removes the agent's rules that aren't the loop devices'
// and adds the missing ones, and points each device's table at it. A
// stale table's route went with its device.
func planNAT64Rules(ns string, devs []fwconfig.NAT64Device, have []ipRule, routes []ipTableRoute) []command {
	key := func(pref int, src, iif, table string) string {
		return fmt.Sprintf("%d|%s|%s|%s", pref, src, iif, table)
	}
	want := map[string]bool{}
	for _, d := range devs {
		want[key(d.Table, d.Address, "lo", strconv.Itoa(d.Table))] = true
	}
	var cmds []command
	haveKeys := map[string]bool{}
	for _, r := range have {
		if r.Protocol != RouteProto {
			continue
		}
		k := key(r.Priority, r.Src, r.Iif, r.Table)
		if want[k] && !haveKeys[k] {
			haveKeys[k] = true
			continue
		}
		args := []string{"-4", "rule", "del", "pref", strconv.Itoa(r.Priority)}
		if r.Src != "" && r.Src != "all" {
			args = append(args, "from", r.Src)
		}
		if r.Iif != "" {
			args = append(args, "iif", r.Iif)
		}
		args = append(args, "lookup", r.Table, "proto", RouteProto)
		cmds = append(cmds, ipCmd(ns, args...))
	}
	for _, d := range devs {
		table := strconv.Itoa(d.Table)
		if !slices.ContainsFunc(routes, func(r ipTableRoute) bool { return r.Table == table && r.Dst == "default" && r.Dev == d.Name }) {
			cmds = append(cmds, ipCmd(ns, "-4", "route", "replace", "default", "dev", d.Name, "table", table, "proto", RouteProto))
		}
		if !haveKeys[key(d.Table, d.Address, "lo", table)] {
			cmds = append(cmds, ipCmd(ns, "-4", "rule", "add", "pref", table, "from", d.Address, "iif", "lo", "lookup", table, "proto", RouteProto))
		}
	}
	return cmds
}

// nat64Routes are the routes in main of the loop devices' addresses.
func nat64Routes(in *fwconfig.Instance) []fwconfig.Route {
	var out []fwconfig.Route
	for _, d := range in.NAT64Devices() {
		out = append(out, fwconfig.Route{Destination: d.Address + "/32", Interface: d.Name})
	}
	return out
}
