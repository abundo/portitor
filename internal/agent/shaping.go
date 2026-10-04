// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/render"
)

// Traffic shaping (fwconfig.Interface.ShapeEgress/ShapeIngress) with CAKE.
// What an interface sends is shaped by a cake root qdisc on it; what it
// receives is redirected (an ingress qdisc with a matchall filter, mirred)
// to an IFB device (fwconfig.IFBName) with a cake qdisc of its own. The
// agent owns the root and ingress qdiscs of its instances' interfaces: a
// cake or htb root it doesn't want is removed, and so is an ingress qdisc.
//
// In an instance whose rules name shapers (rate limits that shape,
// fwconfig.Instance.Shapers), every
// enabled interface sends through an HTB tree instead (htbTree): a class
// at the interface's ShapeEgress (or unlimited), under it a default class
// and one class per shaper, capped at its rate, which the packets reach by
// their mark (render.ShaperMark, set by the ruleset); fq_codel in each.
//
// planUnshape runs before stale virtual interfaces are removed, so an IFB
// device never goes while an interface still redirects to it (mirred to a
// missing device drops); planShape after the interfaces are configured.

// shapeFilterPref is the priority of the matchall filter that redirects
// to the IFB device.
const shapeFilterPref = "1"

// tcQdisc is the subset of `tc -j qdisc show` the agent reads.
type tcQdisc struct {
	Kind    string `json:"kind"`
	Dev     string `json:"dev"`
	Root    bool   `json:"root"`
	Options struct {
		Bandwidth uint64 `json:"bandwidth"` // bytes/s
		Ingress   bool   `json:"ingress"`
	} `json:"options"`
}

// tcFilter is the subset of `tc -j filter show dev X ingress` the agent
// reads.
type tcFilter struct {
	Pref    int    `json:"pref"`
	Kind    string `json:"kind"`
	Options *struct {
		Actions []struct {
			Kind  string `json:"kind"`
			ToDev string `json:"to_dev"`
		} `json:"actions"`
	} `json:"options"`
}

func parseQdiscs(data []byte) (map[string][]tcQdisc, error) {
	var list []tcQdisc
	if len(data) > 0 {
		if err := json.Unmarshal(data, &list); err != nil {
			return nil, fmt.Errorf("parse tc -j qdisc output: %w", err)
		}
	}
	m := map[string][]tcQdisc{}
	for _, q := range list {
		m[q.Dev] = append(m[q.Dev], q)
	}
	return m, nil
}

// parseRedirect returns the device the ingress matchall filter redirects
// to; "" when there is none.
func parseRedirect(data []byte) (string, error) {
	var list []tcFilter
	if len(data) > 0 {
		if err := json.Unmarshal(data, &list); err != nil {
			return "", fmt.Errorf("parse tc -j filter output: %w", err)
		}
	}
	for _, f := range list {
		if f.Kind != "matchall" || strconv.Itoa(f.Pref) != shapeFilterPref || f.Options == nil {
			continue
		}
		for _, a := range f.Options.Actions {
			if a.Kind == "mirred" {
				return a.ToDev, nil
			}
		}
	}
	return "", nil
}

func tcCmd(ns string, args ...string) command {
	return command{Netns: ns, Name: "tc", Args: args}
}

func findQdisc(qs []tcQdisc, match func(tcQdisc) bool) *tcQdisc {
	for i := range qs {
		if match(qs[i]) {
			return &qs[i]
		}
	}
	return nil
}

func isRoot(q tcQdisc) bool    { return q.Root }
func isIngress(q tcQdisc) bool { return q.Kind == "ingress" }

// shapes reports what an interface wants shaped: sending, receiving.
func shapes(ifc fwconfig.Interface) (egress, ingress bool) {
	return ifc.Enabled && ifc.ShapeEgress > 0, ifc.Enabled && ifc.ShapeIngress > 0
}

// usesHTB reports whether an interface sends through an HTB tree: its
// instance's rules name shapers (shapers is nil when they don't).
func usesHTB(ifc fwconfig.Interface, shapers []fwconfig.RateLimit) bool {
	return shapers != nil && ifc.Enabled && ifc.Kind != fwconfig.KindLoopback
}

func ours(q *tcQdisc) bool { return q != nil && (q.Kind == "cake" || q.Kind == "htb") }

// planUnshape removes the shaping the interfaces no longer want: a cake
// or htb root qdisc, and the ingress qdisc (with its redirect).
func planUnshape(ns string, want []fwconfig.Interface, shapers []fwconfig.RateLimit, have map[string]ipLink, qdiscs map[string][]tcQdisc) []command {
	var cmds []command
	for _, ifc := range want {
		if _, ok := have[ifc.Name]; !ok {
			continue
		}
		egress, ingress := shapes(ifc)
		egress = egress || usesHTB(ifc, shapers)
		qs := qdiscs[ifc.Name]
		if q := findQdisc(qs, isRoot); !egress && ours(q) {
			cmds = append(cmds, tcCmd(ns, "qdisc", "del", "dev", ifc.Name, "root"))
		}
		if !ingress && findQdisc(qs, isIngress) != nil {
			cmds = append(cmds, tcCmd(ns, "qdisc", "del", "dev", ifc.Name, "ingress"))
		}
	}
	return cmds
}

// cakeCmd sets dev's root qdisc to cake at mbit, unless it is that.
func cakeCmd(ns, dev string, mbit int, ingress bool, qs []tcQdisc) []command {
	q := findQdisc(qs, isRoot)
	if q != nil && q.Kind == "cake" && q.Options.Bandwidth == uint64(mbit)*125000 && q.Options.Ingress == ingress {
		return nil
	}
	args := []string{"qdisc", "replace", "dev", dev, "root", "cake", "bandwidth", strconv.Itoa(mbit) + "mbit"}
	if ingress {
		args = append(args, "ingress")
	}
	return []command{tcCmd(ns, args...)}
}

// htbTree describes the HTB tree of an interface: what it is built from.
func htbTree(mbit int, shapers []fwconfig.RateLimit) string {
	t := strconv.Itoa(mbit)
	for _, s := range shapers {
		t += " " + strconv.FormatInt(s.Bits(), 10)
	}
	return t
}

// htbCmds builds dev's HTB tree, replacing a cake or htb root of ours.
func htbCmds(ns, dev string, mbit int, shapers []fwconfig.RateLimit, qs []tcQdisc) []command {
	var cmds []command
	if ours(findQdisc(qs, isRoot)) {
		cmds = append(cmds, tcCmd(ns, "qdisc", "del", "dev", dev, "root"))
	}
	total := "100gbit" // not shaped: only the shapers' classes are
	if mbit > 0 {
		total = strconv.Itoa(mbit) + "mbit"
	}
	leaf := func(class string) command {
		return tcCmd(ns, "qdisc", "add", "dev", dev, "parent", class, "fq_codel")
	}
	cmds = append(cmds,
		tcCmd(ns, "qdisc", "replace", "dev", dev, "root", "handle", "1:", "htb", "default", "ffff"),
		tcCmd(ns, "class", "add", "dev", dev, "parent", "1:", "classid", "1:1", "htb", "rate", total, "ceil", total, "quantum", "1514"),
		tcCmd(ns, "class", "add", "dev", dev, "parent", "1:1", "classid", "1:ffff", "htb", "rate", total, "ceil", total, "quantum", "1514"),
		leaf("1:ffff"))
	for i, s := range shapers {
		rate := s.Bits()
		if mbit > 0 && int64(mbit)*1000000 < rate {
			rate = int64(mbit) * 1000000
		}
		class, r := render.ShaperClass(i), strconv.FormatInt(rate, 10)+"bit"
		cmds = append(cmds,
			tcCmd(ns, "class", "add", "dev", dev, "parent", "1:1", "classid", class, "htb", "rate", r, "ceil", r, "quantum", "1514"),
			leaf(class),
			tcCmd(ns, "filter", "add", "dev", dev, "parent", "1:", "protocol", "all", "prio", "1",
				"handle", fmt.Sprintf("%#x", render.ShaperMark(i)), "fw", "classid", class))
	}
	return cmds
}

// planShape sets up the shaping the interfaces want. redirect holds, per
// interface with an ingress qdisc, the device its filter redirects to;
// built, per device, the HTB tree set up on it before (htbTree), which it
// updates.
func planShape(ns string, want []fwconfig.Interface, shapers []fwconfig.RateLimit, have map[string]ipLink, qdiscs map[string][]tcQdisc, redirect, built map[string]string) []command {
	var cmds []command
	for _, ifc := range want {
		if _, ok := have[ifc.Name]; !ok {
			continue
		}
		egress, ingress := shapes(ifc)
		qs := qdiscs[ifc.Name]
		switch {
		case usesHTB(ifc, shapers):
			tree := htbTree(ifc.ShapeEgress, shapers)
			if q := findQdisc(qs, isRoot); q == nil || q.Kind != "htb" || built[ifc.Name] != tree {
				cmds = append(cmds, htbCmds(ns, ifc.Name, ifc.ShapeEgress, shapers, qs)...)
				built[ifc.Name] = tree
			}
		case egress:
			cmds = append(cmds, cakeCmd(ns, ifc.Name, ifc.ShapeEgress, false, qs)...)
			delete(built, ifc.Name)
		default:
			delete(built, ifc.Name)
		}
		if !ingress {
			continue
		}
		ifb := fwconfig.IFBName(ifc.Name)
		l, ok := have[ifb]
		if !ok {
			cmds = append(cmds, ipCmd(ns, "link", "add", ifb, "type", "ifb"))
		}
		if !ok || !l.up() {
			cmds = append(cmds, ipCmd(ns, "link", "set", "dev", ifb, "up"))
		}
		cmds = append(cmds, cakeCmd(ns, ifb, ifc.ShapeIngress, true, qdiscs[ifb])...)
		if findQdisc(qdiscs[ifc.Name], isIngress) == nil {
			cmds = append(cmds, tcCmd(ns, "qdisc", "add", "dev", ifc.Name, "handle", "ffff:", "ingress"))
		} else if to := redirect[ifc.Name]; to == ifb {
			continue
		} else if to != "" {
			cmds = append(cmds, tcCmd(ns, "filter", "del", "dev", ifc.Name, "parent", "ffff:", "pref", shapeFilterPref))
		}
		cmds = append(cmds, tcCmd(ns, "filter", "add", "dev", ifc.Name, "parent", "ffff:", "pref", shapeFilterPref,
			"handle", "1", "matchall", "action", "mirred", "egress", "redirect", "dev", ifb))
	}
	return cmds
}

// qdiscs reads the namespace's qdiscs, by device.
func (a *Agent) qdiscs(ctx context.Context, ns string) (map[string][]tcQdisc, error) {
	out, err := a.run.Run(ctx, ns, "tc", "-j", "qdisc", "show")
	if err != nil {
		return nil, err
	}
	return parseQdiscs(out)
}

// redirects reads where the ingress filters of the interfaces that have
// an ingress qdisc and want receiving shaped redirect to.
func (a *Agent) redirects(ctx context.Context, ns string, want []fwconfig.Interface, qdiscs map[string][]tcQdisc) (map[string]string, error) {
	m := map[string]string{}
	for _, ifc := range want {
		if _, ingress := shapes(ifc); !ingress || findQdisc(qdiscs[ifc.Name], isIngress) == nil {
			continue
		}
		out, err := a.run.Run(ctx, ns, "tc", "-j", "filter", "show", "dev", ifc.Name, "ingress")
		if err != nil {
			return nil, err
		}
		if m[ifc.Name], err = parseRedirect(out); err != nil {
			return nil, err
		}
	}
	return m, nil
}
