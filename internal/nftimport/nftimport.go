// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package nftimport turns an nftables ruleset, as `nft -j list ruleset`
// lists it, into a virtual firewall's rules, NAT rules, hosts/prefixes
// and services. It maps what Portitor can express and reports the rest,
// rule by rule, with the reason. It is pure: what already exists comes in
// through Options.
package nftimport

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/netobj"
	"github.com/abundo/portitor/models"
)

// Options is what the import maps onto.
type Options struct {
	// Objects are the existing hosts/prefixes, by name.
	Objects map[string][]string
	// Services are the existing custom services, by name.
	Services map[string]models.Service
	// Interfaces are the interface and interface zone names of the
	// virtual firewall.
	Interfaces map[string]bool
	// Rename maps an interface name of the file to one of Interfaces;
	// "" (or a name not in Interfaces) leaves the rules that use it out.
	Rename map[string]string
}

// Result is what the import would create.
type Result struct {
	Rules []models.Rule    `json:"rules"`
	NAT   []models.NatRule `json:"nat"`
	// Objects and Services are the new ones the rules refer to.
	Objects  []models.AddressObject `json:"objects"`
	Services []models.Service       `json:"services"`
	Skipped  []Skipped              `json:"skipped"`
	// Interfaces are the file's interface names that are not the virtual
	// firewall's, sorted: Options.Rename maps them.
	Interfaces []string `json:"interfaces"`
}

// Skipped is a rule (or a whole chain) the import leaves out.
type Skipped struct {
	Where  string `json:"where"` // "inet filter input"
	Text   string `json:"text"`
	Reason string `json:"reason"`
	// Builtin marks what Portitor does by itself (established/related,
	// invalid, loopback).
	Builtin bool `json:"builtin,omitempty"`
}

type nftChain struct {
	Family, Table, Name string
	Type, Hook, Policy  string
	Prio                int
	order               int
	rules               []nftRule
}

type nftRule struct {
	Family, Table, Chain string
	Handle               int
	Comment              string
	Expr                 []map[string]json.RawMessage
	// via is the chains that jumped to reach the rule, outermost first
	// ("input").
	via []string
}

type nftSet struct {
	Family, Table, Name string
	Type                any
	Flags               []string
	Elem                []json.RawMessage
}

// Import maps the JSON of `nft -j list ruleset`; text is `nft -a list
// ruleset`, which gives the skipped rules their text.
func Import(js []byte, text string, opt Options) (*Result, error) {
	var top struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(js, &top); err != nil {
		return nil, fmt.Errorf("nft's JSON: %w", err)
	}
	im := &importer{
		opt:      opt,
		texts:    ruleTexts(text),
		sets:     map[string]*nftSet{},
		reached:  map[string]bool{},
		objects:  map[string]string{},
		services: map[string]bool{},
		foreign:  map[string]bool{},
		res:      &Result{Rules: []models.Rule{}, NAT: []models.NatRule{}, Objects: []models.AddressObject{}, Services: []models.Service{}, Skipped: []Skipped{}},
	}
	var chains []*nftChain
	byName := map[string]*nftChain{}
	for _, o := range top.Nftables {
		switch {
		case o["chain"] != nil:
			var c nftChain
			if err := json.Unmarshal(o["chain"], &c); err != nil {
				return nil, err
			}
			c.order = len(chains)
			chains = append(chains, &c)
			byName[c.Family+" "+c.Table+" "+c.Name] = &c
		case o["set"] != nil:
			var s nftSet
			if err := json.Unmarshal(o["set"], &s); err != nil {
				return nil, err
			}
			im.sets[s.Family+" "+s.Table+" "+s.Name] = &s
		case o["rule"] != nil:
			var r nftRule
			if err := json.Unmarshal(o["rule"], &r); err != nil {
				return nil, err
			}
			if c := byName[r.Family+" "+r.Table+" "+r.Chain]; c != nil {
				c.rules = append(c.rules, r)
			}
		}
	}
	im.chains = byName
	// Chains on the same hook run by priority, then as listed.
	sort.SliceStable(chains, func(i, j int) bool { return chains[i].Prio < chains[j].Prio })
	for _, c := range chains {
		if c.Hook != "" {
			im.chain(c)
		}
	}
	for _, c := range chains {
		if c.Hook == "" && !im.reached[c.Family+" "+c.Table+" "+c.Name] {
			for _, r := range c.rules {
				im.skip(r, "chain "+c.Name+" is not reached by a jump from an imported chain", false)
			}
		}
	}
	for n := range im.foreign {
		im.res.Interfaces = append(im.res.Interfaces, n)
	}
	sort.Strings(im.res.Interfaces)
	if im.res.Interfaces == nil {
		im.res.Interfaces = []string{}
	}
	return im.res, nil
}

type importer struct {
	opt   Options
	texts map[string]string
	sets  map[string]*nftSet
	// chains are all chains by "family table name"; reached holds the
	// regular ones a jump reached.
	chains  map[string]*nftChain
	reached map[string]bool
	// objects maps a set ("family table name") to its host/prefix name.
	objects map[string]string
	// services holds the names of the new services.
	services map[string]bool
	foreign  map[string]bool
	res      *Result
}

func (im *importer) chain(c *nftChain) {
	where := c.Family + " " + c.Table + " " + c.Name
	skipAll := func(reason string) {
		for _, r := range c.rules {
			im.skip(r, reason, false)
		}
	}
	switch {
	case c.Family != "inet" && c.Family != "ip" && c.Family != "ip6":
		skipAll("tables of family " + c.Family + " are not imported")
		return
	case c.Type == "filter" && (c.Hook == fwconfig.ChainInput || c.Hook == fwconfig.ChainForward || c.Hook == fwconfig.ChainOutput):
		im.walk(c, c.rules, nil, nil, func(r nftRule) { im.filterRule(c, r) }, func(title string) {
			// A group with nothing in it gives way to the next one.
			if n := len(im.res.Rules); n > 0 && im.res.Rules[n-1].Kind == models.RuleKindGroup && im.res.Rules[n-1].Chain == c.Hook {
				im.res.Rules = im.res.Rules[:n-1]
			}
			im.res.Rules = append(im.res.Rules, models.Rule{
				Chain: c.Hook, Kind: models.RuleKindGroup, Description: title, Enabled: true,
				InInterfaces: models.StringList{}, OutInterfaces: models.StringList{},
				SrcAddrs: models.StringList{}, DstAddrs: models.StringList{}, Services: models.StringList{},
			})
		})
		if c.Policy != "drop" {
			// Portitor's chains drop what no rule accepts.
			im.res.Rules = append(im.res.Rules, models.Rule{
				Chain: c.Hook, Action: fwconfig.ActionAccept, Enabled: true,
				Family:       familyOf(c.Family),
				InInterfaces: models.StringList{}, OutInterfaces: models.StringList{},
				SrcAddrs: models.StringList{}, DstAddrs: models.StringList{}, Services: models.StringList{},
				Description: "Policy accept of " + where,
			})
		}
	case c.Type == "nat" && (c.Hook == "prerouting" || c.Hook == "postrouting"):
		im.walk(c, c.rules, nil, nil, func(r nftRule) { im.natRule(c, r) }, nil)
	default:
		skipAll("chains of type " + c.Type + " on hook " + c.Hook + " are not imported")
	}
}

func (im *importer) skip(r nftRule, reason string, builtin bool) {
	text := im.texts[r.Family+" "+r.Table+" "+r.Chain+" "+strconv.Itoa(r.Handle)]
	where := r.Family + " " + r.Table + " " + r.Chain
	if len(r.via) > 0 {
		where += " (from " + strings.Join(r.via, ", ") + ")"
	}
	im.res.Skipped = append(im.res.Skipped, Skipped{Where: where, Text: text, Reason: reason, Builtin: builtin})
}

// maxJumpDepth bounds nested jumps (nft allows 16).
const maxJumpDepth = 16

// walk passes a chain's rules to emit, following jumps: the rules of a
// regular chain a rule jumps to take its place, each with the jumping
// rule's matches (prefix) before its own, so they match what reached them.
// A goto doesn't come back, so a rule with its matches and the base
// chain's policy follows. An unconditional return ends the chain; a
// conditional one can't be flattened, so the rest of the chain is left out.
// With group (filter chains), each jumped-to chain's rules go in a group
// of their own, and a group named after the calling chain holds what
// follows the jump.
func (im *importer) walk(base *nftChain, rules []nftRule, prefix []map[string]json.RawMessage, via []string, emit func(nftRule), group func(string)) {
	for i, r := range rules {
		r.via = via
		last := ""
		var lastVal json.RawMessage
		if n := len(r.Expr); n > 0 {
			for k, v := range r.Expr[n-1] {
				last, lastVal = k, v
			}
		}
		own := r.Expr
		if last == "jump" || last == "goto" || last == "return" {
			own = r.Expr[:len(r.Expr)-1]
		}
		matches := append(slices.Clone(prefix), own...)
		switch last {
		case "return":
			if len(via) == 0 {
				im.skip(r, "return in a base chain is not supported", false)
				continue
			}
			if len(own) == 0 {
				return // what follows is never reached
			}
			for _, rest := range rules[i:] {
				rest.via = via
				im.skip(rest, "a return with matches can't be flattened; the rest of the chain is left out", false)
			}
			return
		case "jump", "goto":
			var t struct{ Target string }
			_ = json.Unmarshal(lastVal, &t)
			key := r.Family + " " + r.Table + " " + t.Target
			target := im.chains[key]
			switch {
			case target == nil:
				im.skip(r, "chain "+t.Target+" is not in the file", false)
				continue
			case target.Hook != "":
				im.skip(r, last+" to base chain "+t.Target+" is not supported", false)
				continue
			case t.Target == r.Chain || slices.Contains(via, t.Target) || len(via) >= maxJumpDepth:
				im.skip(r, last+" to chain "+t.Target+" loops", false)
				continue
			case last == "goto" && base.Type == "nat":
				im.skip(r, "goto in nat chains is not supported", false)
				continue
			}
			im.reached[key] = true
			caller := r.Chain
			if group != nil {
				title := "Chain " + t.Target + " (" + last + " from " + caller
				if text := im.texts[r.Family+" "+r.Table+" "+r.Chain+" "+strconv.Itoa(r.Handle)]; text != "" {
					title += ": " + text
				}
				group(title + ")")
			}
			im.walk(base, target.rules, matches, append(slices.Clone(via), r.Chain), emit, group)
			if last == "goto" {
				policy := fwconfig.ActionAccept
				if base.Policy == "drop" {
					policy = fwconfig.ActionDrop
				}
				g := r
				g.Expr = append(slices.Clone(matches), map[string]json.RawMessage{policy: json.RawMessage("null")})
				g.Comment = "After goto " + t.Target + ": the policy of " + base.Name
				emit(g)
			}
			// What follows (in the calling chain, or the base chain's
			// policy row) leaves the jump's group.
			if group != nil && (i < len(rules)-1 || len(via) == 0 && base.Policy != "drop") {
				group("Chain " + caller)
			}
		default:
			r.Expr = matches
			emit(r)
		}
	}
}

// match is a rule's matches and statements, gathered.
type match struct {
	in, out   []string
	family    string
	src, dst  []string
	protos    []string // l4 protocol names or numbers
	portProto string   // tcp, udp, sctp or th (protos then say which)
	ports     [][2]int
	icmpProto string // icmp or icmpv6
	icmpTypes []string
	ctState   []string
	verdict   string
	log       bool
	nat       string // dnat, snat, masquerade
	natAddr   string
	natPort   int
	loopback  bool
}

type unsupported string

func (im *importer) gather(c *nftChain, r nftRule) (m *match, why string, builtin bool) {
	m = &match{family: familyOf(c.Family)}
	defer func() {
		if p := recover(); p != nil {
			u, ok := p.(unsupported)
			if !ok {
				panic(p)
			}
			m, why = nil, string(u)
		}
	}()
	for _, e := range r.Expr {
		im.expr(r, m, e)
	}
	if len(m.ctState) > 0 {
		st := slices.Sorted(slices.Values(m.ctState))
		switch {
		case slices.Equal(st, []string{"established", "related"}) && m.verdict == fwconfig.ActionAccept && m.onlyCt():
			return nil, "Portitor accepts established and related connections first", true
		case slices.Equal(st, []string{"invalid"}) && m.verdict == fwconfig.ActionDrop && m.onlyCt():
			return nil, "Portitor drops invalid packets first", true
		case !slices.Equal(st, []string{"new"}):
			return nil, "ct state " + strings.Join(st, ",") + " is not supported", false
		}
		// ct state new: what follows established/related anyway.
	}
	if m.loopback && m.verdict == fwconfig.ActionAccept && len(m.in) == 1 && m.empty() {
		return nil, "Portitor accepts loopback traffic first", true
	}
	return m, "", false
}

func (m *match) onlyCt() bool {
	return len(m.in) == 0 && len(m.out) == 0 && m.empty()
}

func (m *match) empty() bool {
	return len(m.src) == 0 && len(m.dst) == 0 && len(m.protos) == 0 && len(m.ports) == 0 && len(m.icmpTypes) == 0
}

func (im *importer) expr(r nftRule, m *match, e map[string]json.RawMessage) {
	for k, v := range e {
		switch k {
		case "match":
			im.matchExpr(r, m, v)
		case "accept", "drop":
			m.verdict = k
		case "reject":
			m.verdict = fwconfig.ActionReject
		case "counter":
		case "log":
			m.log = true
		case "dnat", "snat":
			var t struct {
				Addr json.RawMessage `json:"addr"`
				Port json.RawMessage `json:"port"`
			}
			_ = json.Unmarshal(v, &t)
			var addr string
			if json.Unmarshal(t.Addr, &addr) != nil {
				panic(unsupported(k + " to a map or expression is not supported"))
			}
			m.nat, m.natAddr = k, addr
			if len(t.Port) > 0 && json.Unmarshal(t.Port, &m.natPort) != nil {
				panic(unsupported(k + " to a port range is not supported"))
			}
		case "masquerade":
			if string(v) != "null" {
				panic(unsupported("masquerade with options is not supported"))
			}
			m.nat = k
		case "jump", "goto", "return":
			panic(unsupported(k + " must end the rule"))
		case "limit":
			panic(unsupported("limit: rate limits are not imported; add one under Rate limits"))
		case "xt":
			panic(unsupported("an iptables extension (xt) is not supported"))
		default:
			panic(unsupported("the " + k + " statement is not supported"))
		}
	}
}

// item is one value of a match's right side.
type item struct {
	str    string
	num    int
	isNum  bool
	rng    bool // num..hi
	hi     int
	prefix string
}

func (im *importer) matchExpr(r nftRule, m *match, raw json.RawMessage) {
	var mt struct {
		Op    string                     `json:"op"`
		Left  map[string]json.RawMessage `json:"left"`
		Right json.RawMessage            `json:"right"`
	}
	if err := json.Unmarshal(raw, &mt); err != nil {
		panic(unsupported("a match nft listed oddly"))
	}
	if mt.Op != "==" && mt.Op != "in" {
		panic(unsupported("matches with " + mt.Op + " (negated or compared) are not supported"))
	}
	var left struct {
		Key      string `json:"key"`
		Protocol string `json:"protocol"`
		Field    string `json:"field"`
	}
	var kind string
	for k, v := range mt.Left {
		kind = k
		_ = json.Unmarshal(v, &left)
	}
	what := kind + " " + left.Key + left.Protocol + " " + left.Field
	switch {
	case kind == "meta" && (left.Key == "iifname" || left.Key == "iif" || left.Key == "oifname" || left.Key == "oif"):
		names := im.strings(r, mt.Right, "interface")
		for _, n := range names {
			if strings.ContainsAny(n, "*\\") {
				panic(unsupported("interface wildcards (" + n + ") are not supported"))
			}
		}
		if left.Key[0] == 'i' {
			once("incoming interface", m.in)
			m.in = append(m.in, names...)
			m.loopback = len(names) == 1 && names[0] == "lo"
		} else {
			once("outgoing interface", m.out)
			m.out = append(m.out, names...)
		}
	case kind == "meta" && left.Key == "nfproto":
		v := im.strings(r, mt.Right, "family")
		if len(v) != 1 {
			panic(unsupported("meta nfproto with several families"))
		}
		m.setFamily(familyOf(map[string]string{"ipv4": "ip", "ipv6": "ip6"}[v[0]]))
	case kind == "meta" && left.Key == "l4proto",
		kind == "payload" && left.Protocol == "ip" && left.Field == "protocol",
		kind == "payload" && left.Protocol == "ip6" && left.Field == "nexthdr":
		if left.Protocol != "" {
			m.setFamily(familyOf(left.Protocol))
		}
		once("protocol", m.protos)
		for _, it := range im.items(r, mt.Right, "protocol") {
			if it.isNum {
				m.protos = append(m.protos, strconv.Itoa(it.num))
			} else {
				m.protos = append(m.protos, it.str)
			}
		}
	case kind == "payload" && (left.Protocol == "ip" || left.Protocol == "ip6") && (left.Field == "saddr" || left.Field == "daddr"):
		m.setFamily(familyOf(left.Protocol))
		addrs := im.addresses(r, mt.Right)
		if left.Field == "saddr" {
			once("source address", m.src)
			m.src = append(m.src, addrs...)
		} else {
			once("destination address", m.dst)
			m.dst = append(m.dst, addrs...)
		}
	case kind == "payload" && left.Field == "dport" && slices.Contains([]string{"tcp", "udp", "sctp", "th"}, left.Protocol):
		if m.portProto != "" {
			panic(unsupported("several port matches in one rule"))
		}
		m.portProto = left.Protocol
		for _, it := range im.items(r, mt.Right, "port") {
			switch {
			case it.rng:
				m.ports = append(m.ports, [2]int{it.num, it.hi})
			case it.isNum:
				m.ports = append(m.ports, [2]int{it.num, it.num})
			default:
				p, ok := fwconfig.ServicePort(it.str)
				if !ok {
					panic(unsupported("port " + it.str + " is not a known port name"))
				}
				m.ports = append(m.ports, [2]int{p, p})
			}
		}
	case kind == "payload" && (left.Protocol == "icmp" || left.Protocol == "icmpv6") && left.Field == "type":
		once("ICMP type", m.icmpTypes)
		m.icmpProto = left.Protocol
		m.icmpTypes = append(m.icmpTypes, im.strings(r, mt.Right, "ICMP type")...)
	case kind == "ct" && left.Key == "state":
		m.ctState = append(m.ctState, im.strings(r, mt.Right, "state")...)
	case kind == "payload" && left.Field == "sport":
		panic(unsupported("source port matches are not supported"))
	default:
		panic(unsupported("matches on " + strings.Join(strings.Fields(what), " ") + " are not supported"))
	}
}

// once refuses a second match on a field, from the rule or the jump to its
// chain: both must hold, and a list would match either.
func once(field string, have []string) {
	if len(have) > 0 {
		panic(unsupported("two " + field + " matches in one rule (with the jump to its chain) are not supported"))
	}
}

func (m *match) setFamily(f string) {
	if f == "" {
		return
	}
	if m.family != "" && m.family != f {
		panic(unsupported("the rule matches both IPv4 and IPv6 fields"))
	}
	m.family = f
}

func familyOf(nftFamily string) string {
	switch nftFamily {
	case "ip":
		return "ipv4"
	case "ip6":
		return "ipv6"
	}
	return ""
}

// items reads a match's right side: a value, an anonymous set, a list
// (ct flags) or a named set, whose elements it reads in place.
func (im *importer) items(r nftRule, raw json.RawMessage, what string) []item {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		if name, ok := strings.CutPrefix(s, "@"); ok {
			set := im.sets[r.Family+" "+r.Table+" "+name]
			if set == nil {
				panic(unsupported("set " + name + " is not in the file"))
			}
			if slices.Contains(set.Flags, "dynamic") || slices.Contains(set.Flags, "timeout") {
				panic(unsupported("set " + name + " is dynamic"))
			}
			var out []item
			for _, e := range set.Elem {
				out = append(out, im.items(r, e, what)...)
			}
			return out
		}
		return []item{{str: s}}
	}
	var n int
	if json.Unmarshal(raw, &n) == nil {
		return []item{{num: n, isNum: true}}
	}
	var list []json.RawMessage
	if json.Unmarshal(raw, &list) == nil {
		var out []item
		for _, e := range list {
			out = append(out, im.items(r, e, what)...)
		}
		return out
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil {
		panic(unsupported("a " + what + " nft listed oddly"))
	}
	switch {
	case obj["set"] != nil:
		var list []json.RawMessage
		_ = json.Unmarshal(obj["set"], &list)
		var out []item
		for _, e := range list {
			out = append(out, im.items(r, e, what)...)
		}
		return out
	case obj["prefix"] != nil:
		var p struct {
			Addr string `json:"addr"`
			Len  int    `json:"len"`
		}
		_ = json.Unmarshal(obj["prefix"], &p)
		return []item{{prefix: fmt.Sprintf("%s/%d", p.Addr, p.Len)}}
	case obj["range"] != nil:
		var lr [2]int
		if json.Unmarshal(obj["range"], &lr) != nil {
			panic(unsupported("address ranges are not supported; use prefixes"))
		}
		return []item{{num: lr[0], hi: lr[1], rng: true, isNum: true}}
	case obj["elem"] != nil:
		var el struct {
			Val json.RawMessage `json:"val"`
		}
		_ = json.Unmarshal(obj["elem"], &el)
		return im.items(r, el.Val, what)
	}
	panic(unsupported("a " + what + " that is not a value, set or range"))
}

func (im *importer) strings(r nftRule, raw json.RawMessage, what string) []string {
	var out []string
	for _, it := range im.items(r, raw, what) {
		if it.str == "" {
			panic(unsupported("a " + what + " that is not a name"))
		}
		out = append(out, it.str)
	}
	return out
}

// addresses reads an address match: literals stay in the rule, a named
// set becomes a host/prefix.
func (im *importer) addresses(r nftRule, raw json.RawMessage) []string {
	var s string
	if json.Unmarshal(raw, &s) == nil && strings.HasPrefix(s, "@") {
		return []string{im.object(r, s[1:])}
	}
	var out []string
	for _, it := range im.items(r, raw, "address") {
		a, err := address(it)
		if err != nil {
			panic(unsupported(err.Error()))
		}
		out = append(out, a)
	}
	return out
}

func address(it item) (string, error) {
	switch {
	case it.prefix != "":
		p, err := netip.ParsePrefix(it.prefix)
		if err != nil {
			return "", fmt.Errorf("%q is not a prefix", it.prefix)
		}
		return p.Masked().String(), nil
	case it.str != "":
		a, err := netip.ParseAddr(it.str)
		if err != nil {
			return "", fmt.Errorf("%q is not an address", it.str)
		}
		return a.String(), nil
	}
	return "", fmt.Errorf("address ranges are not supported; use prefixes")
}

// object returns the host/prefix a named address set becomes: an
// existing one with the same addresses, or a new one.
func (im *importer) object(r nftRule, name string) string {
	key := r.Family + " " + r.Table + " " + name
	if n, ok := im.objects[key]; ok {
		return n
	}
	set := im.sets[key]
	if set == nil {
		panic(unsupported("set " + name + " is not in the file"))
	}
	if slices.Contains(set.Flags, "dynamic") || slices.Contains(set.Flags, "timeout") {
		panic(unsupported("set " + name + " is dynamic"))
	}
	if t, _ := set.Type.(string); t != "ipv4_addr" && t != "ipv6_addr" {
		panic(unsupported("set " + name + " is not a set of addresses"))
	}
	var addrs []string
	for _, e := range set.Elem {
		for _, it := range im.items(r, e, "address") {
			a, err := address(it)
			if err != nil {
				panic(unsupported("set " + name + ": " + err.Error()))
			}
			addrs = append(addrs, a)
		}
	}
	if len(addrs) == 0 {
		panic(unsupported("set " + name + " is empty, and an empty host/prefix would match any address"))
	}
	slices.Sort(addrs)
	addrs = slices.Compact(addrs)
	base := name
	if !netobj.ValidName(base) {
		base = "set-" + sanitize(name)
	}
	n := base
	for i := 1; ; i++ {
		existing, ok := im.opt.Objects[n]
		if ok && slices.Equal(sortedCopy(existing), addrs) {
			break
		}
		if !ok && !im.newObject(n) {
			im.res.Objects = append(im.res.Objects, models.AddressObject{
				Name: n, Addresses: addrs, Description: "Imported from nftables set " + key,
			})
			break
		}
		n = fmt.Sprintf("%s-imported%s", base, suffix(i))
	}
	im.objects[key] = n
	return n
}

func (im *importer) newObject(name string) bool {
	return slices.ContainsFunc(im.res.Objects, func(o models.AddressObject) bool { return o.Name == name })
}

func suffix(i int) string {
	if i == 1 {
		return ""
	}
	return strconv.Itoa(i)
}

var notNameChar = regexp.MustCompile(`[^a-z0-9_.-]+`)

func sanitize(s string) string {
	return strings.Trim(notNameChar.ReplaceAllString(strings.ToLower(s), "-"), "-")
}

func sortedCopy(s []string) []string {
	out := slices.Clone(s)
	slices.Sort(out)
	return slices.Compact(out)
}

// interfaces maps the file's interface names to the virtual firewall's.
func (im *importer) interfaces(names []string) []string {
	out := models.StringList{}
	for _, n := range names {
		to := n
		if n == "lo" {
			panic(unsupported("loopback matches: Portitor accepts loopback traffic first"))
		}
		if !im.opt.Interfaces[n] {
			im.foreign[n] = true
			to = im.opt.Rename[n]
			if !im.opt.Interfaces[to] {
				panic(unsupported("interface " + n + " is not in this virtual firewall"))
			}
		}
		if !slices.Contains(out, to) {
			out = append(out, to)
		}
	}
	return out
}

func (im *importer) filterRule(c *nftChain, r nftRule) {
	m, why, builtin := im.gather(c, r)
	if m == nil {
		im.skip(r, why, builtin)
		return
	}
	rule, why := im.makeRule(c, r, m)
	if why != "" {
		im.skip(r, why, false)
		return
	}
	im.res.Rules = append(im.res.Rules, rule)
}

func (im *importer) makeRule(c *nftChain, r nftRule, m *match) (rule models.Rule, why string) {
	defer func() {
		if p := recover(); p != nil {
			u, ok := p.(unsupported)
			if !ok {
				panic(p)
			}
			why = string(u)
		}
	}()
	switch {
	case m.nat != "":
		return rule, m.nat + " belongs in a nat chain"
	case m.verdict == "":
		return rule, "the rule has no accept, drop or reject"
	}
	rule = models.Rule{
		Chain: c.Hook, Action: m.verdict, Log: m.log, Enabled: true, Family: m.family,
		InInterfaces: im.interfaces(m.in), OutInterfaces: im.interfaces(m.out),
		SrcAddrs: list(m.src), DstAddrs: list(m.dst), Services: list(im.serviceNames(m)),
		Description: r.Comment,
	}
	if c.Hook == fwconfig.ChainInput && len(rule.OutInterfaces) > 0 || c.Hook == fwconfig.ChainOutput && len(rule.InInterfaces) > 0 {
		return rule, "an " + c.Hook + " rule can't match that interface direction"
	}
	return rule, ""
}

func list(s []string) models.StringList {
	if s == nil {
		return models.StringList{}
	}
	return models.StringList(s)
}

func (im *importer) natRule(c *nftChain, r nftRule) {
	m, why, builtin := im.gather(c, r)
	if m == nil {
		im.skip(r, why, builtin)
		return
	}
	n, why := im.makeNAT(c, r, m)
	if why != "" {
		im.skip(r, why, false)
		return
	}
	im.res.NAT = append(im.res.NAT, n)
}

func (im *importer) makeNAT(c *nftChain, r nftRule, m *match) (n models.NatRule, why string) {
	defer func() {
		if p := recover(); p != nil {
			u, ok := p.(unsupported)
			if !ok {
				panic(p)
			}
			why = string(u)
		}
	}()
	switch {
	case m.nat == "":
		return n, "only dnat, snat and masquerade are imported from nat chains"
	case m.nat == "dnat" && c.Hook != "prerouting", m.nat != "dnat" && c.Hook != "postrouting":
		return n, m.nat + " on hook " + c.Hook + " is not supported"
	case len(m.icmpTypes) > 0:
		return n, "NAT rules can't match ICMP types"
	case m.log || m.verdict != "":
		return n, "NAT rules can't log or accept, drop or reject"
	}
	proto, err := natProtocol(m)
	if err != "" {
		return n, err
	}
	var ports []string
	for _, p := range m.ports {
		if p[0] == p[1] {
			ports = append(ports, strconv.Itoa(p[0]))
		} else {
			ports = append(ports, fmt.Sprintf("%d-%d", p[0], p[1]))
		}
	}
	n = models.NatRule{
		Kind: m.nat, Protocol: proto, InInterfaces: models.StringList{}, OutInterfaces: models.StringList{},
		SrcAddrs: list(m.src), DstAddrs: list(m.dst), DstPorts: strings.Join(ports, ","),
		ToAddr: m.natAddr, ToPort: m.natPort, Enabled: true, Description: r.Comment,
	}
	if m.nat == "dnat" {
		if len(m.out) > 0 {
			return n, "dnat can't match the outgoing interface"
		}
		n.InInterfaces = im.interfaces(m.in)
	} else {
		if len(m.in) > 0 {
			return n, m.nat + " can't match the incoming interface"
		}
		n.OutInterfaces = im.interfaces(m.out)
	}
	return n, ""
}

func natProtocol(m *match) (string, string) {
	protos := m.protos
	if m.portProto != "" && m.portProto != "th" {
		protos = []string{m.portProto}
	}
	slices.Sort(protos)
	switch {
	case len(protos) == 0:
		return "", ""
	case slices.Equal(protos, []string{"tcp"}), slices.Equal(protos, []string{"udp"}):
		return protos[0], ""
	case slices.Equal(protos, []string{"tcp", "udp"}):
		return "tcp,udp", ""
	}
	return "", "NAT rules match tcp, udp or both, not " + strings.Join(protos, ",")
}

// protoNumbers are the protocol names nft lists, by number.
var protoNumbers = map[string]int{
	"icmp": 1, "igmp": 2, "tcp": 6, "udp": 17, "gre": 47, "esp": 50, "ah": 51,
	"ipv6-icmp": 58, "icmpv6": 58, "ospf": 89, "ospfigp": 89, "vrrp": 112, "sctp": 132,
}

// serviceNames names the rule's protocol matches: predefined services
// where one fits exactly, else custom ones, created if need be.
func (im *importer) serviceNames(m *match) []string {
	switch {
	case len(m.icmpTypes) > 0:
		typ := models.ServiceTypeICMP
		if m.icmpProto == "icmpv6" {
			typ = models.ServiceTypeICMP6
		}
		var out []string
		for _, t := range m.icmpTypes {
			out = append(out, im.service(models.Service{Type: typ, IcmpType: t, Ports: models.ServicePortList{}}))
		}
		return out
	case len(m.ports) > 0:
		protos := []string{m.portProto}
		if m.portProto == "th" {
			protos = m.protos
			if len(protos) == 0 {
				panic(unsupported("th dport without meta l4proto"))
			}
		}
		var all models.ServicePortList
		for _, pr := range protos {
			if pr != "tcp" && pr != "udp" && pr != "sctp" {
				panic(unsupported("ports of protocol " + pr))
			}
			for _, p := range m.ports {
				all = append(all, servicePort(pr, p))
			}
		}
		if n := predefined(models.Service{Type: models.ServiceTypePorts, Ports: all}); n != "" {
			return []string{n}
		}
		var out []string
		for _, p := range all {
			out = append(out, im.service(models.Service{Type: models.ServiceTypePorts, Ports: models.ServicePortList{p}}))
		}
		return out
	}
	var out []string
	for _, p := range m.protos {
		n, err := strconv.Atoi(p)
		if err != nil {
			var ok bool
			if n, ok = protoNumbers[p]; !ok {
				panic(unsupported("protocol " + p + " is not known; use its number"))
			}
		}
		switch n {
		case 6:
			out = append(out, "all-tcp")
		case 17:
			out = append(out, "all-udp")
		case 132:
			out = append(out, "all-sctp")
		case 1:
			out = append(out, "all-icmp")
		case 58:
			out = append(out, "all-icmp6")
		default:
			out = append(out, im.service(models.Service{Type: models.ServiceTypeIP, IpProtocol: n, Ports: models.ServicePortList{}}))
		}
	}
	return out
}

func servicePort(proto string, p [2]int) models.ServicePort {
	sp := models.ServicePort{Protocol: proto, DstLo: p[0]}
	if p[1] != p[0] {
		sp.DstHi = p[1]
	}
	return sp
}

// service names s: a predefined service, an existing custom one or a new
// one.
func (im *importer) service(s models.Service) string {
	if n := predefined(s); n != "" {
		return n
	}
	var base string
	switch s.Type {
	case models.ServiceTypePorts:
		p := s.Ports[0]
		base = fmt.Sprintf("%s-%d", p.Protocol, p.DstLo)
		if p.DstHi != 0 {
			base += fmt.Sprintf("-%d", p.DstHi)
		}
	case models.ServiceTypeICMP:
		base = "icmp-" + sanitize(s.IcmpType)
	case models.ServiceTypeICMP6:
		base = "icmp6-" + sanitize(s.IcmpType)
	default:
		base = fmt.Sprintf("proto-%d", s.IpProtocol)
	}
	n := base
	for i := 1; ; i++ {
		if existing, ok := im.opt.Services[n]; ok {
			if sameService(existing, s) {
				return n
			}
		} else if im.services[n] {
			return n
		} else {
			s.Name = n
			s.Description = "Imported from nftables"
			im.services[n] = true
			im.res.Services = append(im.res.Services, s)
			return n
		}
		n = fmt.Sprintf("%s-imported%s", base, suffix(i))
	}
}

func predefined(s models.Service) string {
	for _, p := range netobj.Predefined {
		if sameService(p, s) {
			return p.Name
		}
	}
	return ""
}

func sameService(a, b models.Service) bool {
	if a.Type != b.Type || a.IcmpType != b.IcmpType || a.IpProtocol != b.IpProtocol || a.IcmpCode != nil || b.IcmpCode != nil {
		return false
	}
	key := func(p models.ServicePort) string {
		hi := p.DstHi
		if hi == p.DstLo {
			hi = 0
		}
		return fmt.Sprintf("%s/%d/%d/%d/%d", p.Protocol, p.DstLo, hi, p.SrcLo, p.SrcHi)
	}
	ka, kb := make([]string, len(a.Ports)), make([]string, len(b.Ports))
	for i, p := range a.Ports {
		ka[i] = key(p)
	}
	for i, p := range b.Ports {
		kb[i] = key(p)
	}
	slices.Sort(ka)
	slices.Sort(kb)
	return slices.Equal(ka, kb)
}

// ruleTexts reads `nft -a list ruleset`: each rule's line by "family
// table chain handle".
func ruleTexts(text string) map[string]string {
	out := map[string]string{}
	var table, chain string
	for _, line := range strings.Split(text, "\n") {
		t := strings.TrimSpace(line)
		f := strings.Fields(t)
		switch {
		case len(f) >= 3 && f[0] == "table":
			table, chain = f[1]+" "+f[2], ""
		case len(f) >= 2 && f[0] == "chain":
			chain = f[1]
		case len(f) >= 1 && (f[0] == "set" || f[0] == "map" || f[0] == "flowtable"):
			chain = ""
		case chain != "" && strings.Contains(t, " # handle "):
			body, h, _ := strings.Cut(t, " # handle ")
			out[table+" "+chain+" "+strings.TrimSpace(h)] = body
		}
	}
	return out
}
