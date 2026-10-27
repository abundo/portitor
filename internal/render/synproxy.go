// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package render

import (
	"fmt"
	"strings"

	"github.com/abundo/portitor/internal/fwconfig"
)

// SynProxyChain untracks the SYNs of the SYN proxy rules
// (fwconfig.SynProxy), before conntrack sees them.
const SynProxyChain = "prerouting_synproxy"

// synOnly matches a SYN without ACK, FIN or RST.
const synOnly = "tcp flags & (fin | syn | rst | ack) == syn"

// synProxyRule is a rule with a SYN proxy and its number in its chain's
// table (as writeRules numbers it).
type synProxyRule struct {
	idx  int
	rule fwconfig.Rule
}

func synProxyRules(in *fwconfig.Instance) []synProxyRule {
	var out []synProxyRule
	idx := 0
	for _, r := range in.Rules {
		if r.Kind == fwconfig.RuleKindComment {
			continue
		}
		if r.SynProxy != nil {
			out = append(out, synProxyRule{idx, r})
		}
		idx++
	}
	return out
}

// eachSynProxyMatch calls f with each nft match of a SYN proxy rule's TCP
// services for one IP version (synproxy's MSS differs between them) and the interface
// match alternatives (sdif for the forward chain).
func eachSynProxyMatch(b *strings.Builder, in *fwconfig.Instance, s synProxyRule, sdif bool, f func(iif []string, fam string, m fwconfig.RuleMatch)) {
	r := s.rule
	alts, ok := ifaceMatch(b, fmt.Sprintf("syn proxy of rule %d", s.idx+1), in, r.InInterfaces, nil, sdif)
	if !ok {
		return
	}
	for _, iif := range alts {
		for _, m := range r.Matches() {
			if m.Service.Protocol != fwconfig.ProtoTCP { // accepted by the rule
				continue
			}
			var ok bool
			if m.FamilyMatch, ok = dropEmptySets(in, m.FamilyMatch); !ok {
				continue
			}
			fams := []string{m.Family}
			if m.Family == "" { // no addresses: one match per version
				fams = []string{"ipv4", "ipv6"}
			}
			for _, fam := range fams {
				fm := m
				fm.Family = fam
				f(iif, fam, fm)
			}
		}
	}
}

// writeSynProxyNotrack renders SynProxyChain: the rules' SYNs are left
// untracked, but those to the firewall's own addresses (a port forward's
// too: an untracked packet is never DNATed).
func writeSynProxyNotrack(b *strings.Builder, in *fwconfig.Instance) {
	rules := synProxyRules(in)
	if len(rules) == 0 {
		return
	}
	fmt.Fprintf(b, "\tchain %s {\n", SynProxyChain)
	b.WriteString("\t\ttype filter hook prerouting priority raw; policy accept;\n")
	for _, s := range rules {
		eachSynProxyMatch(b, in, s, false, func(iif []string, fam string, m fwconfig.RuleMatch) {
			for _, match := range matchExprs(m.FamilyMatch, serviceExpr(m.Service)) {
				line := append(append(append([]string(nil), iif...), match...), synOnly, "fib daddr type != local", "notrack",
					comment(fmt.Sprintf("rule %d", s.idx+1), "syn proxy"))
				b.WriteString("\t\t" + strings.Join(line, " ") + "\n")
			}
		})
	}
	b.WriteString("\t}\n\n")
}

// writeSynProxies renders, in the forward chain before the invalid drop,
// the synproxy statements: the untracked SYN gets a SYN cookie in reply,
// and the client's ACK, invalid to conntrack without tcp_loose, opens the
// connection to the server.
func writeSynProxies(b *strings.Builder, in *fwconfig.Instance) {
	for _, s := range synProxyRules(in) {
		p := s.rule.SynProxy
		eachSynProxyMatch(b, in, s, true, func(iif []string, fam string, m fwconfig.RuleMatch) {
			mss := p.MSS
			if mss == 0 {
				mss = fwconfig.DefaultSynProxyMSS
			}
			if fam == "ipv6" {
				mss -= 20
			}
			for _, match := range matchExprs(m.FamilyMatch, serviceExpr(m.Service)) {
				line := append(append(append([]string(nil), iif...), match...), "ct state invalid,untracked",
					fmt.Sprintf("synproxy mss %d wscale %d timestamp sack-perm", mss, p.WScale),
					comment(fmt.Sprintf("rule %d", s.idx+1), "syn proxy"))
				b.WriteString("\t\t" + strings.Join(line, " ") + "\n")
			}
		})
	}
}

// writeSynProxyOutput accepts, in the output chain before the invalid
// drop, what synproxy sends on the servers' and clients' behalf, from
// their addresses (not the firewall's): the SYN cookie to the client (a
// SYN-ACK of no connection, invalid to conntrack) and the SYN that opens
// the connection to the server once the client's ACK checked out. That is
// where the connection is new, so the rule's counter, log and connection
// mark go there.
func writeSynProxyOutput(b *strings.Builder, in *fwconfig.Instance) {
	for _, s := range synProxyRules(in) {
		r := s.rule
		name := fmt.Sprintf("rule %d", s.idx+1)
		var tail []string
		if r.ID != 0 {
			tail = append(tail, fmt.Sprintf("counter name %q", RuleCounter(r.ID, CounterOrig)))
		} else {
			tail = append(tail, "counter")
		}
		if r.Log {
			tail = append(tail, logStmt(LogSource{Chain: r.Chain, Rule: s.idx + 1, Action: r.Action}))
		}
		if r.ID != 0 {
			tail = append(tail, fmt.Sprintf("ct mark set %d", r.ID))
		}
		tail = append(tail, "accept", comment(name, "syn proxy"))
		eachSynProxyMatch(b, in, s, false, func(_ []string, fam string, m fwconfig.RuleMatch) {
			for _, src := range addrOperands(m.Src, fam) {
				for _, dst := range addrOperands(m.Dst, fam) {
					// The SYN cookie, from the server to the client.
					reply := m.Service
					reply.SrcPorts, reply.DstPorts = m.Service.DstPorts, m.Service.SrcPorts
					line := append([]string{"fib saddr type != local", "ct state invalid,untracked"}, addrExpr(fam, dst, src)...)
					line = append(append(line, serviceExpr(reply)...), "accept", comment(name, "syn proxy cookie"))
					b.WriteString("\t\t" + strings.Join(line, " ") + "\n")
					// The SYN to the server.
					line = append([]string{"fib saddr type != local", "ct state new"}, addrExpr(fam, src, dst)...)
					line = append(append(append(line, serviceExpr(m.Service)...), synOnly), tail...)
					b.WriteString("\t\t" + strings.Join(line, " ") + "\n")
				}
			}
		})
	}
}
