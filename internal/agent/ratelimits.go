// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"encoding/json"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/render"
)

// RateLimits reads the traffic of the applied configuration's rate limits:
// the rule counters of the rules that name each one, a policer's drop
// counter (render.RateLimitDropCounter), and a shaper's HTB class on each
// interface that sends through the HTB tree (htbCmds).
func (a *Agent) RateLimits(ctx context.Context) agentapi.RateLimitsResponse {
	res := agentapi.RateLimitsResponse{Instances: map[string]map[string]agentapi.RateLimitStats{}}
	a.mu.Lock()
	var instances []fwconfig.Instance
	if a.applied != nil {
		instances = a.applied.Instances
	}
	a.mu.Unlock()
	for _, in := range instances {
		if len(in.RateLimits) == 0 {
			continue
		}
		ns := in.NetnsName()
		out, err := a.run.Run(ctx, ns, "nft", "-j", "list", "counters", "table", "inet", render.TableName)
		if err != nil {
			continue
		}
		stats := rateLimitCounters(&in, nftCounters(out))
		if shapers := in.Shapers(); shapers != nil {
			classes := map[string][]tcClass{}
			for _, ifc := range in.Interfaces {
				if !usesHTB(ifc, shapers) {
					continue
				}
				if out, err := a.run.Run(ctx, ns, "tc", "-s", "-j", "class", "show", "dev", ifc.Name); err == nil {
					classes[ifc.Name] = parseClasses(out)
				}
			}
			var qdiscs []tcQdiscStats
			if out, err := a.run.Run(ctx, ns, "tc", "-s", "-j", "qdisc", "show"); err == nil {
				qdiscs = parseQdiscStats(out)
			}
			addShaperStats(stats, &in, shapers, classes, qdiscs)
		}
		res.Instances[in.Name] = stats
	}
	return res
}

// rateLimitCounters adds up, per rate limit of the instance, the rule
// counters of its rules and a policer's drop counter.
func rateLimitCounters(in *fwconfig.Instance, counters map[string]nftCounter) map[string]agentapi.RateLimitStats {
	stats := map[string]agentapi.RateLimitStats{}
	for _, l := range in.RateLimits {
		var s agentapi.RateLimitStats
		if !l.Shape {
			d := counters[render.RateLimitDropCounter(l.Name)]
			s.DropPackets, s.DropBytes = d.Packets, d.Bytes
		}
		for _, r := range in.Rules {
			if r.Kind == fwconfig.RuleKindComment || r.ID == 0 || r.RateLimit != l.Name {
				continue
			}
			o := counters[render.RuleCounter(r.ID, render.CounterOrig)]
			p := counters[render.RuleCounter(r.ID, render.CounterReply)]
			s.OrigPackets += o.Packets
			s.OrigBytes += o.Bytes
			s.ReplyPackets += p.Packets
			s.ReplyBytes += p.Bytes
		}
		stats[l.Name] = s
	}
	return stats
}

// tcStats is the queue statistics `tc -s -j` shows for a class or qdisc.
type tcStats struct {
	Bytes      uint64 `json:"bytes"`
	Packets    uint64 `json:"packets"`
	Drops      uint64 `json:"drops"`
	Overlimits uint64 `json:"overlimits"`
	Backlog    uint64 `json:"backlog"`
	Qlen       uint64 `json:"qlen"`
}

// tcClass is the subset of `tc -s -j class show dev X` the agent reads.
type tcClass struct {
	Class  string  `json:"class"`
	Handle string  `json:"handle"`
	Stats  tcStats `json:"stats"`
}

// tcQdiscStats is the subset of `tc -s -j qdisc show` the agent reads for
// the statistics: a qdisc's own, at its top level.
type tcQdiscStats struct {
	Kind   string `json:"kind"`
	Dev    string `json:"dev"`
	Parent string `json:"parent"`
	tcStats
}

func parseClasses(out []byte) []tcClass {
	var cs []tcClass
	if json.Unmarshal(out, &cs) != nil {
		return nil
	}
	return cs
}

func parseQdiscStats(out []byte) []tcQdiscStats {
	var qs []tcQdiscStats
	if json.Unmarshal(out, &qs) != nil {
		return nil
	}
	return qs
}

// addShaperStats adds each shaper's HTB class (render.ShaperClass) on the
// interfaces in classes to its stats, in the instance's interface order.
// Its drops are the class's (its queue full) and its fq_codel queue's
// (CoDel's), which the class doesn't count.
func addShaperStats(stats map[string]agentapi.RateLimitStats, in *fwconfig.Instance, shapers []fwconfig.RateLimit, classes map[string][]tcClass, qdiscs []tcQdiscStats) {
	for i, l := range shapers {
		handle := render.ShaperClass(i)
		s := stats[l.Name]
		for _, ifc := range in.Interfaces {
			for _, c := range classes[ifc.Name] {
				if c.Class != "htb" || c.Handle != handle {
					continue
				}
				sc := agentapi.ShaperClass{
					Interface:  ifc.Name,
					Bytes:      c.Stats.Bytes,
					Packets:    c.Stats.Packets,
					Drops:      c.Stats.Drops,
					Overlimits: c.Stats.Overlimits,
					Backlog:    c.Stats.Backlog,
					Qlen:       c.Stats.Qlen,
				}
				for _, q := range qdiscs {
					if q.Dev == ifc.Name && q.Parent == handle {
						sc.Drops += q.Drops
					}
				}
				s.Interfaces = append(s.Interfaces, sc)
			}
		}
		stats[l.Name] = s
	}
}
