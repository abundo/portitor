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

// RuleCounters reads the rule counters (render.RuleCounter) and the chains'
// drop counters (render.DropCounter) of the applied configuration from each
// instance's ruleset.
func (a *Agent) RuleCounters(ctx context.Context) agentapi.RuleCountersResponse {
	res := agentapi.RuleCountersResponse{
		Rules: map[uint32]agentapi.RuleCounters{},
		Drops: map[string]map[string]agentapi.ChainDrops{},
	}
	a.mu.Lock()
	var instances []fwconfig.Instance
	if a.applied != nil {
		instances = a.applied.Instances
	}
	a.mu.Unlock()
	for _, in := range instances {
		out, err := a.run.Run(ctx, in.NetnsName(), "nft", "-j", "list", "counters", "table", "inet", render.TableName)
		if err != nil {
			continue
		}
		drops := map[string]agentapi.ChainDrops{}
		parseCounters(out, res.Rules, drops)
		if len(drops) > 0 {
			res.Drops[in.Name] = drops
		}
	}
	return res
}

// nftCounter is a named counter's value.
type nftCounter struct {
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

// nftCounters reads the named counters in `nft -j list counters` output,
// by name; nil for unparsable output.
func nftCounters(out []byte) map[string]nftCounter {
	var doc struct {
		Nftables []struct {
			Counter *struct {
				Name string `json:"name"`
				nftCounter
			} `json:"counter"`
		} `json:"nftables"`
	}
	if json.Unmarshal(out, &doc) != nil {
		return nil
	}
	m := map[string]nftCounter{}
	for _, o := range doc.Nftables {
		if o.Counter != nil {
			m[o.Counter.Name] = o.Counter.nftCounter
		}
	}
	return m
}

// parseCounters adds the rule counters in `nft -j list counters` output
// to rules and the drop counters to drops (by chain); other counters and
// unparsable output are ignored.
func parseCounters(out []byte, rules map[uint32]agentapi.RuleCounters, drops map[string]agentapi.ChainDrops) {
	for name, v := range nftCounters(out) {
		if chain, reason, ok := render.ParseDropCounter(name); ok {
			d := drops[chain]
			if reason == render.DropInvalid {
				d.InvalidPackets, d.InvalidBytes = v.Packets, v.Bytes
			} else {
				d.PolicyPackets, d.PolicyBytes = v.Packets, v.Bytes
			}
			drops[chain] = d
			continue
		}
		id, dir, ok := render.ParseRuleCounter(name)
		if !ok {
			continue
		}
		c := rules[id]
		if dir == render.CounterOrig {
			c.OrigPackets, c.OrigBytes = v.Packets, v.Bytes
		} else {
			c.ReplyPackets, c.ReplyBytes = v.Packets, v.Bytes
		}
		rules[id] = c
	}
}
