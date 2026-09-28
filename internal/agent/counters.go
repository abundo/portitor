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

// RuleCounters reads the rule counters (render.RuleCounter) of the applied
// configuration from each instance's ruleset.
func (a *Agent) RuleCounters(ctx context.Context) agentapi.RuleCountersResponse {
	res := agentapi.RuleCountersResponse{Rules: map[uint32]agentapi.RuleCounters{}}
	a.mu.Lock()
	var instances []fwconfig.Instance
	if a.applied != nil {
		instances = a.applied.Instances
	}
	a.mu.Unlock()
	for _, in := range instances {
		if !hasRuleIDs(in.Rules) {
			continue
		}
		out, err := a.run.Run(ctx, in.NetnsName(), "nft", "-j", "list", "counters", "table", "inet", render.TableName)
		if err == nil {
			parseRuleCounters(out, res.Rules)
		}
	}
	return res
}

func hasRuleIDs(rules []fwconfig.Rule) bool {
	for _, r := range rules {
		if r.ID != 0 {
			return true
		}
	}
	return false
}

// parseRuleCounters adds the rule counters in `nft -j list counters` output
// to into; other counters and unparsable output are ignored.
func parseRuleCounters(out []byte, into map[uint32]agentapi.RuleCounters) {
	var doc struct {
		Nftables []struct {
			Counter *struct {
				Name    string `json:"name"`
				Packets uint64 `json:"packets"`
				Bytes   uint64 `json:"bytes"`
			} `json:"counter"`
		} `json:"nftables"`
	}
	if json.Unmarshal(out, &doc) != nil {
		return
	}
	for _, o := range doc.Nftables {
		if o.Counter == nil {
			continue
		}
		id, dir, ok := render.ParseRuleCounter(o.Counter.Name)
		if !ok {
			continue
		}
		c := into[id]
		if dir == render.CounterOrig {
			c.OrigPackets, c.OrigBytes = o.Counter.Packets, o.Counter.Bytes
		} else {
			c.ReplyPackets, c.ReplyBytes = o.Counter.Packets, o.Counter.Bytes
		}
		into[id] = c
	}
}
