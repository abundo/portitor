// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/abundo/portitor/internal/agentapi"
)

// BFD asks FRR, through vtysh, for the BFD sessions of each instance that
// runs bfdd.
func (a *Agent) BFD(ctx context.Context) *agentapi.BFDResponse {
	resp := &agentapi.BFDResponse{Instances: []agentapi.BFDInstance{}}
	a.mu.Lock()
	doc := a.applied
	a.mu.Unlock()
	if doc == nil {
		return resp
	}
	for i := range doc.Instances {
		in := &doc.Instances[i]
		if !in.BFDRunning() {
			continue
		}
		bi := agentapi.BFDInstance{Instance: in.Name, Peers: []agentapi.BFDPeerInfo{}}
		out, err := a.vtysh(ctx, in)("show bfd peers json")
		if err != nil {
			bi.Error = vtyshError(out, err)
		} else if bi.Peers, err = parseBFDPeers(out); err != nil {
			bi.Error = err.Error()
		}
		resp.Instances = append(resp.Instances, bi)
	}
	return resp
}

// parseBFDPeers reads `show bfd peers json`: a list of sessions.
func parseBFDPeers(data []byte) ([]agentapi.BFDPeerInfo, error) {
	var list []map[string]any
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("unexpected answer from vtysh: %v", err)
	}
	out := []agentapi.BFDPeerInfo{}
	for _, m := range list {
		o := jsonObj(m)
		num := func(key string) int64 {
			n, _ := o.num(key)
			return n
		}
		p := agentapi.BFDPeerInfo{
			Peer: o.str("peer"), Local: o.str("local"), Interface: o.str("interface"),
			Multihop: o.flag("multihop"), Profile: o.str("profile"), Status: o.str("status"),
			Diagnostic: o.str("diagnostic"), RemoteDiagnostic: o.str("remote-diagnostic"),
			Uptime: num("uptime"), Downtime: num("downtime"),
			DetectMultiplier: int(num("detect-multiplier")), ReceiveInterval: int(num("receive-interval")),
			TransmitInterval: int(num("transmit-interval")), RemoteDetectMultiplier: int(num("remote-detect-multiplier")),
			RemoteReceiveInterval: int(num("remote-receive-interval")), RemoteTransmitInterval: int(num("remote-transmit-interval")),
		}
		out = append(out, p)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Interface != out[j].Interface {
			return out[i].Interface < out[j].Interface
		}
		return out[i].Peer < out[j].Peer
	})
	return out, nil
}
