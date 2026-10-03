// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/abundo/portitor/internal/agentapi"
)

// BGP asks FRR, through vtysh, for the state of each instance that runs
// BGP: its neighbours' sessions and, when it is not too large, its BGP
// table.
func (a *Agent) BGP(ctx context.Context) *agentapi.BGPResponse {
	resp := &agentapi.BGPResponse{Instances: []agentapi.BGPInstance{}}
	a.mu.Lock()
	doc := a.applied
	a.mu.Unlock()
	if doc == nil {
		return resp
	}
	for i := range doc.Instances {
		in := &doc.Instances[i]
		if !in.BGPRunning() {
			continue
		}
		vtysh := func(command string) ([]byte, error) {
			args := []string{}
			if !in.Default {
				// The instance is FRR's pathspace (portitor-frr@.service).
				args = append(args, "-N", in.Name)
			}
			args = append(args, "-c", command)
			cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
			defer cancel()
			return a.bg.Run(cctx, "", "vtysh", args...)
		}
		resp.Instances = append(resp.Instances, bgpInstance(in.Name, vtysh))
	}
	return resp
}

// bgpInstance gathers one instance's BGP state with vtysh.
func bgpInstance(name string, vtysh func(string) ([]byte, error)) agentapi.BGPInstance {
	bi := agentapi.BGPInstance{Instance: name, Peers: []agentapi.BGPPeerInfo{}, Routes: []agentapi.BGPRoute{}}
	out, err := vtysh("show bgp neighbors json")
	if err != nil {
		bi.Error = vtyshError(out, err)
		return bi
	}
	peers, err := parseBGPNeighbors(out)
	if err != nil {
		bi.Error = err.Error()
		return bi
	}
	bi.Peers = peers
	for _, fam := range []string{"ipv4", "ipv6"} {
		out, err := vtysh("show bgp " + fam + " unicast summary json")
		if err != nil {
			continue
		}
		sum := parseBGPSummary(out)
		if sum.RouterID != "" {
			bi.RouterID, bi.ASN = sum.RouterID, sum.AS
		}
		if sum.RIBCount == 0 {
			continue
		}
		// A full Internet table would be hundreds of megabytes of JSON.
		if sum.RIBCount > agentapi.BGPMaxRoutes {
			bi.RoutesTruncated = true
			continue
		}
		if out, err := vtysh("show bgp " + fam + " unicast json"); err == nil {
			bi.Routes = append(bi.Routes, parseBGPRoutes(out, fam)...)
		}
	}
	return bi
}

// vtyshError makes vtysh's complaint (bgpd not running, say) the error.
func vtyshError(out []byte, err error) string {
	if msg := strings.TrimSpace(string(out)); msg != "" && !strings.HasPrefix(msg, "{") {
		return msg
	}
	var ee interface{ ExitCode() int }
	if errors.As(err, &ee) {
		return fmt.Sprintf("vtysh: exit code %d", ee.ExitCode())
	}
	return err.Error()
}

// parseBGPNeighbors reads `show bgp neighbors json`: neighbours by address.
func parseBGPNeighbors(data []byte) ([]agentapi.BGPPeerInfo, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("unexpected answer from vtysh: %v", err)
	}
	out := []agentapi.BGPPeerInfo{}
	for addr, msg := range raw {
		var n struct {
			RemoteAS      uint32 `json:"remoteAs"`
			LocalAS       uint32 `json:"localAs"`
			Desc          string `json:"nbrDesc"`
			Hostname      string `json:"hostname"`
			State         string `json:"bgpState"`
			AdminShutdown bool   `json:"adminShutDown"`
			UpMsec        int64  `json:"bgpTimerUpMsec"`
			UpString      string `json:"bgpTimerUpString"`
			LastReset     string `json:"lastResetDueTo"`
			Stats         struct {
				Sent int64 `json:"totalSent"`
				Recv int64 `json:"totalRecv"`
			} `json:"messageStats"`
			Families map[string]struct {
				Accepted int64 `json:"acceptedPrefixCounter"`
				Sent     int64 `json:"sentPrefixCounter"`
			} `json:"addressFamilyInfo"`
		}
		// Other keys (a peer group's, FRR's own) are not neighbours.
		if json.Unmarshal(msg, &n) != nil || n.State == "" {
			continue
		}
		p := agentapi.BGPPeerInfo{
			Address:     addr,
			RemoteAS:    n.RemoteAS,
			LocalAS:     n.LocalAS,
			Description: n.Desc,
			Hostname:    n.Hostname,
			State:       n.State,
			MsgRcvd:     n.Stats.Recv,
			MsgSent:     n.Stats.Sent,
			LastReset:   n.LastReset,
			Families:    map[string]agentapi.BGPPeerFamily{},
		}
		if n.AdminShutdown {
			p.State = "Idle (Admin)"
		}
		if n.State == "Established" {
			p.Uptime, p.UptimeSecs = n.UpString, n.UpMsec/1000
		}
		for key, f := range n.Families {
			fam := ""
			switch key {
			case "ipv4Unicast":
				fam = "ipv4"
			case "ipv6Unicast":
				fam = "ipv6"
			default:
				continue
			}
			p.Families[fam] = agentapi.BGPPeerFamily{PrefixesReceived: f.Accepted, PrefixesSent: f.Sent}
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Address < out[j].Address })
	return out, nil
}

type bgpSummary struct {
	RouterID string `json:"routerId"`
	AS       uint32 `json:"as"`
	RIBCount int    `json:"ribCount"`
}

// parseBGPSummary reads `show bgp <afi> unicast summary json`; FRR keys it
// by the address family in some versions.
func parseBGPSummary(data []byte) bgpSummary {
	var s bgpSummary
	if json.Unmarshal(data, &s) == nil && s.RouterID != "" {
		return s
	}
	var byFamily map[string]bgpSummary
	if json.Unmarshal(data, &byFamily) == nil {
		for _, v := range byFamily {
			if v.RouterID != "" {
				return v
			}
		}
	}
	return bgpSummary{}
}

// parseBGPRoutes reads `show bgp <afi> unicast json`: paths by prefix.
func parseBGPRoutes(data []byte, fam string) []agentapi.BGPRoute {
	var table struct {
		Routes map[string][]struct {
			Valid    bool   `json:"valid"`
			Best     bool   `json:"bestpath"`
			Metric   *int64 `json:"metric"`
			LocPrf   *int64 `json:"locPrf"`
			Weight   int64  `json:"weight"`
			PeerID   string `json:"peerId"`
			Path     string `json:"path"`
			Origin   string `json:"origin"`
			NextHops []struct {
				IP    string `json:"ip"`
				Scope string `json:"scope"`
			} `json:"nexthops"`
		} `json:"routes"`
	}
	if json.Unmarshal(data, &table) != nil {
		return nil
	}
	var out []agentapi.BGPRoute
	for prefix, paths := range table.Routes {
		for _, p := range paths {
			r := agentapi.BGPRoute{
				Family: fam, Prefix: prefix, Best: p.Best, Valid: p.Valid,
				Metric: p.Metric, LocalPref: p.LocPrf, Weight: p.Weight,
				Path: p.Path, Origin: p.Origin, PeerID: p.PeerID,
			}
			// IPv6 paths list the global next hop first.
			for _, nh := range p.NextHops {
				if nh.Scope != "link-local" {
					r.NextHop = nh.IP
					break
				}
			}
			out = append(out, r)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Prefix != out[j].Prefix {
			return out[i].Prefix < out[j].Prefix
		}
		return out[i].Best && !out[j].Best
	})
	return out
}
