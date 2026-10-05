// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/abundo/portitor/internal/buildinfo"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/render"
)

func (a *Agent) Status(ctx context.Context) *Status {
	a.mu.Lock()
	st := &Status{
		Version:      buildinfo.Version,
		DryRun:       a.cfg.DryRun,
		LastError:    a.lastError,
		DHCPLeases:   clientLeases(a.dhcp.Leases(), a.dhcp6.Leases()),
		DynDNS:       a.ddns.Status(),
		TunnelBroker: a.tbroker.Status(),
		Certificates: a.certs.Status(),
		IPLists:      a.lists.Status(),
		Tasks:        a.tasks.Status(),
		Instances:    []InstanceStatus{},
		AntiLockout:  a.cfg.antiLockout(),
	}
	st.Hostname, _ = os.Hostname()
	var doc *fwconfig.Document
	if a.applied != nil {
		d := *a.applied
		doc = &d
		st.Generation = d.Generation
		t := a.lastApply
		st.LastApply = &t
	}
	if a.pending != nil {
		st.Pending = &PendingStatus{Generation: a.pending.Generation, Deadline: a.pending.Deadline}
	}
	a.mu.Unlock()
	st.Programs = programStatus(doc)
	st.NICs = a.nics(ctx, doc)

	if doc == nil {
		return st
	}
	for _, in := range doc.Instances {
		st.Instances = append(st.Instances, a.instanceStatus(ctx, &in))
	}
	return st
}

func (a *Agent) instanceStatus(ctx context.Context, in *fwconfig.Instance) InstanceStatus {
	ns := in.NetnsName()
	is := InstanceStatus{Name: in.Name, Netns: ns, Interfaces: []IfaceStatus{}, Routes: []RouteStatus{}, WireGuard: []WGStatus{}, Services: map[string]string{}}

	if out, err := a.run.Run(ctx, ns, "ip", "-j", "-d", "-s", "addr", "show"); err == nil {
		var links []struct {
			ipLink
			Operstate string `json:"operstate"`
			Address   string `json:"address"`
			Stats64   struct {
				Rx struct {
					Bytes      uint64 `json:"bytes"`
					Packets    uint64 `json:"packets"`
					Errors     uint64 `json:"errors"`
					Dropped    uint64 `json:"dropped"`
					OverErrors uint64 `json:"over_errors"`
					Multicast  uint64 `json:"multicast"`
				} `json:"rx"`
				Tx struct {
					Bytes         uint64 `json:"bytes"`
					Packets       uint64 `json:"packets"`
					Errors        uint64 `json:"errors"`
					Dropped       uint64 `json:"dropped"`
					CarrierErrors uint64 `json:"carrier_errors"`
					Collisions    uint64 `json:"collisions"`
				} `json:"tx"`
			} `json:"stats64"`
		}
		if json.Unmarshal(out, &links) == nil {
			for _, l := range links {
				if l.Ifname == "lo" {
					continue
				}
				s := IfaceStatus{Name: l.Ifname, Kind: l.kind(), State: strings.ToLower(l.Operstate), MTU: l.MTU, MAC: l.Address,
					Addresses: []string{}, RxBytes: l.Stats64.Rx.Bytes, TxBytes: l.Stats64.Tx.Bytes,
					RxPackets: l.Stats64.Rx.Packets, TxPackets: l.Stats64.Tx.Packets,
					RxErrors: l.Stats64.Rx.Errors, TxErrors: l.Stats64.Tx.Errors,
					RxDropped: l.Stats64.Rx.Dropped, TxDropped: l.Stats64.Tx.Dropped,
					RxOverErrors: l.Stats64.Rx.OverErrors, RxMulticast: l.Stats64.Rx.Multicast,
					TxCarrierErrors: l.Stats64.Tx.CarrierErrors, TxCollisions: l.Stats64.Tx.Collisions}
				for _, ad := range l.AddrInfo {
					if p, err := ad.prefix(); err == nil {
						s.Addresses = append(s.Addresses, p.String())
					}
				}
				is.Interfaces = append(is.Interfaces, s)
			}
		}
	}

	for _, fam := range []string{"-4", "-6"} {
		out, err := a.run.Run(ctx, ns, "ip", "-j", fam, "route", "show")
		if err != nil {
			continue
		}
		var routes []struct {
			Dst      string `json:"dst"`
			Gateway  string `json:"gateway"`
			Dev      string `json:"dev"`
			Protocol any    `json:"protocol"`
			Metric   int    `json:"metric"`
		}
		if json.Unmarshal(out, &routes) == nil {
			for _, r := range routes {
				proto := ""
				if r.Protocol != nil {
					proto = strings.Trim(strings.TrimSpace(toString(r.Protocol)), `"`)
				}
				is.Routes = append(is.Routes, RouteStatus{Dst: r.Dst, Gateway: r.Gateway, Dev: r.Dev, Protocol: proto, Metric: r.Metric})
			}
		}
	}

	if out, err := a.run.Run(ctx, ns, "wg", "show", "all", "dump"); err == nil {
		is.WireGuard = parseWGDump(string(out))
	}

	units := a.serviceUnits(in)
	for _, u := range units {
		out, _ := a.run.Run(ctx, "", "systemctl", "is-active", u)
		state := strings.TrimSpace(string(out))
		if state == "" || state == "[]" {
			state = "unknown"
		}
		is.Services[u] = state
	}
	return is
}

// nics lists the physical interfaces in the root namespace and in the
// namespaces of the applied document's instances.
func (a *Agent) nics(ctx context.Context, doc *fwconfig.Document) []NICStatus {
	namespaces := []string{""}
	declared := map[string]bool{}
	if doc != nil {
		for _, in := range doc.Instances {
			if ns := in.NetnsName(); ns != "" {
				namespaces = append(namespaces, ns)
			}
			for _, ifc := range in.Interfaces {
				if ifc.Kind == fwconfig.KindPhysical {
					declared[ifc.Name] = true
				}
			}
		}
	}
	out := []NICStatus{}
	for _, ns := range namespaces {
		if data, err := a.run.Run(ctx, ns, "ip", "-j", "-d", "addr", "show"); err == nil {
			out = append(out, parseNICs(ns, data, declared)...)
		}
	}
	return out
}

// parseNICs picks the physical interfaces out of `ip -j -d addr show`.
func parseNICs(ns string, data []byte, declared map[string]bool) []NICStatus {
	var links []struct {
		ipLink
		Operstate string `json:"operstate"`
		Address   string `json:"address"`
	}
	if len(data) == 0 || json.Unmarshal(data, &links) != nil {
		return nil
	}
	var out []NICStatus
	for _, l := range links {
		if l.Ifname == "lo" || (l.kind() != "" && !declared[l.Ifname]) {
			continue
		}
		n := NICStatus{Name: l.Ifname, Netns: ns, MAC: l.Address, State: strings.ToLower(l.Operstate), Up: l.up(), MTU: l.MTU, Addresses: []string{}}
		for _, ad := range l.AddrInfo {
			p, err := ad.prefix()
			if err != nil || ad.Scope == "link" || ad.Scope == "host" {
				continue
			}
			switch {
			case !ad.Dynamic:
				n.Addresses = append(n.Addresses, p.String())
			case p.Addr().Is4():
				n.DHCPv4 = true
			default:
				n.SLAAC = true
			}
		}
		out = append(out, n)
	}
	return out
}

func toString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.Itoa(int(t))
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// parseWGDump parses `wg show all dump`: an interface line has 5 fields,
// a peer line 9.
func parseWGDump(s string) []WGStatus {
	out := []WGStatus{}
	idx := map[string]int{}
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		f := strings.Split(sc.Text(), "\t")
		switch len(f) {
		case 5:
			port, _ := strconv.Atoi(f[3])
			idx[f[0]] = len(out)
			out = append(out, WGStatus{Interface: f[0], PublicKey: f[2], ListenPort: port, Peers: []WGPeerStatus{}})
		case 9:
			i, ok := idx[f[0]]
			if !ok {
				continue
			}
			p := WGPeerStatus{PublicKey: f[1], AllowedIPs: []string{}}
			if f[3] != "(none)" {
				p.Endpoint = f[3]
			}
			if f[4] != "(none)" {
				p.AllowedIPs = strings.Split(f[4], ",")
			}
			if ts, _ := strconv.ParseInt(f[5], 10, 64); ts > 0 {
				t := time.Unix(ts, 0)
				p.LatestHandshake = &t
			}
			p.RxBytes, _ = strconv.ParseUint(f[6], 10, 64)
			p.TxBytes, _ = strconv.ParseUint(f[7], 10, 64)
			out[i].Peers = append(out[i].Peers, p)
		}
	}
	return out
}

// ServerLeases reads Kea's memfile lease files (DHCPv4 and DHCPv6) for
// every instance with DHCP enabled. The memfile is an append log: the last line for an
// address wins; lease file cleanup (LFC) spreads it over X.2, X.1 and X.
func (a *Agent) ServerLeases() map[string][]ServerLease {
	a.mu.Lock()
	var instances []fwconfig.Instance
	if a.applied != nil {
		for _, in := range a.applied.Instances {
			if in.DHCP.Enabled {
				instances = append(instances, in)
			}
		}
	}
	a.mu.Unlock()

	out := map[string][]ServerLease{}
	now := time.Now()
	for _, in := range instances {
		name := in.Name
		latest := map[string]ServerLease{}
		var order []string
		var paths []string
		files := a.cfg.Paths.Files(&in)
		dir := files.KeaData
		for _, f := range []string{files.Kea4Lease, files.Kea6Lease} {
			base := filepath.Join(dir, filepath.Base(f))
			paths = append(paths, base+".2", base+".1", base)
		}
		for _, path := range paths {
			f, err := os.Open(path)
			if err != nil {
				continue
			}
			parseKeaLeases(f, func(l ServerLease, valid bool) {
				if _, seen := latest[l.Address]; !seen {
					order = append(order, l.Address)
				}
				if valid {
					latest[l.Address] = l
				} else {
					latest[l.Address] = ServerLease{}
				}
			})
			f.Close()
		}
		list := []ServerLease{}
		for _, addr := range order {
			if l := latest[addr]; l.Address != "" && l.Expires.After(now) {
				list = append(list, l)
			}
		}
		out[name] = list
	}
	return out
}

func parseKeaLeases(r io.Reader, fn func(l ServerLease, valid bool)) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	header, err := cr.Read()
	if err != nil {
		return
	}
	col := map[string]int{}
	for i, h := range header {
		col[h] = i
	}
	get := func(rec []string, name string) string {
		if i, ok := col[name]; ok && i < len(rec) {
			return rec[i]
		}
		return ""
	}
	for {
		rec, err := cr.Read()
		if err != nil {
			return
		}
		exp, _ := strconv.ParseInt(get(rec, "expire"), 10, 64)
		l := ServerLease{
			Address:  get(rec, "address"),
			MAC:      get(rec, "hwaddr"),
			Hostname: strings.TrimSuffix(get(rec, "hostname"), "."),
			Expires:  time.Unix(exp, 0),
		}
		// state 0 = default (active); 1 declined, 2 expired-reclaimed.
		fn(l, get(rec, "state") == "0" || get(rec, "state") == "")
	}
}

// clientLeases are the DHCPv4 and DHCPv6 client leases, by instance,
// interface and family.
func clientLeases(v4, v6 []Lease) []Lease {
	out := slices.Concat(v4, v6)
	slices.SortFunc(out, func(a, b Lease) int {
		return strings.Compare(a.Instance+"\x00"+a.Interface+"\x00"+a.Family, b.Instance+"\x00"+b.Interface+"\x00"+b.Family)
	})
	return out
}

// serviceUnits lists the systemd units of the instance's services.
func (a *Agent) serviceUnits(in *fwconfig.Instance) []string {
	units := []string{}
	if in.DNS.Enabled {
		units = append(units, a.cfg.Units.Named(in))
	}
	if in.DHCP.Enabled {
		units = append(units, a.cfg.Units.Kea4(in))
	}
	if len(render.DHCP6Subnets(in)) > 0 {
		units = append(units, a.cfg.Units.Kea6(in))
	}
	if len(in.RA) > 0 {
		units = append(units, a.cfg.Units.Radvd(in))
	}
	if in.NTP != nil {
		units = append(units, a.cfg.Units.Chrony(in))
	}
	if in.SNMP != nil {
		units = append(units, a.cfg.Units.Snmpd(in))
	}
	if in.FRRRunning() {
		units = append(units, a.cfg.Units.FRR(in))
	}
	return units
}
