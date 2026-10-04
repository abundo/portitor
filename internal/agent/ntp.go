// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"encoding/csv"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/fwconfig"
)

// chronyUsers are the users chronyd drops to: Debian's, then Fedora's.
var chronyUsers = []string{"_chrony", "chrony"}

// snmpdUser is the user a virtual firewall's snmpd drops to
// (portitor-snmpd@.service): Debian's.
const snmpdUser = "Debian-snmp"

// NTP gathers the sources and statistics of the instances' chronyd, with
// chronyc through each one's command socket (render.InstanceFiles.ChronySocket;
// the default instance's is chrony's own).
func (a *Agent) NTP(ctx context.Context) *agentapi.NTPResponse {
	resp := &agentapi.NTPResponse{Instances: []agentapi.NTPInstance{}}
	a.mu.Lock()
	doc := a.applied
	a.mu.Unlock()
	if doc == nil {
		return resp
	}
	for i := range doc.Instances {
		in := &doc.Instances[i]
		if in.NTP == nil {
			continue
		}
		resp.Instances = append(resp.Instances, ntpInstance(in.Name, a.chronyc(ctx, in)))
	}
	return resp
}

// chronyc returns a function that runs chronyc against the instance's
// chronyd.
func (a *Agent) chronyc(ctx context.Context, in *fwconfig.Instance) func(...string) ([]byte, error) {
	return func(args ...string) ([]byte, error) {
		if sock := a.cfg.Paths.Files(in).ChronySocket; sock != "" {
			args = append([]string{"-h", sock}, args...)
		}
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		return a.bg.Run(cctx, "", "chronyc", args...)
	}
}

func ntpInstance(name string, chronyc func(...string) ([]byte, error)) agentapi.NTPInstance {
	ni := agentapi.NTPInstance{Instance: name, Sources: []agentapi.NTPSource{}, Tracking: []agentapi.NTPField{}, ServerStats: []agentapi.NTPField{}}
	out, err := chronyc("-c", "-n", "sources")
	if err != nil {
		ni.Error = chronycError(out, err)
		return ni
	}
	if ni.Sources, err = parseChronySources(out); err != nil {
		ni.Error = err.Error()
		return ni
	}
	for i := range ni.Sources {
		s := &ni.Sources[i]
		if out, err := chronyc("sourcename", s.Address); err == nil {
			if name := strings.TrimSpace(string(out)); name != s.Address && fwconfig.ValidNTPServer(name) {
				s.Name = name
			}
		}
	}
	if out, err := chronyc("-c", "-n", "sourcestats"); err == nil {
		addChronySourceStats(ni.Sources, out)
	}
	if out, err := chronyc("-c", "-n", "authdata"); err == nil {
		addChronyAuth(ni.Sources, out)
	}
	if out, err := chronyc("tracking"); err == nil {
		ni.Tracking = parseChronyFields(out)
	}
	if out, err := chronyc("serverstats"); err == nil {
		ni.ServerStats = parseChronyFields(out)
	}
	return ni
}

func chronycError(out []byte, err error) string {
	if s := strings.TrimSpace(string(out)); s != "" {
		return s
	}
	return err.Error()
}

func chronyCSV(out []byte) ([][]string, error) {
	r := csv.NewReader(strings.NewReader(string(out)))
	r.FieldsPerRecord = -1
	return r.ReadAll()
}

// parseChronySources reads `chronyc -c -n sources`: mode, state, address,
// stratum, poll (log2 seconds), reach (octal), last sample's age, adjusted
// and measured offset and error (seconds).
func parseChronySources(out []byte) ([]agentapi.NTPSource, error) {
	rows, err := chronyCSV(out)
	if err != nil {
		return nil, fmt.Errorf("unexpected answer from chronyc: %v", err)
	}
	modes := map[string]string{"^": "server", "=": "peer", "#": "refclock"}
	states := map[string]string{"*": "selected", "+": "combined", "-": "not combined", "?": "unusable", "x": "falseticker", "~": "too variable"}
	srcs := []agentapi.NTPSource{}
	for _, f := range rows {
		if len(f) < 10 {
			return nil, fmt.Errorf("unexpected answer from chronyc: %q", strings.Join(f, ","))
		}
		s := agentapi.NTPSource{Mode: modes[f[0]], State: states[f[1]], Address: f[2]}
		if s.Mode == "" {
			s.Mode = f[0]
		}
		if s.State == "" {
			s.State = f[1]
		}
		s.Stratum, _ = strconv.Atoi(f[3])
		if p, err := strconv.Atoi(f[4]); err == nil && p >= -32 && p < 32 {
			s.Poll = pow2(p)
		}
		if r, err := strconv.ParseUint(f[5], 8, 16); err == nil {
			s.Reach = int(r)
		}
		s.LastRx, _ = strconv.ParseInt(f[6], 10, 64)
		s.Offset, _ = strconv.ParseFloat(f[7], 64)
		s.Error, _ = strconv.ParseFloat(f[9], 64)
		srcs = append(srcs, s)
	}
	return srcs, nil
}

func pow2(p int) float64 {
	if p < 0 {
		return 1 / float64(int64(1)<<-p)
	}
	return float64(int64(1) << p)
}

// addChronySourceStats adds `chronyc -c -n sourcestats` (address, samples,
// runs, span, frequency and its skew in ppm, offset, standard deviation)
// to the sources.
func addChronySourceStats(srcs []agentapi.NTPSource, out []byte) {
	rows, _ := chronyCSV(out)
	for _, f := range rows {
		if len(f) < 8 {
			continue
		}
		for i := range srcs {
			if srcs[i].Address != f[0] {
				continue
			}
			s := &srcs[i]
			s.Samples, _ = strconv.Atoi(f[1])
			s.Span, _ = strconv.ParseInt(f[3], 10, 64)
			s.Frequency, _ = strconv.ParseFloat(f[4], 64)
			s.FreqSkew, _ = strconv.ParseFloat(f[5], 64)
			s.StdDev, _ = strconv.ParseFloat(f[7], 64)
		}
	}
}

// addChronyAuth adds the authentication (NTS, a symmetric key, or none)
// from `chronyc -c -n authdata` (address, mode, ...) to the sources.
func addChronyAuth(srcs []agentapi.NTPSource, out []byte) {
	rows, _ := chronyCSV(out)
	for _, f := range rows {
		if len(f) < 2 {
			continue
		}
		for i := range srcs {
			if srcs[i].Address == f[0] && f[1] != "-" {
				srcs[i].Auth = f[1]
			}
		}
	}
}

// parseChronyFields reads chronyc's "Name : value" lines (tracking,
// serverstats), as they are: the fields differ between chrony versions.
func parseChronyFields(out []byte) []agentapi.NTPField {
	fields := []agentapi.NTPField{}
	for _, line := range strings.Split(string(out), "\n") {
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		fields = append(fields, agentapi.NTPField{Name: strings.TrimSpace(name), Value: strings.TrimSpace(value)})
	}
	return fields
}
