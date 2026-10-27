// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package fwconfig

import (
	"net/netip"
	"slices"
	"strings"
)

// Syslog sends the host's journal to remote syslog servers (rsyslog). It
// is the default instance's alone: the journal is the host's, and holds
// what every virtual firewall's services log.
type Syslog struct {
	Servers []SyslogServer `json:"servers"`
}

// SyslogServer is a remote syslog server: the journal's entries of
// Severity or more urgent are sent to Address and Port over Protocol, in
// Format.
type SyslogServer struct {
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Format   string `json:"format"`
	Severity string `json:"severity"`
}

// SyslogPort is the default syslog port, over UDP and TCP.
const SyslogPort = 514

// The syslog protocols, formats and severities, in rsyslog's words; the
// severities from the most urgent.
var (
	SyslogProtocols  = []string{"udp", "tcp"}
	SyslogFormats    = []string{"rfc3164", "rfc5424"}
	SyslogSeverities = []string{"emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"}
)

// CheckSyslogServer checks a syslog server; it returns its problems.
func CheckSyslogServer(s SyslogServer) []string {
	var out []string
	if a, err := netip.ParseAddr(s.Address); err != nil || a.Zone() != "" || a.IsUnspecified() {
		out = append(out, "the address must be an IPv4 or IPv6 address")
	}
	if s.Port < 1 || s.Port > 65535 {
		out = append(out, "the port must be 1 to 65535")
	}
	if !slices.Contains(SyslogProtocols, s.Protocol) {
		out = append(out, "the protocol must be one of "+strings.Join(SyslogProtocols, ", "))
	}
	if !slices.Contains(SyslogFormats, s.Format) {
		out = append(out, "the format must be one of "+strings.Join(SyslogFormats, ", "))
	}
	if !slices.Contains(SyslogSeverities, s.Severity) {
		out = append(out, "the severity must be one of "+strings.Join(SyslogSeverities, ", "))
	}
	return out
}

func (v *validator) syslog(p string, in *Instance) {
	if !in.Default {
		v.addf("%s: syslog: only the default instance sends the journal to syslog servers", p)
	}
	if len(in.Syslog.Servers) == 0 {
		v.addf("%s: syslog: no servers", p)
	}
	seen := map[SyslogServer]bool{}
	for _, s := range in.Syslog.Servers {
		for _, e := range CheckSyslogServer(s) {
			v.addf("%s: syslog server %s: %s", p, s.Address, e)
		}
		key := SyslogServer{Address: s.Address, Port: s.Port, Protocol: s.Protocol}
		if seen[key] {
			v.addf("%s: syslog: duplicate server %s port %s/%d", p, s.Address, s.Protocol, s.Port)
		}
		seen[key] = true
	}
}
