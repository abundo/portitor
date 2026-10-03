// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package fwconfig

import (
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strings"

	"github.com/abundo/portitor/internal/cron"
)

// IP list sources.
const (
	// IPListCrowdSec reads the ban decisions of a CrowdSec Local API, as
	// a bouncer (URL is the LAPI, e.g. http://127.0.0.1:8080).
	IPListCrowdSec = "crowdsec"
	// IPListURL reads plain text with one address or prefix per line;
	// "#" and ";" start comments. CrowdSec blocklist integrations serve
	// this, with HTTP basic auth.
	IPListURL = "url"
)

// IPList is a list of addresses and prefixes the agent downloads and
// loads into the nftables sets "<name>_v4" and "<name>_v6" of every
// instance whose rules refer to it. It is downloaded on apply when it
// has not been yet, and whenever a task of kind TaskIPList runs.
type IPList struct {
	Name   string `json:"name"`
	Source string `json:"source"`
	URL    string `json:"url"`
	// Username and Password are HTTP basic auth (URL source).
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	// APIKey is the CrowdSec bouncer key (cscli bouncers add).
	APIKey string `json:"api_key,omitempty"`
}

// IPListRef is the prefix of an IP list reference in a rule's addresses.
const IPListRef = "@"

// IPListName returns the list an address entry refers to, if it is a
// reference.
func IPListName(entry string) (string, bool) {
	return strings.CutPrefix(entry, IPListRef)
}

// IPList returns the named IP list, or nil.
func (d *Document) IPList(name string) *IPList {
	for i := range d.IPLists {
		if d.IPLists[i].Name == name {
			return &d.IPLists[i]
		}
	}
	return nil
}

// UsedIPLists returns the names of the IP lists the instance's rules
// refer to, in order of first use.
func (in *Instance) UsedIPLists() []string {
	var out []string
	for _, r := range in.Rules {
		for _, a := range append(append([]string(nil), r.SrcAddrs...), r.DstAddrs...) {
			if name, ok := IPListName(a); ok && !slices.Contains(out, name) {
				out = append(out, name)
			}
		}
	}
	return out
}

// Task kinds.
const (
	// TaskIPList downloads an IP list again and reloads its sets.
	TaskIPList = "iplist"
	// TaskCommand runs Command with /bin/sh -c as the agent's console
	// user, in the root network namespace. The agent refuses it when its
	// console is off (console_user: none).
	TaskCommand = "command"
)

// DefaultTaskTimeout applies to commands without a Timeout (seconds).
const DefaultTaskTimeout = 3600

// Task is something the agent runs on a cron schedule (see package cron),
// in the firewall's local time. A task does not start again while its
// previous run is still going.
type Task struct {
	Name     string `json:"name"`
	Schedule string `json:"schedule"`
	Kind     string `json:"kind"`
	IPList   string `json:"ip_list,omitempty"`
	Command  string `json:"command,omitempty"`
	// Timeout ends a command after that many seconds; 0 means
	// DefaultTaskTimeout.
	Timeout int `json:"timeout,omitempty"`
}

// ValidURL checks an IP list URL: http or https, a host, no credentials
// (they have their own fields) and nothing that could break a log line.
func ValidURL(s string) error {
	if len(s) > 2048 {
		return fmt.Errorf("longer than 2048 characters")
	}
	if strings.ContainsFunc(s, func(r rune) bool { return r <= ' ' || r == 0x7f }) {
		return fmt.Errorf("contains spaces or control characters")
	}
	u, err := url.Parse(s)
	if err != nil {
		return err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("must start with http:// or https://")
	}
	if u.Host == "" {
		return fmt.Errorf("has no host")
	}
	if u.User != nil {
		return fmt.Errorf("put the username and password in their own fields")
	}
	return nil
}

// PlainTextCredentials tells whether l sends its credentials (API key,
// password) unencrypted across a network: over http:// to a host that is
// not a loopback address. portitor-web refuses to store such a list; the
// agent still takes one, so a configuration made before keeps working.
func PlainTextCredentials(l IPList) bool {
	if l.APIKey == "" && l.Username == "" && l.Password == "" {
		return false
	}
	u, err := url.Parse(l.URL)
	if err != nil || u.Scheme != "http" {
		return false
	}
	host := u.Hostname()
	if host == "localhost" {
		return false
	}
	a, err := netip.ParseAddr(host)
	return err != nil || !a.IsLoopback()
}

func (v *validator) ipLists(lists []IPList) {
	for _, l := range lists {
		lp := fmt.Sprintf("ip list %q", l.Name)
		if !ValidName(l.Name) || strings.HasPrefix(l.Name, "@") {
			v.addf("%s: invalid name", lp)
		}
		if v.lists[l.Name] {
			v.addf("%s: duplicate", lp)
		}
		v.lists[l.Name] = true
		if err := ValidURL(l.URL); err != nil {
			v.addf("%s: url %v", lp, err)
		}
		for _, f := range []struct{ name, value string }{{"username", l.Username}, {"password", l.Password}, {"api key", l.APIKey}} {
			if len(f.value) > 256 {
				v.addf("%s: %s longer than 256 characters", lp, f.name)
			}
			if strings.ContainsFunc(f.value, func(r rune) bool { return r < ' ' || r == 0x7f }) {
				v.addf("%s: %s contains control characters", lp, f.name)
			}
		}
		switch l.Source {
		case IPListURL:
			if strings.Contains(l.Username, ":") {
				v.addf("%s: username cannot contain ':'", lp)
			}
			if l.Password != "" && l.Username == "" {
				v.addf("%s: a password needs a username", lp)
			}
			if l.APIKey != "" {
				v.addf("%s: an api key is for crowdsec lists", lp)
			}
		case IPListCrowdSec:
			if l.APIKey == "" {
				v.addf("%s: crowdsec needs a bouncer api key", lp)
			} else if strings.ContainsAny(l.APIKey, " \t") {
				v.addf("%s: api key contains spaces", lp)
			}
			if l.Username != "" || l.Password != "" {
				v.addf("%s: crowdsec takes an api key, not a username and password", lp)
			}
		default:
			v.addf("%s: invalid source %q", lp, l.Source)
		}
	}
}

func (v *validator) tasks(tasks []Task) {
	names := map[string]bool{}
	for _, t := range tasks {
		tp := fmt.Sprintf("task %q", t.Name)
		if !ValidFileName(t.Name) {
			v.addf("%s: invalid name", tp)
		}
		if names[t.Name] {
			v.addf("%s: duplicate", tp)
		}
		names[t.Name] = true
		if _, err := cron.Parse(t.Schedule); err != nil {
			v.addf("%s: schedule: %v", tp, err)
		}
		switch t.Kind {
		case TaskIPList:
			if !v.lists[t.IPList] {
				v.addf("%s: unknown ip list %q", tp, t.IPList)
			}
			if t.Command != "" || t.Timeout != 0 {
				v.addf("%s: an ip list task has no command or timeout", tp)
			}
		case TaskCommand:
			if strings.TrimSpace(t.Command) == "" {
				v.addf("%s: command is empty", tp)
			}
			if len(t.Command) > 4096 {
				v.addf("%s: command longer than 4096 characters", tp)
			}
			if strings.ContainsRune(t.Command, 0) {
				v.addf("%s: command contains a NUL character", tp)
			}
			if t.IPList != "" {
				v.addf("%s: a command task has no ip list", tp)
			}
			if t.Timeout < 0 || t.Timeout > 86400 {
				v.addf("%s: timeout must be 0-86400 seconds", tp)
			}
		default:
			v.addf("%s: invalid kind %q", tp, t.Kind)
		}
	}
}
