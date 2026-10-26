// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package fwconfig

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// DNS blocklist actions: BIND's response policy for the names of a list
// (response-policy zone ... policy).
const (
	BlocklistNXDomain = "nxdomain" // the name does not exist
	BlocklistNoData   = "nodata"   // the name exists, without records of the type asked
	BlocklistDrop     = "drop"     // no answer at all
	// BlocklistLog answers as usual and only logs the names it would
	// block (policy disabled).
	BlocklistLog = "log"
)

const (
	// BlocklistKeyPlaceholder in a blocklist's URL is replaced by its
	// Key (URLhaus puts the account's key in the path).
	BlocklistKeyPlaceholder = "{key}"
	// DefaultBlocklistRefresh is the minutes between downloads when a
	// blocklist names none.
	DefaultBlocklistRefresh = 720
	// MaxBlocklistURLs is the most URLs one blocklist reads (Hagezi's
	// full TIF list comes in two files).
	MaxBlocklistURLs = 4
	// MaxBlocklists is the most blocklists an instance may have.
	MaxBlocklists = 32
)

var (
	blocklistNameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$`)
	blocklistKeyRe  = regexp.MustCompile(`^[A-Za-z0-9._~-]{1,256}$`)
)

// DNSBlocklist is a list of domains that the instance's DNS server
// refuses to resolve: a response policy zone (RPZ) in BIND, which the
// agent downloads from URLs and keeps current every Refresh minutes. A
// download is an RPZ zone file or a plain list of domains (see package
// dnsblocklist); only its names reach BIND, each answered by Action.
type DNSBlocklist struct {
	Name string   `json:"name"`
	URLs []string `json:"urls"`
	// Key replaces BlocklistKeyPlaceholder in the URLs.
	Key     string `json:"key,omitempty"`
	Action  string `json:"action"`
	Refresh int    `json:"refresh,omitempty"` // minutes; 0: DefaultBlocklistRefresh
}

// RefreshMinutes is the minutes between downloads.
func (b DNSBlocklist) RefreshMinutes() int {
	if b.Refresh == 0 {
		return DefaultBlocklistRefresh
	}
	return b.Refresh
}

// FetchURLs are the URLs with the key filled in.
func (b DNSBlocklist) FetchURLs() []string {
	out := make([]string, len(b.URLs))
	for i, u := range b.URLs {
		out[i] = strings.ReplaceAll(u, BlocklistKeyPlaceholder, b.Key)
	}
	return out
}

// RPZZone is the name of the blocklist's response policy zone in BIND;
// "invalid" (RFC 6761) keeps it from shadowing a real name.
func (b DNSBlocklist) RPZZone() string { return b.Name + ".rpz.invalid" }

// RPZAllowZone is the response policy zone of DNSServer.BlocklistAllow.
// Its first label can't be a blocklist's name (they have no "_").
const RPZAllowZone = "_allow.rpz.invalid"

// ValidBlocklistName checks a blocklist's name: a DNS label of lowercase
// letters, digits and '-', at most 32 characters. It names the RPZ zone
// and its file.
func ValidBlocklistName(s string) bool { return blocklistNameRe.MatchString(s) }

// ValidBlocklistKey checks a blocklist's key, which goes into a URL.
func ValidBlocklistKey(s string) bool { return blocklistKeyRe.MatchString(s) }

// CheckBlocklistURL checks one URL of a blocklist: an http(s) URL
// (ValidURL) once its key is in, which goes over https.
func CheckBlocklistURL(u string, hasKey bool) error {
	keyed := strings.Contains(u, BlocklistKeyPlaceholder)
	if err := ValidURL(strings.ReplaceAll(u, BlocklistKeyPlaceholder, "key")); err != nil {
		return err
	}
	if keyed && !hasKey {
		return fmt.Errorf("has %s but the blocklist has no key", BlocklistKeyPlaceholder)
	}
	if p, err := url.Parse(u); keyed && err == nil && p.Scheme != "https" {
		return fmt.Errorf("would send the key unencrypted: use https://")
	}
	return nil
}

func (v *validator) dnsBlocklists(p string, d *DNSServer) {
	if len(d.Blocklists) > MaxBlocklists {
		v.addf("%s: dns: more than %d blocklists", p, MaxBlocklists)
	}
	seen := map[string]bool{}
	for _, b := range d.Blocklists {
		bp := fmt.Sprintf("%s: dns blocklist %q", p, b.Name)
		if !ValidBlocklistName(b.Name) {
			v.addf("%s: invalid name (lowercase letters, digits and '-', at most 32)", bp)
		}
		if seen[b.Name] {
			v.addf("%s: duplicate", bp)
		}
		seen[b.Name] = true
		if len(b.URLs) == 0 || len(b.URLs) > MaxBlocklistURLs {
			v.addf("%s: needs 1 to %d urls", bp, MaxBlocklistURLs)
		}
		keyed := false
		for _, u := range b.URLs {
			if err := CheckBlocklistURL(u, b.Key != ""); err != nil {
				v.addf("%s: url %v", bp, err)
			}
			keyed = keyed || strings.Contains(u, BlocklistKeyPlaceholder)
		}
		if b.Key != "" && !ValidBlocklistKey(b.Key) {
			v.addf("%s: invalid key (letters, digits and ._~-, at most 256)", bp)
		}
		if b.Key != "" && !keyed {
			v.addf("%s: a key needs %s in a url", bp, BlocklistKeyPlaceholder)
		}
		switch b.Action {
		case BlocklistNXDomain, BlocklistNoData, BlocklistDrop, BlocklistLog:
		default:
			v.addf("%s: invalid action %q", bp, b.Action)
		}
		if b.Refresh != 0 && (b.Refresh < 5 || b.Refresh > 10080) {
			v.addf("%s: refresh must be 5-10080 minutes", bp)
		}
	}
	for _, n := range d.BlocklistAllow {
		if !validDomain(n) {
			v.addf("%s: dns: blocklist allow: invalid domain %q", p, n)
		}
	}
}
