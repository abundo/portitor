// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package iplist downloads the addresses of an fwconfig.IPList: the ban
// decisions of a CrowdSec Local API, or a plain-text list with one
// address or prefix per line.
package iplist

import (
	"bufio"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"slices"
	"strings"

	"github.com/abundo/portitor/internal/fwconfig"
)

const (
	// MaxBody limits a download.
	MaxBody = 64 << 20
	// MaxEntries limits a list: every entry costs kernel memory in each
	// instance that uses it.
	MaxEntries = 1_000_000
)

// Result is a downloaded list.
type Result struct {
	// Prefixes are normalized (Normalize).
	Prefixes []netip.Prefix
	// Skipped counts entries that are not an address or prefix, and
	// CrowdSec decisions that are not an IP or range ban.
	Skipped int
}

// Fetch downloads the list with client.
func Fetch(ctx context.Context, client *http.Client, l fwconfig.IPList, userAgent string) (*Result, error) {
	u := l.URL
	if l.Source == fwconfig.IPListCrowdSec {
		// startup=true returns every active decision, not only the
		// changes since this bouncer's last pull.
		u = strings.TrimRight(u, "/") + "/v1/decisions/stream?startup=true&scopes=ip,range"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	switch {
	case l.Source == fwconfig.IPListCrowdSec:
		req.Header.Set("X-Api-Key", l.APIKey)
		req.Header.Set("Accept", "application/json")
	case l.Username != "":
		req.SetBasicAuth(l.Username, l.Password)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("%s: %s", resp.Status, firstLine(string(msg)))
	}
	body := &limitedReader{r: resp.Body, left: MaxBody}
	if l.Source == fwconfig.IPListCrowdSec {
		return ParseCrowdSec(body)
	}
	return ParseText(body)
}

// ParseText reads one address or prefix per line. "#" and ";" start a
// comment, and only the first word of a line counts, so lists such as
// Spamhaus DROP ("192.0.2.0/24 ; SBL123") read as they are.
func ParseText(r io.Reader) (*Result, error) {
	res := &Result{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 64<<10)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if err := res.add(fields[0]); err != nil {
			return nil, err
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	res.Prefixes = Normalize(res.Prefixes)
	return res, nil
}

// crowdsecStream is the Local API's GET /v1/decisions/stream answer.
type crowdsecStream struct {
	New []struct {
		Scope string `json:"scope"`
		Type  string `json:"type"`
		Value string `json:"value"`
	} `json:"new"`
}

// ParseCrowdSec reads the ban decisions for IPs and ranges from a
// decision stream.
func ParseCrowdSec(r io.Reader) (*Result, error) {
	var st crowdsecStream
	if err := json.NewDecoder(r).Decode(&st); err != nil {
		return nil, fmt.Errorf("decision stream: %w", err)
	}
	res := &Result{}
	for _, d := range st.New {
		scope := strings.ToLower(d.Scope)
		if !strings.EqualFold(d.Type, "ban") || (scope != "ip" && scope != "range") {
			res.Skipped++
			continue
		}
		if err := res.add(d.Value); err != nil {
			return nil, err
		}
	}
	res.Prefixes = Normalize(res.Prefixes)
	return res, nil
}

func (res *Result) add(s string) error {
	p, err := fwconfig.ParseAddrOrPrefix(s)
	// A zone (fe80::1%eth0) is dropped by the parser; refuse it.
	if err != nil || strings.Contains(s, "%") {
		res.Skipped++
		return nil
	}
	if len(res.Prefixes) >= MaxEntries {
		return fmt.Errorf("more than %d entries", MaxEntries)
	}
	res.Prefixes = append(res.Prefixes, p)
	return nil
}

// Normalize returns the prefixes masked, IPv4-mapped IPv6 as IPv4, sorted
// (IPv4 first) and without duplicates or prefixes inside another one.
func Normalize(list []netip.Prefix) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(list))
	for _, p := range list {
		a := p.Addr()
		bits := p.Bits()
		if a.Is4In6() {
			a, bits = a.Unmap(), max(bits-96, 0)
		}
		out = append(out, netip.PrefixFrom(a, bits).Masked())
	}
	slices.SortFunc(out, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return cmp.Compare(a.Bits(), b.Bits())
	})
	// Sorted by address, then shorter first: a prefix that contains
	// another comes before it, and nested prefixes are never interleaved
	// with others, so comparing with the last one kept suffices.
	kept := out[:0]
	for _, p := range out {
		if n := len(kept); n > 0 {
			last := kept[n-1]
			if last.Addr().Is4() == p.Addr().Is4() && last.Bits() <= p.Bits() && last.Contains(p.Addr()) {
				continue
			}
		}
		kept = append(kept, p)
	}
	return kept
}

// limitedReader fails, rather than truncates, past its limit: a cut-off
// list would silently drop entries.
type limitedReader struct {
	r    io.Reader
	left int64
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.left <= 0 {
		return 0, fmt.Errorf("list is larger than %d MiB", MaxBody>>20)
	}
	if int64(len(p)) > l.left {
		p = p[:l.left]
	}
	n, err := l.r.Read(p)
	l.left -= int64(n)
	return n, err
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	if len(s) > 200 {
		s = s[:200]
	}
	return strings.Map(func(r rune) rune {
		if r < ' ' || r == 0x7f {
			return -1
		}
		return r
	}, s)
}
