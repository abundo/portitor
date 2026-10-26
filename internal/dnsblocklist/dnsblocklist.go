// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package dnsblocklist downloads the names of an fwconfig.DNSBlocklist and
// writes them as the records of a response policy zone (RPZ) for BIND.
//
// A download is untrusted: it is never handed to BIND as it is (a zone
// file could $INCLUDE a file of the host, or redirect a name to another
// one). Only its names are kept, each checked to be a domain or a
// wildcard, and written as "name CNAME ." (the zone's policy decides the
// answer).
package dnsblocklist

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/iplist"
)

const (
	// MaxBody limits one download (and the files of a zip archive).
	MaxBody = 512 << 20
	// MaxNames limits a blocklist: every name costs memory in BIND.
	// Hagezi's full TIF list has over 4 million.
	MaxNames = 6_000_000
	// maxName leaves room in a name for the zone it goes in
	// (fwconfig.DNSBlocklist.RPZZone) within DNS's 253 characters.
	maxName = 210
)

// Validator is what a server said about a URL's content, for a
// conditional request the next time.
type Validator struct {
	ETag         string `json:"etag,omitempty"`
	LastModified string `json:"last_modified,omitempty"`
}

// Result is a download.
type Result struct {
	// NotModified: every URL answered 304 Not Modified; nothing was
	// written.
	NotModified bool
	// Names counts the records written; Skipped the entries that are not
	// a name to block (other records, IP triggers, passthru).
	Names, Skipped int
	// Validators are the URLs', in order.
	Validators []Validator
}

// NewClient returns the HTTP client for Fetch: it follows a redirect only
// where the key stays safe (iplist.CheckRedirect).
func NewClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, CheckRedirect: iplist.CheckRedirect}
}

// Fetch downloads b's URLs into files in tmpDir and writes their names to
// w as RPZ records (WriteHeader writes the zone's start). With the
// validators of the last download it asks for changed content only: when
// every URL is unchanged, nothing is written; when some are, those that
// are not are downloaded again in full.
func Fetch(ctx context.Context, client *http.Client, b fwconfig.DNSBlocklist, prev []Validator, userAgent, tmpDir string, w io.Writer) (*Result, error) {
	urls := b.FetchURLs()
	if len(prev) != len(urls) {
		prev = nil
	}
	res := &Result{Validators: make([]Validator, len(urls))}
	files := make([]*os.File, len(urls))
	defer func() {
		for _, f := range files {
			if f != nil {
				f.Close()
				os.Remove(f.Name())
			}
		}
	}()
	changed := false
	for i, u := range urls {
		var cond Validator
		if prev != nil {
			cond = prev[i]
		}
		f, v, err := download(ctx, client, u, cond, userAgent, tmpDir)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", redact(u, b), redactErr(err, b))
		}
		files[i], res.Validators[i] = f, v
		changed = changed || f != nil
	}
	if !changed {
		res.NotModified = true
		return res, nil
	}
	for i, u := range urls {
		if files[i] != nil {
			continue
		}
		f, v, err := download(ctx, client, u, Validator{}, userAgent, tmpDir)
		if err == nil && f == nil {
			err = errors.New("304 Not Modified to an unconditional request")
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", redact(u, b), redactErr(err, b))
		}
		files[i], res.Validators[i] = f, v
	}
	bw := bufio.NewWriterSize(w, 256<<10)
	for i, f := range files {
		if err := parseFile(f, bw, res); err != nil {
			return nil, fmt.Errorf("%s: %w", redact(urls[i], b), err)
		}
	}
	if res.Names == 0 && res.Skipped > 0 {
		return nil, fmt.Errorf("not a blocklist: none of its %d entries is a domain to block", res.Skipped)
	}
	return res, bw.Flush()
}

// redact hides a blocklist's key in what is logged and shown.
func redact(s string, b fwconfig.DNSBlocklist) string {
	if b.Key == "" {
		return s
	}
	return strings.ReplaceAll(s, b.Key, "<key>")
}

func redactErr(err error, b fwconfig.DNSBlocklist) error {
	if b.Key == "" || !strings.Contains(err.Error(), b.Key) {
		return err
	}
	return errors.New(redact(err.Error(), b))
}

// download gets u into a file in tmpDir, or nil when it is not modified
// since cond.
func download(ctx context.Context, client *http.Client, u string, cond Validator, userAgent, tmpDir string) (*os.File, Validator, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, Validator{}, err
	}
	req.Header.Set("User-Agent", userAgent)
	if cond.ETag != "" {
		req.Header.Set("If-None-Match", cond.ETag)
	}
	if cond.LastModified != "" {
		req.Header.Set("If-Modified-Since", cond.LastModified)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, Validator{}, err
	}
	defer resp.Body.Close()
	v := Validator{ETag: resp.Header.Get("ETag"), LastModified: resp.Header.Get("Last-Modified")}
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotModified:
		if cond == (Validator{}) {
			return nil, v, nil
		}
		// A 304 may leave the validators out; the old ones still hold.
		if v == (Validator{}) {
			v = cond
		}
		return nil, v, nil
	default:
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, Validator{}, fmt.Errorf("%s: %s", resp.Status, firstLine(string(msg)))
	}
	f, err := os.CreateTemp(tmpDir, "blocklist-")
	if err != nil {
		return nil, Validator{}, err
	}
	if _, err := io.Copy(f, &limitedReader{r: resp.Body, left: MaxBody}); err != nil {
		f.Close()
		os.Remove(f.Name())
		return nil, Validator{}, err
	}
	return f, v, nil
}

// parseFile parses a downloaded file, which may be a zip archive (each
// of its files is read).
func parseFile(f *os.File, w *bufio.Writer, res *Result) error {
	magic := make([]byte, 4)
	n, _ := f.ReadAt(magic, 0)
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if !bytes.Equal(magic[:n], []byte("PK\x03\x04")) {
		return Parse(f, w, res)
	}
	st, err := f.Stat()
	if err != nil {
		return err
	}
	zr, err := zip.NewReader(f, st.Size())
	if err != nil {
		return err
	}
	left := int64(MaxBody)
	for _, zf := range zr.File {
		if zf.FileInfo().IsDir() {
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			return err
		}
		lr := &limitedReader{r: rc, left: left}
		err = Parse(lr, w, res)
		rc.Close()
		if err != nil {
			return fmt.Errorf("%s: %w", zf.Name, err)
		}
		left = lr.left
	}
	return nil
}

// rrTypes are the record types Parse recognises in a zone file line;
// only CNAME records are kept.
var rrTypes = map[string]bool{
	"A": true, "AAAA": true, "CAA": true, "CNAME": true, "DNAME": true, "DNSKEY": true, "DS": true,
	"HTTPS": true, "MX": true, "NAPTR": true, "NS": true, "PTR": true, "SOA": true, "SRV": true,
	"SVCB": true, "TXT": true,
}

// blockTargets are the CNAME targets of RPZ records that block (NXDOMAIN,
// NODATA, drop and TCP only); rpz-passthru. and other names are not.
var blockTargets = map[string]bool{".": true, "*.": true, "rpz-drop.": true, "rpz-tcp-only.": true}

// rpzTriggers end the names of the RPZ triggers other than the query
// name (response and client addresses, nameservers).
var rpzTriggers = []string{"rpz-ip", "rpz-nsip", "rpz-nsdname", "rpz-client-ip"}

var labelRe = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$`)

// Parse reads a blocklist and writes "name CNAME ." for each name it
// blocks:
//
//   - an RPZ zone file: its CNAME records whose target blocks (".", "*.",
//     rpz-drop.), with names relative to the zone ($ORIGIN, or relative
//     already), as Hagezi's, URLhaus's and OISD's RPZ files have them;
//   - a list of domains, one per line, or adblock's "||domain^": the
//     domain and every name below it;
//   - a hosts file ("0.0.0.0 domain ..."): the same, for each domain.
//
// ";" and "#" start a comment. Anything else is skipped.
func Parse(r io.Reader, w *bufio.Writer, res *Result) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	origin := ""
	inParens := false
	emit := func(name string) error {
		if res.Names >= MaxNames {
			return fmt.Errorf("more than %d names", MaxNames)
		}
		res.Names++
		w.WriteString(name)
		_, err := w.WriteString(" CNAME .\n")
		return err
	}
	for sc.Scan() {
		raw := sc.Text()
		line := raw
		if i := strings.IndexAny(line, ";#"); i >= 0 {
			line = line[:i]
		}
		// A record over several lines (the SOA): skip it whole.
		if inParens {
			if strings.Contains(line, ")") {
				inParens = false
			}
			continue
		}
		if strings.Contains(line, "(") && !strings.Contains(line, ")") {
			inParens = true
			continue
		}
		fields := strings.Fields(strings.ToLower(line))
		if len(fields) == 0 {
			continue
		}
		if strings.HasPrefix(fields[0], "$") {
			switch {
			case fields[0] == "$origin" && len(fields) == 2:
				origin = strings.TrimSuffix(fields[1], ".")
			case fields[0] == "$ttl":
			default:
				res.Skipped++ // $INCLUDE above all
			}
			continue
		}
		// A zone file record: [owner] [ttl] [class] type rdata, the owner
		// left out when the line starts with a blank.
		blankOwner := raw[0] == ' ' || raw[0] == '\t'
		if t := rrTypeIndex(fields, blankOwner); t >= 0 {
			switch {
			case fields[t] == "soa" || fields[t] == "ns":
			case fields[t] != "cname" || blankOwner || t != len(fields)-2 || !blockTargets[fields[t+1]]:
				res.Skipped++
			default:
				name, ok := zoneName(fields[0], origin)
				if !ok {
					res.Skipped++
					continue
				}
				if err := emit(name); err != nil {
					return err
				}
			}
			continue
		}
		// A list of domains, or a hosts file.
		names := fields[:1]
		if _, err := netip.ParseAddr(fields[0]); err == nil {
			names = fields[1:]
		} else if len(fields) > 1 {
			res.Skipped++
			continue
		}
		for _, n := range names {
			if s, ok := strings.CutPrefix(n, "||"); ok {
				n, _, _ = strings.Cut(s, "^")
			}
			n = strings.TrimSuffix(n, ".")
			wild := strings.HasPrefix(n, "*.")
			if !strings.Contains(n, ".") || !validName(n) {
				res.Skipped++
				continue
			}
			if err := emit(n); err != nil {
				return err
			}
			if !wild {
				if err := emit("*." + n); err != nil {
					return err
				}
			}
		}
	}
	return sc.Err()
}

// rrTypeIndex returns the index of a zone file record's type, or -1 when
// the line is not a record.
func rrTypeIndex(fields []string, blankOwner bool) int {
	i := 1
	if blankOwner {
		i = 0
	}
	for ; i < len(fields); i++ {
		f := fields[i]
		switch {
		case f == "in" || f == "ch" || f == "hs":
		case f[0] >= '0' && f[0] <= '9':
			// A TTL (300, 1h).
		default:
			if rrTypes[strings.ToUpper(f)] {
				return i
			}
			return -1
		}
	}
	return -1
}

// zoneName returns a record's owner relative to the zone, checked.
func zoneName(owner, origin string) (string, bool) {
	if strings.HasSuffix(owner, ".") {
		rel, ok := strings.CutSuffix(strings.TrimSuffix(owner, "."), "."+origin)
		if origin == "" || !ok {
			return "", false
		}
		owner = rel
	}
	labels := strings.Split(owner, ".")
	for _, t := range rpzTriggers {
		if labels[len(labels)-1] == t {
			return "", false
		}
	}
	return owner, validName(owner)
}

// validName checks a name to block: labels of letters, digits, '_' and
// '-', the first of them '*' for a wildcard.
func validName(s string) bool {
	if s == "" || len(s) > maxName {
		return false
	}
	labels := strings.Split(strings.TrimPrefix(s, "*."), ".")
	for _, l := range labels {
		if !labelRe.MatchString(l) {
			return false
		}
	}
	return true
}

// WriteHeader writes the start of a blocklist's zone file: its SOA and
// NS, which BIND needs and RPZ ignores.
func WriteHeader(w io.Writer, name string, serial uint32) error {
	_, err := fmt.Fprintf(w, "; dns blocklist %s. Written by portitor-agent.\n$TTL 300\n@ SOA localhost. root.localhost. %d 3600 600 86400 300\n@ NS localhost.\n", name, serial)
	return err
}

// limitedReader fails, rather than truncates, past its limit: a cut-off
// list would silently drop names.
type limitedReader struct {
	r    io.Reader
	left int64
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.left <= 0 {
		return 0, fmt.Errorf("larger than %d MiB", MaxBody>>20)
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
