// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package dyndns keeps DNS records on an authoritative nameserver in step
// with a network interface's addresses, by RFC 2136 UPDATE (optionally
// signed with TSIG). It is ifnsupdate (github.com/abundo/ifnsupdate) as a
// library: the caller supplies the interface's addresses, address change
// events and a way to reach the nameserver, so the agent can run it inside
// an instance's network namespace.
//
// A and AAAA records without a value follow the interface. Records with a
// value, and CNAMEs, are static: verified at start and then every
// VerifyInterval. A TXT record without a value holds the time of the last
// update. Records are only updated when a query shows they differ; an
// update replaces the whole RRset and is verified by querying again.
package dyndns

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/abundo/portitor/internal/fwconfig"
)

const (
	defaultRetryInterval  = 5 * time.Minute
	defaultVerifyInterval = time.Hour
	defaultTTL            = 300
	// maxUpdateAttempts is the number of UPDATE+verify cycles before giving
	// up on a single reconcile (the event loop then schedules a retry).
	maxUpdateAttempts = 2
	timeout           = 10 * time.Second
)

// recordScope selects which configured records a reconcile pass considers.
type recordScope int

const (
	scopeAll recordScope = iota
	scopeDynamic
	scopeStatic
)

// Config is a validated, normalised client configuration.
type Config struct {
	Server         string // ip:port
	Zone           string // FQDN with the trailing dot
	TSIG           *fwconfig.TSIG
	Records        []Record
	RetryInterval  time.Duration
	VerifyInterval time.Duration
}

// Record is a DNS name to maintain; Name is an FQDN with the trailing dot.
//
// A/AAAA without value are filled from the interface.
// A/AAAA with value, CNAME, and TXT with value are static.
// TXT without value is a last-update timestamp (RFC 3339).
type Record struct {
	Name  string
	Type  string
	TTL   uint32
	Value string
}

// isTimestamp reports whether r is a last-update TXT (type TXT, no value).
// Its RDATA is set to the current UTC time whenever an UPDATE runs.
func (r Record) isTimestamp() bool {
	return r.Type == "TXT" && r.Value == ""
}

// isStatic reports whether r is not derived from the interface address and
// is not a last-update timestamp.
func (r Record) isStatic() bool {
	switch r.Type {
	case "CNAME":
		return true
	case "TXT", "A", "AAAA":
		return r.Value != ""
	default:
		return false
	}
}

// NewConfig normalises a document's client: absolute names, default TTLs
// and intervals, canonical addresses.
func NewConfig(d fwconfig.DynDNS) (*Config, error) {
	server, err := fwconfig.DynDNSServerAddr(d.Server)
	if err != nil {
		return nil, fmt.Errorf("server: %w", err)
	}
	cfg := &Config{
		Server:         server.String(),
		Zone:           dns.Fqdn(strings.ToLower(d.Zone)),
		RetryInterval:  seconds(d.RetryInterval, defaultRetryInterval),
		VerifyInterval: seconds(d.VerifyInterval, defaultVerifyInterval),
	}
	if d.TSIG != nil {
		t := *d.TSIG
		t.Name = dns.Fqdn(strings.ToLower(t.Name))
		cfg.TSIG = &t
	}
	if len(d.Records) == 0 {
		return nil, fmt.Errorf("at least one record is required")
	}
	for i, r := range d.Records {
		name, err := fwconfig.DynDNSOwner(r.Name, cfg.Zone)
		if err != nil {
			return nil, fmt.Errorf("records[%d].name: %w", i, err)
		}
		rec := Record{Name: name, Type: strings.ToUpper(strings.TrimSpace(r.Type)), TTL: uint32(r.TTL), Value: strings.TrimSpace(r.Value)}
		if rec.TTL == 0 {
			rec.TTL = defaultTTL
		}
		switch rec.Type {
		case "A", "AAAA":
			if rec.Value != "" {
				ip := net.ParseIP(rec.Value)
				if ip == nil || (rec.Type == "A") != (ip.To4() != nil) {
					return nil, fmt.Errorf("records[%d].value is not an address for type %s", i, rec.Type)
				}
				rec.Value = ip.String()
			}
		case "CNAME":
			if rec.Value == "" {
				return nil, fmt.Errorf("records[%d].value is required for CNAME", i)
			}
			// Absolute targets may point outside the zone; relative ones
			// are names in it.
			if !strings.HasSuffix(rec.Value, ".") {
				if rec.Value, err = fwconfig.DynDNSOwner(rec.Value, cfg.Zone); err != nil {
					return nil, fmt.Errorf("records[%d].value: %w", i, err)
				}
			}
		case "TXT":
			// Empty value: last-update timestamp. Non-empty: static string.
		default:
			return nil, fmt.Errorf("records[%d].type must be A, AAAA, CNAME, or TXT", i)
		}
		cfg.Records = append(cfg.Records, rec)
	}
	return cfg, nil
}

func seconds(n int, def time.Duration) time.Duration {
	if n <= 0 {
		return def
	}
	return time.Duration(n) * time.Second
}

// Env is what a client needs from where it runs.
type Env struct {
	// Addrs returns the interface's first global IPv4 and IPv6 address
	// (nil when it has none).
	Addrs func() (v4, v6 net.IP, err error)
	// Exchange sends m to the nameserver at addr with c and returns the
	// reply. Nil uses c.Exchange.
	Exchange func(c *dns.Client, m *dns.Msg, addr string) (*dns.Msg, error)
	Log      *slog.Logger
	// Now is the clock for timestamp TXT records; nil is time.Now.
	Now func() time.Time
	// VerifyDelay is the wait after an UPDATE before querying to confirm
	// it; 0 is 2 seconds, negative none.
	VerifyDelay time.Duration
}

// Status is a client's state, for the agent status.
type Status struct {
	// State: starting, ok, error.
	State string `json:"state"`
	// IPv4 and IPv6 are the interface addresses last published.
	IPv4 string `json:"ipv4,omitempty"`
	IPv6 string `json:"ipv6,omitempty"`
	// LastCheck is the last time DNS was verified, LastUpdate the last
	// UPDATE the nameserver accepted.
	LastCheck  *time.Time `json:"last_check,omitempty"`
	LastUpdate *time.Time `json:"last_update,omitempty"`
	LastError  string     `json:"last_error,omitempty"`
	NextRetry  *time.Time `json:"next_retry,omitempty"`
}

// lastIPs is the last successfully published addresses.
type lastIPs struct {
	v4, v6 net.IP
}

type Client struct {
	cfg *Config
	env Env
	log *slog.Logger

	mu     sync.Mutex
	status Status
}

func New(cfg *Config, env Env) *Client {
	if env.Exchange == nil {
		env.Exchange = func(c *dns.Client, m *dns.Msg, addr string) (*dns.Msg, error) {
			r, _, err := c.Exchange(m, addr)
			return r, err
		}
	}
	if env.Now == nil {
		env.Now = time.Now
	}
	if env.VerifyDelay == 0 {
		env.VerifyDelay = 2 * time.Second
	}
	if env.Log == nil {
		env.Log = slog.Default()
	}
	return &Client{cfg: cfg, env: env, log: env.Log, status: Status{State: "starting"}}
}

func (c *Client) Status() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.status
}

func (c *Client) setStatus(fn func(s *Status)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	fn(&c.status)
}

// timestampTXTValue returns the RDATA for a last-update timestamp TXT.
func (c *Client) timestampTXTValue() string {
	return c.env.Now().UTC().Format(time.RFC3339)
}

func filterRecords(recs []Record, scope recordScope) []Record {
	if scope == scopeAll {
		return recs
	}
	out := make([]Record, 0, len(recs))
	for _, r := range recs {
		// Last-update timestamps ride along with every reconcile scope so any
		// successful UPDATE refreshes the "when last updated" marker.
		if r.isTimestamp() {
			out = append(out, r)
			continue
		}
		static := r.isStatic()
		if scope == scopeStatic && static {
			out = append(out, r)
		}
		if scope == scopeDynamic && !static {
			out = append(out, r)
		}
	}
	return out
}

func hasStaticRecords(cfg *Config) bool {
	for _, r := range cfg.Records {
		if r.isStatic() {
			return true
		}
	}
	return false
}

// expectedIP returns the address that should be published for an A/AAAA
// record, or nil if none is available on the interface.
func expectedIP(rec Record, v4, v6 net.IP) net.IP {
	if rec.isStatic() {
		return net.ParseIP(rec.Value)
	}
	switch rec.Type {
	case "A":
		return v4
	case "AAAA":
		return v6
	default:
		return nil
	}
}

// buildRR constructs the dns.RR to publish for rec.
func (c *Client) buildRR(rec Record, v4, v6 net.IP) (dns.RR, string, error) {
	var rdata, rrStr string
	switch rec.Type {
	case "A", "AAAA":
		ip := expectedIP(rec, v4, v6)
		if ip == nil {
			return nil, "", fmt.Errorf("no %s address on interface for %s", rec.Type, rec.Name)
		}
		rdata = ip.String()
		rrStr = fmt.Sprintf("%s %d IN %s %s", rec.Name, rec.TTL, rec.Type, rdata)
	case "CNAME":
		rdata = rec.Value
		rrStr = fmt.Sprintf("%s %d IN CNAME %s", rec.Name, rec.TTL, rdata)
	case "TXT":
		rdata = rec.Value
		if rec.isTimestamp() {
			rdata = c.timestampTXTValue()
		}
		// Quote so spaces and special characters are valid presentation format.
		rrStr = fmt.Sprintf("%s %d IN TXT %q", rec.Name, rec.TTL, rdata)
	default:
		return nil, "", fmt.Errorf("unsupported type %q", rec.Type)
	}
	rr, err := dns.NewRR(rrStr)
	if err != nil {
		return nil, "", fmt.Errorf("invalid RR %q: %w", rrStr, err)
	}
	return rr, rdata, nil
}

// dnsQuery exchanges a non-recursive query against the nameserver.
func (c *Client) dnsQuery(name string, qtype uint16) (*dns.Msg, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), qtype)
	msg.RecursionDesired = false

	resp, err := c.env.Exchange(&dns.Client{Net: "udp", Timeout: timeout}, msg, c.cfg.Server)
	if err != nil {
		return nil, fmt.Errorf("DNS query %s %s: %w", name, dns.TypeToString[qtype], err)
	}
	if resp.Rcode == dns.RcodeNameError {
		return nil, nil
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("DNS query %s %s rejected: %s", name, dns.TypeToString[qtype], dns.RcodeToString[resp.Rcode])
	}
	return resp, nil
}

// recordMatches reports whether the nameserver already has exactly the
// expected RDATA for rec.
func (c *Client) recordMatches(rec Record, v4, v6 net.IP) (bool, error) {
	qtype := dns.StringToType[rec.Type]
	resp, err := c.dnsQuery(rec.Name, qtype)
	if err != nil || resp == nil {
		return false, err // resp nil: NXDOMAIN
	}
	var got []string
	for _, rr := range resp.Answer {
		if rr.Header().Rrtype != qtype {
			continue
		}
		switch r := rr.(type) {
		case *dns.A:
			got = append(got, r.A.String())
		case *dns.AAAA:
			got = append(got, r.AAAA.String())
		case *dns.CNAME:
			got = append(got, strings.ToLower(r.Target))
		case *dns.TXT:
			// Concatenated character-strings.
			got = append(got, strings.Join(r.Txt, ""))
		}
	}
	if len(got) != 1 {
		return false, nil
	}
	switch rec.Type {
	case "A", "AAAA":
		want := expectedIP(rec, v4, v6)
		return want != nil && net.ParseIP(got[0]).Equal(want), nil
	case "CNAME":
		return got[0] == strings.ToLower(rec.Value), nil
	case "TXT":
		// Timestamp TXT: any single existing RR is fine. It is only
		// rewritten when some other record in the same UPDATE needs fixing
		// (or it is missing), so it still means "last update time".
		return rec.isTimestamp() || got[0] == rec.Value, nil
	}
	return false, fmt.Errorf("unsupported type %q", rec.Type)
}

// recordsNeedUpdate queries each record in recs and returns true if any
// does not already match. A missing interface address for a dynamic
// A/AAAA, and query failures, count as needing an update.
func (c *Client) recordsNeedUpdate(recs []Record, v4, v6 net.IP) bool {
	need := false
	for _, rec := range recs {
		if (rec.Type == "A" || rec.Type == "AAAA") && expectedIP(rec, v4, v6) == nil {
			c.log.Info("dyndns record needs update", "name", rec.Name, "type", rec.Type, "reason", "no matching address on interface")
			need = true
			continue
		}
		ok, err := c.recordMatches(rec, v4, v6)
		if err != nil {
			c.log.Warn("dyndns verify query failed; will update", "name", rec.Name, "type", rec.Type, "err", err)
			need = true
			continue
		}
		if !ok {
			want := rec.Value
			if ip := expectedIP(rec, v4, v6); ip != nil {
				want = ip.String()
			} else if rec.isTimestamp() {
				want = "(timestamp)"
			}
			c.log.Info("dyndns record incorrect or missing", "name", rec.Name, "type", rec.Type, "want", want)
			need = true
			continue
		}
		c.log.Debug("dyndns record already correct", "name", rec.Name, "type", rec.Type)
	}
	return need
}

// updateAndVerify sends a DNS UPDATE for recs, waits briefly, then confirms
// the nameserver reflects it. If not, the UPDATE is retried once.
func (c *Client) updateAndVerify(ctx context.Context, recs []Record, v4, v6 net.IP) error {
	for attempt := 1; attempt <= maxUpdateAttempts; attempt++ {
		if err := c.performUpdate(recs, v4, v6); err != nil {
			return err
		}
		now := c.env.Now()
		c.setStatus(func(s *Status) { s.LastUpdate = &now })
		if c.env.VerifyDelay > 0 && !sleepCtx(ctx, c.env.VerifyDelay) {
			return ctx.Err()
		}
		if !c.recordsNeedUpdate(recs, v4, v6) {
			c.log.Info("dyndns post-update verify succeeded")
			return nil
		}
		if attempt < maxUpdateAttempts {
			c.log.Warn("dyndns post-update verify failed; retrying update", "attempt", attempt)
		}
	}
	return fmt.Errorf("DNS update not reflected in queries after %d attempts", maxUpdateAttempts)
}

// reconcile re-reads the interface addresses and makes DNS match them for
// scope.
//
// Without force, a dynamic or full pass whose addresses equal last is a
// no-op (static passes always check). force is for the initial sync,
// retries and pending failures. alwaysUpdate sends an UPDATE even when the
// records already match.
//
// last advances only when dynamic records are in scope and DNS matches.
func (c *Client) reconcile(ctx context.Context, last *lastIPs, force bool, scope recordScope, alwaysUpdate bool) error {
	v4, v6, err := c.env.Addrs()
	if err != nil {
		return err
	}
	recs := filterRecords(c.cfg.Records, scope)
	if len(recs) == 0 {
		return nil
	}
	// Address-driven early exit only when interface-sourced records count.
	if scope != scopeStatic && !force && !alwaysUpdate && v4.Equal(last.v4) && v6.Equal(last.v6) {
		return nil
	}
	if scope != scopeStatic {
		if !v4.Equal(last.v4) {
			c.log.Info("dyndns IPv4 changed", "old", last.v4, "new", v4)
		}
		if !v6.Equal(last.v6) {
			c.log.Info("dyndns IPv6 changed", "old", last.v6, "new", v6)
		}
	}
	now := c.env.Now()
	c.setStatus(func(s *Status) { s.LastCheck = &now })

	if alwaysUpdate || c.recordsNeedUpdate(recs, v4, v6) {
		if err := c.updateAndVerify(ctx, recs, v4, v6); err != nil {
			return err
		}
	} else if scope == scopeStatic {
		c.log.Debug("dyndns static records already correct")
	} else {
		c.log.Debug("dyndns records already match")
	}
	if scope != scopeStatic {
		last.v4, last.v6 = v4, v6
		c.setStatus(func(s *Status) { s.IPv4, s.IPv6 = ipString(v4), ipString(v6) })
	}
	return nil
}

func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

// Run keeps DNS in step until ctx is done. A receive on addrChanged means
// the interface's addresses may have changed. After a failure it retries
// every RetryInterval, re-reading the addresses each time; address changes
// are applied at once, also while a retry is pending. Static records are
// verified at start and then every VerifyInterval.
func (c *Client) Run(ctx context.Context, addrChanged <-chan struct{}) {
	last := &lastIPs{}
	pending := false // true after a failed reconcile until the next success

	retry := time.NewTimer(0)
	stopTimer(retry)
	defer retry.Stop()
	var retryC <-chan time.Time

	apply := func(force bool, scope recordScope) {
		err := c.reconcile(ctx, last, force, scope, false)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			c.log.Error("dyndns update failed", "err", err, "retry_in", c.cfg.RetryInterval)
			pending = true
			stopTimer(retry)
			retry.Reset(c.cfg.RetryInterval)
			retryC = retry.C
			next := c.env.Now().Add(c.cfg.RetryInterval)
			c.setStatus(func(s *Status) { s.State, s.LastError, s.NextRetry = "error", err.Error(), &next })
			return
		}
		if scope == scopeStatic && pending {
			return // a dynamic failure is still unresolved
		}
		pending = false
		stopTimer(retry)
		retryC = nil
		c.setStatus(func(s *Status) { s.State, s.LastError, s.NextRetry = "ok", "", nil })
	}

	// Initial sync: always verify dynamic and static records.
	apply(true, scopeAll)

	var verifyC <-chan time.Time
	if hasStaticRecords(c.cfg) {
		t := time.NewTicker(c.cfg.VerifyInterval)
		defer t.Stop()
		verifyC = t.C
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-addrChanged:
			// With a retry pending, re-attempt everything even when the
			// addresses equal the last successful publish.
			if pending {
				apply(true, scopeAll)
			} else {
				apply(false, scopeDynamic)
			}
		case <-retryC:
			retryC = nil
			c.log.Info("dyndns retrying update")
			apply(true, scopeAll)
		case <-verifyC:
			apply(true, scopeStatic)
		}
	}
}

// stopTimer stops t and drains its channel if the timer already fired.
func stopTimer(t *time.Timer) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// Sync verifies all records once and updates those that differ; with
// force it sends an UPDATE even when they match.
func (c *Client) Sync(ctx context.Context, force bool) error {
	return c.reconcile(ctx, &lastIPs{}, true, scopeAll, force)
}

func (c *Client) performUpdate(recs []Record, v4, v6 net.IP) error {
	msg := new(dns.Msg)
	msg.SetUpdate(c.cfg.Zone)
	for _, rec := range recs {
		rr, rdata, err := c.buildRR(rec, v4, v6)
		if err != nil {
			return err
		}
		// Classic dynamic update: delete the RRset, then insert the record.
		msg.RemoveRRset([]dns.RR{rr})
		msg.Insert([]dns.RR{rr})
		c.log.Info("dyndns will update", "name", rec.Name, "type", rec.Type, "rdata", rdata)
	}
	return c.exchangeUpdate(msg)
}

// exchangeUpdate sends a prepared UPDATE (with TSIG when configured) and
// checks for a successful reply.
func (c *Client) exchangeUpdate(msg *dns.Msg) error {
	client := &dns.Client{Net: "udp", Timeout: timeout}
	if t := c.cfg.TSIG; t != nil {
		client.TsigSecret = map[string]string{t.Name: t.Secret}
		msg.SetTsig(t.Name, mapAlgorithm(t.Algorithm), 300, c.env.Now().Unix())
	}
	resp, err := c.env.Exchange(client, msg, c.cfg.Server)
	if err != nil {
		return fmt.Errorf("DNS update: %w", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("DNS update rejected: %s", dns.RcodeToString[resp.Rcode])
	}
	c.log.Info("dyndns UPDATE successful")
	return nil
}

func mapAlgorithm(name string) string {
	switch strings.ToLower(name) {
	case "hmac-md5":
		return dns.HmacMD5
	case "hmac-sha1":
		return dns.HmacSHA1
	case "hmac-sha224":
		return dns.HmacSHA224
	case "hmac-sha384":
		return dns.HmacSHA384
	case "hmac-sha512":
		return dns.HmacSHA512
	default:
		return dns.HmacSHA256
	}
}
