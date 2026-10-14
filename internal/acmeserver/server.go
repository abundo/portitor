// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package acmeserver is an ACME server (RFC 8555): the subset ACME
// clients use to get a certificate (accounts, orders, the HTTP-01
// challenge, finalize, the certificate). What a name may be ordered by,
// how a challenge is validated and where the certificate comes from are
// the caller's (Hooks): the agent's ACME proxy checks its policies,
// fetches the token in the instance and orders upstream by DNS-01.
//
// Accounts are kept in a file; orders, authorizations and nonces only in
// memory, so a restart leaves a client to order again.
package acmeserver

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// Hooks are what the server leaves to its caller.
type Hooks struct {
	// Authorize says whether client may order name: nil, or why not.
	Authorize func(name string, client netip.Addr) error
	// Validate checks an HTTP-01 challenge: that
	// http://<name>/.well-known/acme-challenge/<token> answers keyAuth.
	Validate func(ctx context.Context, name, token, keyAuth string, client netip.Addr) error
	// Ordered, when set, is told of each new order's names (sorted), once
	// each is authorized: the proxy starts its upstream authorizations
	// then, while the client answers its challenges.
	Ordered func(names []string, client netip.Addr)
	// Issue gets the certificate of a CSR whose names (sorted) were all
	// authorized and validated: the PEM chain, leaf first.
	Issue func(ctx context.Context, csr *x509.CertificateRequest, names []string, client netip.Addr) ([]byte, error)
}

// Lifetimes of what the server keeps in memory.
const (
	nonceLife = time.Hour
	orderLife = 24 * time.Hour
	// maxNonces and maxOrders cap the memory a client can take.
	maxNonces = 10000
	maxOrders = 10000
	// maxBody is the largest request: a CSR with 100 names fits easily.
	maxBody = 64 << 10
	// maxNames is the most identifiers an order may have.
	maxNames = 100
)

// Timeouts of the work done after answering.
var (
	validateTimeout = time.Minute
	issueTimeout    = 15 * time.Minute
)

// Server is an http.Handler serving the ACME API under /acme/ and its
// directory at /directory.
type Server struct {
	hooks        Hooks
	accountsFile string
	now          func() time.Time

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu       sync.Mutex
	nonces   map[string]time.Time
	accounts map[string]*account // by id
	orders   map[string]*order
	authzs   map[string]*authz
	chals    map[string]*authz // by challenge id
	certs    map[string]*order // by certificate id
}

type account struct {
	ID      string           `json:"id"`
	Key     *jose.JSONWebKey `json:"key"`
	Contact []string         `json:"contact,omitempty"`
	Status  string           `json:"status"`
	Created time.Time        `json:"created"`
}

type order struct {
	id, account string
	client      netip.Addr
	names       []string // sorted
	authzs      []*authz
	status      string // pending, ready, processing, valid, invalid
	expires     time.Time
	err         *problem
	certID      string
	chain       []byte
}

type authz struct {
	id, chalID, account, name, token string
	client                           netip.Addr
	status                           string // pending, valid, invalid
	chalStatus                       string // pending, processing, valid, invalid
	expires, validated               time.Time
	err                              *problem
}

// New returns a server keeping its accounts in accountsFile.
func New(accountsFile string, hooks Hooks) (*Server, error) {
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{
		hooks: hooks, accountsFile: accountsFile, now: time.Now, ctx: ctx, cancel: cancel,
		nonces: map[string]time.Time{}, accounts: map[string]*account{}, orders: map[string]*order{},
		authzs: map[string]*authz{}, chals: map[string]*authz{}, certs: map[string]*order{},
	}
	data, err := os.ReadFile(accountsFile)
	switch {
	case err == nil:
		var list []*account
		if err := json.Unmarshal(data, &list); err != nil {
			cancel()
			return nil, fmt.Errorf("%s: %w", accountsFile, err)
		}
		for _, a := range list {
			if a.Key != nil && a.Key.Valid() {
				s.accounts[a.ID] = a
			}
		}
	case !errors.Is(err, os.ErrNotExist):
		cancel()
		return nil, err
	}
	return s, nil
}

// Close stops the validations and orders running; it waits for them.
func (s *Server) Close() {
	s.cancel()
	s.wg.Wait()
}

// Errors (RFC 8555 6.7).
type problem struct {
	Type   string `json:"type"`
	Detail string `json:"detail"`
	Status int    `json:"status"`
}

func (p *problem) Error() string { return p.Detail }

func prob(status int, typ, format string, args ...any) *problem {
	return &problem{Type: "urn:ietf:params:acme:error:" + typ, Detail: fmt.Sprintf(format, args...), Status: status}
}

var algs = []jose.SignatureAlgorithm{jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512, jose.ES256, jose.ES384, jose.ES512, jose.EdDSA}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	base := "https://" + r.Host
	w.Header().Add("Link", fmt.Sprintf("<%s/directory>;rel=\"index\"", base))
	if r.Method == http.MethodPost || r.URL.Path == "/acme/new-nonce" {
		w.Header().Set("Replay-Nonce", s.newNonce())
	}
	switch {
	case r.URL.Path == "/directory" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{
			"newNonce":   base + "/acme/new-nonce",
			"newAccount": base + "/acme/new-account",
			"newOrder":   base + "/acme/new-order",
			"revokeCert": base + "/acme/revoke-cert",
			"keyChange":  base + "/acme/key-change",
			"meta":       map[string]any{"externalAccountRequired": false},
		})
	case r.URL.Path == "/acme/new-nonce":
		switch r.Method {
		case http.MethodHead:
			w.WriteHeader(http.StatusOK)
		case http.MethodGet:
			w.WriteHeader(http.StatusNoContent)
		default:
			writeProblem(w, prob(http.StatusMethodNotAllowed, "malformed", "use HEAD or GET"))
		}
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/acme/"):
		if err := s.post(w, r, base); err != nil {
			var p *problem
			if !errors.As(err, &p) {
				p = prob(http.StatusInternalServerError, "serverInternal", "%v", err)
			}
			writeProblem(w, p)
		}
	default:
		writeProblem(w, prob(http.StatusNotFound, "malformed", "not found"))
	}
}

// request is a verified JWS request.
type request struct {
	r       *http.Request
	base    string
	payload []byte
	jwk     *jose.JSONWebKey // the new-account request's key
	acct    *account         // the other requests' (kid)
	client  netip.Addr
}

func (s *Server) post(w http.ResponseWriter, r *http.Request, base string) error {
	if ct, _, _ := strings.Cut(r.Header.Get("Content-Type"), ";"); strings.TrimSpace(ct) != "application/jose+json" {
		return prob(http.StatusUnsupportedMediaType, "malformed", "Content-Type must be application/jose+json")
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil {
		return prob(http.StatusBadRequest, "malformed", "%v", err)
	}
	if len(body) > maxBody {
		return prob(http.StatusRequestEntityTooLarge, "malformed", "request too large")
	}
	req, err := s.verify(r, base, body)
	if err != nil {
		return err
	}
	path := r.URL.Path
	switch {
	case path == "/acme/new-account":
		return s.newAccount(w, req)
	case path == "/acme/new-order":
		return s.newOrder(w, req)
	case path == "/acme/revoke-cert" || path == "/acme/key-change":
		return prob(http.StatusForbidden, "unauthorized", "not supported by this server")
	}
	kind, id, _ := strings.Cut(strings.TrimPrefix(path, "/acme/"), "/")
	switch kind {
	case "acct":
		return s.accountReq(w, req, id)
	case "order":
		if oid, ok := strings.CutSuffix(id, "/finalize"); ok {
			return s.finalize(w, req, oid)
		}
		return s.orderReq(w, req, id)
	case "authz":
		return s.authzReq(w, req, id)
	case "chall":
		return s.challengeReq(w, req, id)
	case "cert":
		return s.certReq(w, req, id)
	}
	return prob(http.StatusNotFound, "malformed", "not found")
}

// verify checks a request's JWS (RFC 8555 6.2-6.5): the signature by its
// jwk (new-account) or its account's key (kid), the url and the nonce.
func (s *Server) verify(r *http.Request, base string, body []byte) (*request, error) {
	jws, err := jose.ParseSigned(string(body), algs)
	if err != nil {
		return nil, prob(http.StatusBadRequest, "malformed", "JWS: %v", err)
	}
	if len(jws.Signatures) != 1 {
		return nil, prob(http.StatusBadRequest, "malformed", "JWS: one signature")
	}
	h := jws.Signatures[0].Protected
	url, _ := h.ExtraHeaders["url"].(string)
	if url != base+r.URL.Path {
		return nil, prob(http.StatusUnauthorized, "unauthorized", "JWS url %q is not this request's", url)
	}
	if !s.useNonce(h.Nonce) {
		return nil, prob(http.StatusBadRequest, "badNonce", "unknown or used nonce")
	}
	req := &request{r: r, base: base, client: remoteAddr(r)}
	var key any
	switch {
	case r.URL.Path == "/acme/new-account" || r.URL.Path == "/acme/revoke-cert":
		if h.JSONWebKey == nil || h.KeyID != "" || !h.JSONWebKey.Valid() || !h.JSONWebKey.IsPublic() {
			return nil, prob(http.StatusBadRequest, "malformed", "JWS: needs a public jwk and no kid")
		}
		req.jwk, key = h.JSONWebKey, h.JSONWebKey
	default:
		if h.JSONWebKey != nil || h.KeyID == "" {
			return nil, prob(http.StatusBadRequest, "malformed", "JWS: needs a kid and no jwk")
		}
		id, ok := strings.CutPrefix(h.KeyID, base+"/acme/acct/")
		s.mu.Lock()
		a := s.accounts[id]
		s.mu.Unlock()
		if !ok || a == nil {
			return nil, prob(http.StatusBadRequest, "accountDoesNotExist", "unknown account")
		}
		if a.Status != "valid" {
			return nil, prob(http.StatusUnauthorized, "unauthorized", "account %s", a.Status)
		}
		req.acct, key = a, a.Key
	}
	payload, err := jws.Verify(key)
	if err != nil {
		return nil, prob(http.StatusBadRequest, "malformed", "JWS signature: %v", err)
	}
	req.payload = payload
	return req, nil
}

func remoteAddr(r *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	a, _ := netip.ParseAddr(host)
	return a.Unmap()
}

func (s *Server) newNonce() string {
	n := randID()
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if len(s.nonces) >= maxNonces {
		for k, exp := range s.nonces {
			if now.After(exp) || len(s.nonces) >= maxNonces {
				delete(s.nonces, k)
			}
		}
	}
	s.nonces[n] = now.Add(nonceLife)
	return n
}

func (s *Server) useNonce(n string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.nonces[n]
	delete(s.nonces, n)
	return ok && s.now().Before(exp)
}

func randID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// ----- accounts -----

func (s *Server) acctURL(base string, a *account) string { return base + "/acme/acct/" + a.ID }

func (s *Server) acctJSON(base string, a *account) map[string]any {
	return map[string]any{"status": a.Status, "contact": nonNil(a.Contact), "orders": s.acctURL(base, a) + "/orders"}
}

func nonNil(l []string) []string {
	if l == nil {
		return []string{}
	}
	return l
}

func (s *Server) newAccount(w http.ResponseWriter, req *request) error {
	var p struct {
		Contact            []string        `json:"contact"`
		ToS                bool            `json:"termsOfServiceAgreed"`
		OnlyReturnExisting bool            `json:"onlyReturnExisting"`
		EAB                json.RawMessage `json:"externalAccountBinding"`
	}
	if err := json.Unmarshal(req.payload, &p); err != nil {
		return prob(http.StatusBadRequest, "malformed", "%v", err)
	}
	tp, err := req.jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return prob(http.StatusBadRequest, "badPublicKey", "%v", err)
	}
	id := base64.RawURLEncoding.EncodeToString(tp)
	s.mu.Lock()
	defer s.mu.Unlock()
	if a := s.accounts[id]; a != nil {
		w.Header().Set("Location", s.acctURL(req.base, a))
		writeJSON(w, http.StatusOK, s.acctJSON(req.base, a))
		return nil
	}
	if p.OnlyReturnExisting {
		return prob(http.StatusBadRequest, "accountDoesNotExist", "no account for this key")
	}
	if err := checkContact(p.Contact); err != nil {
		return err
	}
	a := &account{ID: id, Key: req.jwk, Contact: p.Contact, Status: "valid", Created: s.now().UTC()}
	s.accounts[id] = a
	if err := s.saveAccounts(); err != nil {
		delete(s.accounts, id)
		return err
	}
	slog.Info("acme proxy: new account", "account", id, "client", req.client)
	w.Header().Set("Location", s.acctURL(req.base, a))
	writeJSON(w, http.StatusCreated, s.acctJSON(req.base, a))
	return nil
}

func checkContact(c []string) error {
	if len(c) > 10 {
		return prob(http.StatusBadRequest, "invalidContact", "at most 10 contacts")
	}
	for _, x := range c {
		if !strings.HasPrefix(x, "mailto:") || len(x) > 300 || strings.ContainsFunc(x, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			return prob(http.StatusBadRequest, "unsupportedContact", "contact %q: a mailto: URL", x)
		}
	}
	return nil
}

// saveAccounts writes the accounts; called with s.mu held.
func (s *Server) saveAccounts() error {
	list := make([]*account, 0, len(s.accounts))
	for _, a := range s.accounts {
		list = append(list, a)
	}
	slices.SortFunc(list, func(a, b *account) int { return strings.Compare(a.ID, b.ID) })
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.accountsFile), 0o700); err != nil {
		return err
	}
	tmp := s.accountsFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.accountsFile)
}

func (s *Server) accountReq(w http.ResponseWriter, req *request, id string) error {
	if id == req.acct.ID+"/orders" {
		return s.ordersList(w, req)
	}
	if id != req.acct.ID {
		return prob(http.StatusUnauthorized, "unauthorized", "not your account")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a := req.acct
	if len(req.payload) > 0 {
		var p struct {
			Contact *[]string `json:"contact"`
			Status  string    `json:"status"`
		}
		if err := json.Unmarshal(req.payload, &p); err != nil {
			return prob(http.StatusBadRequest, "malformed", "%v", err)
		}
		changed := false
		if p.Contact != nil {
			if err := checkContact(*p.Contact); err != nil {
				return err
			}
			a.Contact, changed = *p.Contact, true
		}
		switch p.Status {
		case "":
		case "deactivated":
			a.Status, changed = "deactivated", true
		default:
			return prob(http.StatusBadRequest, "malformed", "status can only be deactivated")
		}
		if changed {
			if err := s.saveAccounts(); err != nil {
				return err
			}
		}
	}
	w.Header().Set("Location", s.acctURL(req.base, a))
	writeJSON(w, http.StatusOK, s.acctJSON(req.base, a))
	return nil
}

func (s *Server) ordersList(w http.ResponseWriter, req *request) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	urls := []string{}
	for _, o := range s.orders {
		if o.account == req.acct.ID {
			urls = append(urls, req.base+"/acme/order/"+o.id)
		}
	}
	slices.Sort(urls)
	writeJSON(w, http.StatusOK, map[string]any{"orders": urls})
	return nil
}

// ----- orders -----

func (s *Server) newOrder(w http.ResponseWriter, req *request) error {
	var p struct {
		Identifiers []struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"identifiers"`
		NotBefore string `json:"notBefore"`
		NotAfter  string `json:"notAfter"`
	}
	if err := json.Unmarshal(req.payload, &p); err != nil {
		return prob(http.StatusBadRequest, "malformed", "%v", err)
	}
	if p.NotBefore != "" || p.NotAfter != "" {
		return prob(http.StatusBadRequest, "malformed", "notBefore and notAfter are not supported")
	}
	if len(p.Identifiers) == 0 || len(p.Identifiers) > maxNames {
		return prob(http.StatusBadRequest, "malformed", "1-%d identifiers", maxNames)
	}
	var names []string
	for _, id := range p.Identifiers {
		if id.Type != "dns" {
			return prob(http.StatusBadRequest, "unsupportedIdentifier", "%s identifiers are not supported", id.Type)
		}
		name := strings.ToLower(strings.TrimSuffix(id.Value, "."))
		if strings.HasPrefix(name, "*.") {
			return prob(http.StatusBadRequest, "rejectedIdentifier", "%s: HTTP-01 can't validate a wildcard", name)
		}
		if !validName(name) {
			return prob(http.StatusBadRequest, "rejectedIdentifier", "%q is not a DNS name", id.Value)
		}
		if err := s.hooks.Authorize(name, req.client); err != nil {
			slog.Warn("acme proxy: name refused", "name", name, "client", req.client, "err", err)
			return prob(http.StatusForbidden, "rejectedIdentifier", "%s: %v", name, err)
		}
		if !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	slices.Sort(names)

	o, err := s.addOrder(req, names)
	if err != nil {
		return err
	}
	if s.hooks.Ordered != nil {
		s.hooks.Ordered(names, req.client)
	}
	w.Header().Set("Location", req.base+"/acme/order/"+o.id)
	s.mu.Lock()
	j := s.orderJSON(req.base, o)
	s.mu.Unlock()
	writeJSON(w, http.StatusCreated, j)
	return nil
}

func (s *Server) addOrder(req *request, names []string) (*order, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.purge(now)
	if len(s.orders) >= maxOrders {
		return nil, prob(http.StatusServiceUnavailable, "rateLimited", "too many orders; try later")
	}
	o := &order{id: randID(), account: req.acct.ID, client: req.client, names: names, status: "pending", expires: now.Add(orderLife)}
	for _, n := range names {
		// A name validated for this account and client before is reused.
		if a := s.validAuthz(req.acct.ID, n, req.client, now); a != nil {
			o.authzs = append(o.authzs, a)
			continue
		}
		a := &authz{id: randID(), chalID: randID(), account: req.acct.ID, name: n, token: randID(), client: req.client,
			status: "pending", chalStatus: "pending", expires: o.expires}
		s.authzs[a.id], s.chals[a.chalID] = a, a
		o.authzs = append(o.authzs, a)
	}
	s.orders[o.id] = o
	s.refresh(o)
	slog.Info("acme proxy: new order", "order", o.id, "names", names, "client", req.client)
	return o, nil
}

// validAuthz is a valid authorization of a name for an account and client.
func (s *Server) validAuthz(acct, name string, client netip.Addr, now time.Time) *authz {
	for _, a := range s.authzs {
		if a.account == acct && a.name == name && a.client == client && a.status == "valid" && now.Before(a.expires) {
			return a
		}
	}
	return nil
}

// purge drops expired orders and the authorizations no order holds.
func (s *Server) purge(now time.Time) {
	held := map[*authz]bool{}
	for id, o := range s.orders {
		if now.After(o.expires) && o.status != "processing" {
			delete(s.orders, id)
			if o.certID != "" {
				delete(s.certs, o.certID)
			}
			continue
		}
		for _, a := range o.authzs {
			held[a] = true
		}
	}
	for id, a := range s.authzs {
		if !held[a] {
			delete(s.authzs, id)
			delete(s.chals, a.chalID)
		}
	}
}

// refresh moves an order on from its authorizations; with s.mu held.
func (s *Server) refresh(o *order) {
	if o.status != "pending" {
		return
	}
	ready := true
	for _, a := range o.authzs {
		switch a.status {
		case "invalid", "deactivated":
			o.status, o.err = "invalid", a.err
			return
		case "pending":
			ready = false
		}
	}
	if ready {
		o.status = "ready"
	}
}

func (s *Server) orderJSON(base string, o *order) map[string]any {
	ids := make([]map[string]string, len(o.names))
	authzs := make([]string, len(o.authzs))
	for i, n := range o.names {
		ids[i] = map[string]string{"type": "dns", "value": n}
	}
	for i, a := range o.authzs {
		authzs[i] = base + "/acme/authz/" + a.id
	}
	j := map[string]any{
		"status": o.status, "expires": o.expires.UTC().Format(time.RFC3339),
		"identifiers": ids, "authorizations": authzs, "finalize": base + "/acme/order/" + o.id + "/finalize",
	}
	if o.certID != "" && o.status == "valid" {
		j["certificate"] = base + "/acme/cert/" + o.certID
	}
	if o.err != nil {
		j["error"] = o.err
	}
	return j
}

// mine finds an order of the request's account; with s.mu held.
func (s *Server) mine(req *request, id string) (*order, error) {
	o := s.orders[id]
	if o == nil || o.account != req.acct.ID {
		return nil, prob(http.StatusNotFound, "malformed", "no such order")
	}
	return o, nil
}

func (s *Server) orderReq(w http.ResponseWriter, req *request, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, err := s.mine(req, id)
	if err != nil {
		return err
	}
	s.refresh(o)
	if o.status == "processing" {
		w.Header().Set("Retry-After", "1")
	}
	writeJSON(w, http.StatusOK, s.orderJSON(req.base, o))
	return nil
}

func (s *Server) finalize(w http.ResponseWriter, req *request, id string) error {
	var p struct {
		CSR string `json:"csr"`
	}
	if err := json.Unmarshal(req.payload, &p); err != nil {
		return prob(http.StatusBadRequest, "malformed", "%v", err)
	}
	der, err := base64.RawURLEncoding.DecodeString(p.CSR)
	if err != nil {
		return prob(http.StatusBadRequest, "badCSR", "csr: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return prob(http.StatusBadRequest, "badCSR", "csr: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return prob(http.StatusBadRequest, "badCSR", "csr signature: %v", err)
	}
	if len(csr.IPAddresses) > 0 || len(csr.EmailAddresses) > 0 || len(csr.URIs) > 0 {
		return prob(http.StatusBadRequest, "badCSR", "csr: DNS names only")
	}
	var names []string
	for _, n := range append([]string{csr.Subject.CommonName}, csr.DNSNames...) {
		if n = strings.ToLower(n); n != "" && !slices.Contains(names, n) {
			names = append(names, n)
		}
	}
	slices.Sort(names)

	s.mu.Lock()
	defer s.mu.Unlock()
	o, err := s.mine(req, id)
	if err != nil {
		return err
	}
	s.refresh(o)
	if o.status != "ready" {
		return prob(http.StatusForbidden, "orderNotReady", "the order is %s", o.status)
	}
	if !slices.Equal(names, o.names) {
		return prob(http.StatusBadRequest, "badCSR", "the CSR's names %v are not the order's %v", names, o.names)
	}
	o.status = "processing"
	o.expires = s.now().Add(orderLife)
	s.wg.Add(1)
	go s.issue(o, csr)
	w.Header().Set("Location", req.base+"/acme/order/"+o.id)
	w.Header().Set("Retry-After", "1")
	writeJSON(w, http.StatusOK, s.orderJSON(req.base, o))
	return nil
}

func (s *Server) issue(o *order, csr *x509.CertificateRequest) {
	defer s.wg.Done()
	ctx, cancel := context.WithTimeout(s.ctx, issueTimeout)
	defer cancel()
	chain, err := s.hooks.Issue(ctx, csr, o.names, o.client)
	if err == nil {
		err = checkChain(chain, csr)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		slog.Error("acme proxy: certificate", "order", o.id, "names", o.names, "err", err)
		o.status, o.err = "invalid", prob(http.StatusInternalServerError, "serverInternal", "certificate: %v", err)
		return
	}
	o.status, o.chain, o.certID = "valid", chain, randID()
	s.certs[o.certID] = o
}

// checkChain checks that the chain's leaf is for the CSR's key.
func checkChain(chain []byte, csr *x509.CertificateRequest) error {
	b, _ := pem.Decode(chain)
	if b == nil || b.Type != "CERTIFICATE" {
		return errors.New("no certificate")
	}
	leaf, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return err
	}
	type eq interface{ Equal(crypto.PublicKey) bool }
	if k, ok := leaf.PublicKey.(eq); !ok || !k.Equal(csr.PublicKey) {
		return errors.New("the certificate is not for the CSR's key")
	}
	return nil
}

func (s *Server) certReq(w http.ResponseWriter, req *request, id string) error {
	s.mu.Lock()
	o := s.certs[id]
	s.mu.Unlock()
	if o == nil || o.account != req.acct.ID {
		return prob(http.StatusNotFound, "malformed", "no such certificate")
	}
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(o.chain)
	return nil
}

// ----- authorizations and challenges -----

func (s *Server) chalJSON(base string, a *authz) map[string]any {
	j := map[string]any{"type": "http-01", "url": base + "/acme/chall/" + a.chalID, "token": a.token, "status": a.chalStatus}
	if !a.validated.IsZero() {
		j["validated"] = a.validated.UTC().Format(time.RFC3339)
	}
	if a.err != nil {
		j["error"] = a.err
	}
	return j
}

func (s *Server) authzReq(w http.ResponseWriter, req *request, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.authzs[id]
	if a == nil || a.account != req.acct.ID {
		return prob(http.StatusNotFound, "malformed", "no such authorization")
	}
	if len(req.payload) > 0 {
		var p struct {
			Status string `json:"status"`
		}
		if err := json.Unmarshal(req.payload, &p); err != nil || p.Status != "deactivated" {
			return prob(http.StatusBadRequest, "malformed", "status can only be deactivated")
		}
		a.status = "deactivated"
	}
	if a.status == "pending" && a.chalStatus == "processing" {
		w.Header().Set("Retry-After", "1")
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"identifier": map[string]string{"type": "dns", "value": a.name},
		"status":     a.status, "expires": a.expires.UTC().Format(time.RFC3339),
		"challenges": []any{s.chalJSON(req.base, a)},
	})
	return nil
}

func (s *Server) challengeReq(w http.ResponseWriter, req *request, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.chals[id]
	if a == nil || a.account != req.acct.ID {
		return prob(http.StatusNotFound, "malformed", "no such challenge")
	}
	// An empty payload is POST-as-GET; {} asks for the validation.
	if len(req.payload) > 0 && a.chalStatus == "pending" {
		tp, err := req.acct.Key.Thumbprint(crypto.SHA256)
		if err != nil {
			return err
		}
		a.chalStatus = "processing"
		s.wg.Add(1)
		go s.validate(a, a.token+"."+base64.RawURLEncoding.EncodeToString(tp))
	}
	w.Header().Add("Link", fmt.Sprintf("<%s/acme/authz/%s>;rel=\"up\"", req.base, a.id))
	writeJSON(w, http.StatusOK, s.chalJSON(req.base, a))
	return nil
}

func (s *Server) validate(a *authz, keyAuth string) {
	defer s.wg.Done()
	ctx, cancel := context.WithTimeout(s.ctx, validateTimeout)
	defer cancel()
	err := s.hooks.Validate(ctx, a.name, a.token, keyAuth, a.client)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		slog.Warn("acme proxy: validation failed", "name", a.name, "client", a.client, "err", err)
		a.status, a.chalStatus, a.err = "invalid", "invalid", prob(http.StatusForbidden, "unauthorized", "%s: %v", a.name, err)
		return
	}
	a.status, a.chalStatus, a.validated = "valid", "valid", s.now()
}

// ----- helpers -----

func validName(n string) bool {
	if len(n) == 0 || len(n) > 253 || !strings.Contains(n, ".") {
		return false
	}
	if _, err := netip.ParseAddr(n); err == nil {
		return false
	}
	for _, l := range strings.Split(n, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeProblem(w http.ResponseWriter, p *problem) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(p.Status)
	_ = json.NewEncoder(w).Encode(p)
}
