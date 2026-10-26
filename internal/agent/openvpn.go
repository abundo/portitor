// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/abundo/portitor/internal/acme"
	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/ldapauth"
	"github.com/abundo/portitor/internal/render"
)

// OpenVPN: the agent is the management client of each OpenVPN process
// (render.OpenVPNConf, management-client-auth). OpenVPN asks it about
// every client that connects, with the user name and password the client
// sent; the agent checks them as portitor-config checks a GUI login (the
// document's users' bcrypt hashes, then the Directory) and answers, so no
// script runs and no password is written down. It restarts OpenVPN when the server's certificate
// changes (an ACME renewal), and lists the clients for the GUI.

// openvpnItem is an OpenVPN process as the applied document declares it.
type openvpnItem struct {
	// iface is the OpenVPN interface, device the process's (the
	// interface, or its TCP device).
	instance, netns, iface, device, unit, socket, certDir string
	cfg                                                   fwconfig.OpenVPN
	// dir are the Directory's servers.
	dir []fwconfig.LDAPServer
}

// Errors of a login.
var (
	errNoSuchUser  = errors.New("no such user")
	errBadPassword = errors.New("wrong password")
	errNotMember   = errors.New("not a member of the group")
)

const (
	// ovpnFailDelay is how long a refused login waits for its answer, to
	// slow down guessing.
	ovpnFailDelay = 2 * time.Second
	// ovpnCertCheck is how often the server's certificate is looked at.
	ovpnCertCheck = time.Minute
)

type openvpnManager struct {
	dryRun bool
	// run restarts OpenVPN when its certificate changes, outside an
	// apply's log.
	run Runner
	// ldapAuth checks a password at a directory server
	// (directoryAuthenticate; a fake in tests).
	ldapAuth  func(ctx context.Context, l fwconfig.LDAPServer, user, password string) (bool, *ldapauth.UserInfo, error)
	failDelay time.Duration
	// logins are the directory logins of users the firewall doesn't
	// have, for portitor-config to copy (GET /v1/directory/logins).
	logins *ring[agentapi.DirectoryLogin]

	mu      sync.Mutex
	servers map[string]*ovpnServer // by unit
	wg      sync.WaitGroup
}

func newOpenVPNManager(dryRun bool, run Runner) *openvpnManager {
	return &openvpnManager{dryRun: dryRun, run: run, ldapAuth: directoryAuthenticate, failDelay: ovpnFailDelay, servers: map[string]*ovpnServer{},
		logins: newRing(500, func(l *agentapi.DirectoryLogin) *int64 { return &l.ID })}
}

// ovpnServer is the agent's side of one OpenVPN process.
type ovpnServer struct {
	m      *openvpnManager
	cancel context.CancelFunc

	mu      sync.Mutex
	item    openvpnItem
	conn    *ovpnConn // nil while not connected
	err     string
	clients map[int64]*ovpnClient
	certSum string
}

// ovpnClient is a client this agent let in: who, and what checked the
// password ("local" or an LDAP server's name).
type ovpnClient struct {
	user, source string
}

const ovpnLocal = "local"

// Reconcile starts a management client for each new OpenVPN process and
// stops removed ones. A process whose socket stays gets the new users and
// LDAP servers in place, and its clients that may no longer log in are
// disconnected.
func (m *openvpnManager) Reconcile(want []openvpnItem) {
	m.mu.Lock()
	defer m.mu.Unlock()
	keep := map[string]bool{}
	for _, it := range want {
		keep[it.unit] = true
		if s, ok := m.servers[it.unit]; ok {
			if s.item.socket == it.socket && s.item.netns == it.netns {
				s.update(it)
				continue
			}
			s.cancel()
		}
		m.servers[it.unit] = m.start(it)
	}
	for unit, s := range m.servers {
		if !keep[unit] {
			s.cancel()
			delete(m.servers, unit)
		}
	}
}

func (m *openvpnManager) Stop() {
	m.Reconcile(nil)
	m.wg.Wait()
}

func (m *openvpnManager) start(it openvpnItem) *ovpnServer {
	ctx, cancel := context.WithCancel(context.Background())
	s := &ovpnServer{m: m, cancel: cancel, item: it, clients: map[int64]*ovpnClient{}, certSum: certSum(it.certDir)}
	if m.dryRun {
		s.err = "dry run"
		return s
	}
	m.wg.Add(2)
	go func() {
		defer m.wg.Done()
		s.loop(ctx)
	}()
	go func() {
		defer m.wg.Done()
		s.watchCert(ctx)
	}()
	return s
}

// update takes a changed item of the same process.
func (s *ovpnServer) update(it openvpnItem) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.item.certDir != it.certDir {
		s.certSum = certSum(it.certDir)
	}
	s.item = it
	for id, c := range s.clients {
		if !s.allowedLocked(c) {
			slog.Info("openvpn: disconnecting a user who may no longer log in", "instance", it.instance, "device", it.device, "user", c.user)
			delete(s.clients, id)
			if conn := s.conn; conn != nil {
				go conn.command(context.Background(), fmt.Sprintf("client-kill %d", id), false) //nolint:errcheck
			}
		}
	}
}

// allowedLocked says whether a client let in may still log in the same
// way: a local user still listed and not denied, a directory server still
// asked.
func (s *ovpnServer) allowedLocked(c *ovpnClient) bool {
	if c.source == ovpnLocal {
		return slices.ContainsFunc(s.item.cfg.Users, func(u fwconfig.OpenVPNUser) bool { return u.Name == c.user && !u.LDAP && !u.Denied })
	}
	return slices.ContainsFunc(s.item.dir, func(l fwconfig.LDAPServer) bool { return l.Name == c.source })
}

// loop connects to the management socket and serves it, again whenever
// OpenVPN restarts, until ctx is done.
func (s *ovpnServer) loop(ctx context.Context) {
	for {
		s.mu.Lock()
		socket := s.item.socket
		s.mu.Unlock()
		c, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", socket)
		if err == nil {
			s.serve(ctx, c)
		} else {
			s.mu.Lock()
			s.err = "OpenVPN is not running"
			s.mu.Unlock()
		}
		if !sleepCtx(ctx, 2*time.Second) {
			return
		}
	}
}

// serve reads OpenVPN's messages until the connection or ctx ends.
func (s *ovpnServer) serve(ctx context.Context, c net.Conn) {
	conn := newOvpnConn(c)
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	s.mu.Lock()
	s.conn, s.err = conn, ""
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.conn, s.err = nil, "OpenVPN is not running"
		s.mu.Unlock()
	}()
	conn.read(func(ev *ovpnEvent) { s.event(ctx, conn, ev) })
}

// event handles a client notification.
func (s *ovpnServer) event(ctx context.Context, conn *ovpnConn, ev *ovpnEvent) {
	switch ev.kind {
	case "CONNECT", "REAUTH":
		go s.authorize(ctx, conn, ev)
	case "DISCONNECT":
		s.mu.Lock()
		delete(s.clients, ev.cid)
		s.mu.Unlock()
	}
}

// authorize answers a client's login. A renegotiation of a client this
// agent let in (one without the auth token) is let in again while its
// user may still log in.
func (s *ovpnServer) authorize(ctx context.Context, conn *ovpnConn, ev *ovpnEvent) {
	user, password := ev.env["username"], ev.env["password"]
	from := ev.env["untrusted_ip"]
	if from == "" {
		from = ev.env["untrusted_ip6"]
	}
	s.mu.Lock()
	it := s.item
	known := s.clients[ev.cid]
	again := ev.kind == "REAUTH" && known != nil && known.user == user && s.allowedLocked(known)
	s.mu.Unlock()
	log := slog.With("instance", it.instance, "device", it.device, "user", user, "from", from)
	if again {
		s.answer(ctx, log, conn, ev, nil)
		return
	}
	source, err := s.m.check(ctx, it, user, password)
	if err != nil {
		log.Warn("openvpn: login refused", "err", err)
		if !sleepCtx(ctx, s.m.failDelay) {
			return
		}
		s.answer(ctx, log, conn, ev, err)
		return
	}
	log.Info("openvpn: login", "checked_by", source)
	s.mu.Lock()
	s.clients[ev.cid] = &ovpnClient{user: user, source: source}
	s.mu.Unlock()
	s.answer(ctx, log, conn, ev, nil)
}

func (s *ovpnServer) answer(ctx context.Context, log *slog.Logger, conn *ovpnConn, ev *ovpnEvent, refused error) {
	cmd := fmt.Sprintf("client-auth-nt %d %d", ev.cid, ev.kid)
	if refused != nil {
		// The client is told no more than AUTH_FAILED.
		cmd = fmt.Sprintf(`client-deny %d %d "login refused"`, ev.cid, ev.kid)
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if _, err := conn.command(cctx, cmd, false); err != nil {
		log.Warn("openvpn: answer", "err", err)
	}
}

// check follows portitor-config's login path (web authenticateUser): a
// local user's password is checked against its hash; a directory user's,
// and a user the firewall doesn't have, at the directory's servers in
// order, the first to accept it deciding. A user the firewall doesn't
// have is then reported, to be copied to the users. With a required role,
// a user must be a member, or a directory user in one of the role's
// groups. It returns what checked the password.
func (m *openvpnManager) check(ctx context.Context, it openvpnItem, user, password string) (string, error) {
	if !fwconfig.ValidOpenVPNUser(user) {
		return "", errors.New("invalid user name")
	}
	if password == "" || len(password) > 1024 {
		return "", errBadPassword
	}
	i := slices.IndexFunc(it.cfg.Users, func(u fwconfig.OpenVPNUser) bool { return u.Name == user })
	if i >= 0 && !it.cfg.Users[i].LDAP {
		u := it.cfg.Users[i]
		if u.Denied {
			return "", errNotMember
		}
		if bcrypt.CompareHashAndPassword([]byte(u.Hash), []byte(password)) != nil {
			return "", errBadPassword
		}
		return ovpnLocal, nil
	}
	server, info, err := m.directory(ctx, it.dir, user, password)
	if err != nil {
		return "", err
	}
	if i < 0 {
		// Copied even when the role refuses, as a GUI login is.
		m.logins.add(agentapi.DirectoryLogin{Time: time.Now().UTC(), User: user, Server: server,
			DN: info.DN, Email: info.Email, DisplayName: info.DisplayName, Groups: info.Groups})
	}
	if it.cfg.RequireRole && (i < 0 || it.cfg.Users[i].Denied) && !ldapauth.InGroups(info.Groups, it.cfg.RoleGroups) {
		return "", fmt.Errorf("%s: %w", server, errNotMember)
	}
	return server, nil
}

// directory checks a password at each server in turn: one that is down
// or doesn't accept it is passed over. It returns the server that did.
func (m *openvpnManager) directory(ctx context.Context, servers []fwconfig.LDAPServer, user, password string) (string, *ldapauth.UserInfo, error) {
	if len(servers) == 0 {
		return "", nil, errNoSuchUser
	}
	var errs []error
	for _, l := range servers {
		lctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		ok, info, err := m.ldapAuth(lctx, l, user, password)
		cancel()
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("%s: %w", l.Name, err))
		case ok:
			return l.Name, info, nil
		}
	}
	if len(errs) > 0 {
		return "", nil, fmt.Errorf("no directory server accepted the password: %w", errors.Join(errs...))
	}
	return "", nil, errors.New("no directory server accepted the password")
}

// directoryAuthenticate checks a password at one directory server, from
// the agent's namespace.
func directoryAuthenticate(ctx context.Context, l fwconfig.LDAPServer, user, password string) (bool, *ldapauth.UserInfo, error) {
	return ldapauth.Authenticate(ctx, LDAPConfig(l), user, password)
}

// LDAPConfig is a directory server as ldapauth takes it.
func LDAPConfig(l fwconfig.LDAPServer) ldapauth.Config {
	return ldapauth.Config{
		Host: l.Host, Port: l.Port, TLSMode: l.TLSMode, SkipTLSVerify: l.SkipTLSVerify, CACert: l.CACert, ServerType: l.ServerType,
		BindDN: l.BindDN, BindPassword: l.BindPassword, BaseDN: l.BaseDN, UserFilter: l.UserFilter, AttrGroups: l.AttrGroups,
	}
}

// DirectoryLogins are the directory logins since after.
func (a *Agent) DirectoryLogins(after int64) *agentapi.DirectoryLoginsResponse {
	return &agentapi.DirectoryLoginsResponse{Logins: a.ovpn.logins.After(after)}
}

// watchCert restarts OpenVPN when the server's certificate changes on
// disk: renewed, imported anew or copied from the HA peer.
func (s *ovpnServer) watchCert(ctx context.Context) {
	for sleepCtx(ctx, ovpnCertCheck) {
		s.mu.Lock()
		dir, unit, old := s.item.certDir, s.item.unit, s.certSum
		sum := certSum(dir)
		if sum != "" {
			s.certSum = sum
		}
		s.mu.Unlock()
		if sum == "" || sum == old {
			continue
		}
		slog.Info("openvpn: certificate changed, restarting", "instance", s.item.instance, "unit", unit)
		if _, err := s.m.run.Run(ctx, "", "systemctl", "try-restart", unit); err != nil {
			slog.Warn("openvpn: restart", "unit", unit, "err", err)
		}
	}
}

// certSum is a hash of a stored certificate's chain and key; empty
// without one.
func certSum(dir string) string {
	h := sha256.New()
	for _, f := range []string{acme.FullChainFile, acme.PrivKeyFile} {
		b, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			return ""
		}
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Status lists the OpenVPN processes with their clients (OpenVPN's
// status 3).
func (m *openvpnManager) Status(ctx context.Context) *agentapi.OpenVPNResponse {
	m.mu.Lock()
	servers := make([]*ovpnServer, 0, len(m.servers))
	for _, s := range m.servers {
		servers = append(servers, s)
	}
	m.mu.Unlock()
	resp := &agentapi.OpenVPNResponse{Servers: []agentapi.OpenVPNServer{}}
	for _, s := range servers {
		resp.Servers = append(resp.Servers, s.status(ctx))
	}
	slices.SortFunc(resp.Servers, func(a, b agentapi.OpenVPNServer) int {
		return strings.Compare(a.Instance+" "+a.Device, b.Instance+" "+b.Device)
	})
	return resp
}

func (s *ovpnServer) status(ctx context.Context) agentapi.OpenVPNServer {
	s.mu.Lock()
	it, conn, errText := s.item, s.conn, s.err
	s.mu.Unlock()
	out := agentapi.OpenVPNServer{Instance: it.instance, Device: it.device, Interface: it.iface, Proto: it.cfg.Proto, Error: errText, Clients: []agentapi.OpenVPNClient{}}
	if conn == nil {
		return out
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	lines, err := conn.command(cctx, "status 3", true)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	out.Connected = true
	out.Clients = parseOpenVPNStatus(lines)
	s.mu.Lock()
	for i := range out.Clients {
		if c := s.clients[out.Clients[i].ID]; c != nil {
			out.Clients[i].Source = c.source
		}
	}
	s.mu.Unlock()
	return out
}

// parseOpenVPNStatus reads the CLIENT_LIST lines of status 3 (tabs), by
// their HEADER's column names.
func parseOpenVPNStatus(lines []string) []agentapi.OpenVPNClient {
	out := []agentapi.OpenVPNClient{}
	var cols map[string]int
	for _, l := range lines {
		f := strings.Split(l, "\t")
		switch {
		case len(f) > 1 && f[0] == "HEADER" && f[1] == "CLIENT_LIST":
			cols = map[string]int{}
			for i, name := range f[1:] {
				cols[name] = i
			}
		case f[0] == "CLIENT_LIST" && cols != nil:
			get := func(name string) string {
				if i, ok := cols[name]; ok && i < len(f) {
					return f[i]
				}
				return ""
			}
			num := func(name string) int64 { n, _ := strconv.ParseInt(get(name), 10, 64); return n }
			c := agentapi.OpenVPNClient{
				ID: num("Client ID"), User: get("Username"), RealAddress: get("Real Address"),
				Address: get("Virtual Address"), Address6: get("Virtual IPv6 Address"),
				RxBytes: num("Bytes Received"), TxBytes: num("Bytes Sent"), Cipher: get("Data Channel Cipher"),
			}
			if c.User == "" || c.User == "UNDEF" {
				c.User = get("Common Name")
			}
			if t := num("Connected Since (time_t)"); t > 0 {
				c.Since = time.Unix(t, 0).UTC()
			}
			out = append(out, c)
		}
	}
	return out
}

// OpenVPN lists the OpenVPN processes and their clients.
func (a *Agent) OpenVPN(ctx context.Context) *agentapi.OpenVPNResponse {
	return a.ovpn.Status(ctx)
}

// openvpnItems are the OpenVPN processes of an expanded instance.
func (a *Agent) openvpnItems(in *fwconfig.Instance, ns string, dir *fwconfig.Directory) []openvpnItem {
	var out []openvpnItem
	files := a.cfg.Paths.Files(in)
	for _, ifc := range in.OpenVPNDevices() {
		o := ifc.OpenVPN
		iface := ifc.Name
		if ifc.Parent != "" {
			iface = ifc.Parent
		}
		it := openvpnItem{
			instance: in.Name, netns: ns, iface: iface, device: ifc.Name, cfg: *o,
			unit: a.cfg.Units.OpenVPN(in, o.Proto), socket: files.OpenVPNSocket(o.Proto),
			certDir: a.cfg.Paths.CertificateDir(in.Name, o.Certificate),
		}
		if dir != nil {
			it.dir = dir.Servers
		}
		out = append(out, it)
	}
	return out
}

// OpenVPNCA is what a client of an instance's OpenVPN server needs to
// trust it: the root of its certificate's chain (the last one when it is
// self-signed, else the system CA that signed it) and the name to verify.
func (a *Agent) OpenVPNCA(instance string) (*agentapi.OpenVPNCA, error) {
	a.mu.Lock()
	doc := a.applied
	a.mu.Unlock()
	var in *fwconfig.Instance
	if doc != nil {
		in = doc.Instance(instance)
	}
	if in == nil || in.OpenVPNServer() == nil {
		return nil, fmt.Errorf("instance %s has no OpenVPN server", instance)
	}
	name := in.OpenVPNServer().OpenVPN.Certificate
	chain, err := os.ReadFile(filepath.Join(a.cfg.Paths.CertificateDir(instance, name), acme.FullChainFile))
	if err != nil {
		return nil, fmt.Errorf("no certificate %s yet", name)
	}
	return clientCA(chain)
}

func clientCA(chain []byte) (*agentapi.OpenVPNCA, error) {
	var certs []*x509.Certificate
	for rest := chain; ; {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			break
		}
		if c, err := x509.ParseCertificate(b.Bytes); err == nil {
			certs = append(certs, c)
		}
	}
	if len(certs) == 0 {
		return nil, errors.New("no certificate in the chain")
	}
	leaf, top := certs[0], certs[len(certs)-1]
	out := &agentapi.OpenVPNCA{CommonName: leaf.Subject.CommonName}
	if string(top.RawIssuer) == string(top.RawSubject) && top.CheckSignature(top.SignatureAlgorithm, top.RawTBSCertificate, top.Signature) == nil {
		out.CA = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: top.Raw}))
		return out, nil
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	// At a time the certificate was valid: an expired one still names
	// its CA.
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: leaf.NotBefore.Add(time.Minute),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if err != nil || len(chains) == 0 {
		return nil, fmt.Errorf("the certificate's CA is not one of the system's: %v", err)
	}
	root := chains[0][len(chains[0])-1]
	out.CA = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw}))
	return out, nil
}

// prepareOpenVPN makes the directory of an instance's management sockets,
// root's alone, before OpenVPN starts.
func prepareOpenVPN(files render.InstanceFiles) error {
	if err := os.MkdirAll(files.OpenVPNRun, 0o700); err != nil {
		return err
	}
	return os.Chmod(files.OpenVPNRun, 0o700)
}

// ovpnEvent is a client notification with its environment.
type ovpnEvent struct {
	kind     string
	cid, kid int64
	env      map[string]string
}

// ovpnConn is a connection to OpenVPN's management interface: commands
// one at a time, each answered by a SUCCESS: or ERROR: line, or (status)
// lines up to END; notifications (">...") come in between.
type ovpnConn struct {
	c      net.Conn
	w      sync.Mutex // one command at a time
	mu     sync.Mutex
	reply  *ovpnReply
	closed chan struct{}
}

type ovpnReply struct {
	multi bool
	lines []string
	done  chan struct{}
}

func newOvpnConn(c net.Conn) *ovpnConn {
	return &ovpnConn{c: c, closed: make(chan struct{})}
}

// command sends a command and waits for its answer: one line, or (multi)
// the lines before END.
func (c *ovpnConn) command(ctx context.Context, line string, multi bool) ([]string, error) {
	c.w.Lock()
	defer c.w.Unlock()
	r := &ovpnReply{multi: multi, done: make(chan struct{})}
	c.mu.Lock()
	c.reply = r
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		if c.reply == r {
			c.reply = nil
		}
		c.mu.Unlock()
	}()
	if _, err := io.WriteString(c.c, line+"\n"); err != nil {
		return nil, err
	}
	select {
	case <-r.done:
	case <-c.closed:
		return nil, errors.New("management connection closed")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if len(r.lines) > 0 && strings.HasPrefix(r.lines[0], "ERROR:") {
		return nil, errors.New(strings.TrimSpace(strings.TrimPrefix(r.lines[0], "ERROR:")))
	}
	return r.lines, nil
}

// answerLine gives a line that is no notification to the waiting command.
func (c *ovpnConn) answerLine(line string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	r := c.reply
	if r == nil {
		return
	}
	if r.multi && line == "END" {
		c.reply = nil
		close(r.done)
		return
	}
	r.lines = append(r.lines, line)
	if !r.multi || (len(r.lines) == 1 && strings.HasPrefix(line, "ERROR:")) {
		c.reply = nil
		close(r.done)
	}
}

// read reads until the connection ends, handing each client notification
// (with its ENV lines) to handle.
func (c *ovpnConn) read(handle func(*ovpnEvent)) {
	defer close(c.closed)
	sc := bufio.NewScanner(c.c)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var ev *ovpnEvent
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if !strings.HasPrefix(line, ">") {
			c.answerLine(line)
			continue
		}
		kind, rest, _ := strings.Cut(line[1:], ":")
		if kind != "CLIENT" {
			continue // >INFO, >LOG, >HOLD, ...
		}
		if env, ok := strings.CutPrefix(rest, "ENV,"); ok {
			if ev == nil {
				continue
			}
			if env == "END" {
				handle(ev)
				ev = nil
				continue
			}
			k, v, _ := strings.Cut(env, "=")
			ev.env[k] = v
			continue
		}
		f := strings.Split(rest, ",")
		ev = &ovpnEvent{kind: f[0], env: map[string]string{}}
		if len(f) > 1 {
			ev.cid, _ = strconv.ParseInt(f[1], 10, 64)
		}
		if len(f) > 2 {
			ev.kid, _ = strconv.ParseInt(f[2], 10, 64)
		}
		if ev.kind == "ADDRESS" {
			ev = nil // no ENV lines follow
		}
	}
}
