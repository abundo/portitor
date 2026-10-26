// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/fwconfig"
)

// probes counts the running connectivity tests (agentapi.ProbeMaxSessions).
var probes atomic.Int32

// handleProbe sends ICMP echoes, TCP connects or UDP datagrams from the
// instance's namespace at an interval and streams each one's result as an
// agentapi.ProbeEvent, one JSON line each. The sockets are the agent's own,
// opened in the namespace (withNetns). The client disconnecting stops it.
func (a *Agent) handleProbe(w http.ResponseWriter, r *http.Request) {
	var req agentapi.ProbeRequest
	if !decode(w, r, &req) {
		return
	}
	if a.cfg.DryRun {
		writeError(w, http.StatusServiceUnavailable, errors.New("connectivity tests are not available in dry-run mode"))
		return
	}
	a.mu.Lock()
	var in *fwconfig.Instance
	if a.applied != nil {
		d := a.applied.Expand()
		in = d.Instance(req.Instance)
	}
	a.mu.Unlock()
	if in == nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("no applied instance %q", req.Instance))
		return
	}
	ns := in.NetnsName()
	if _, err := netip.ParseAddr(req.Target); err != nil {
		if len(req.Target) > 253 || !dnsName.MatchString(req.Target) {
			writeError(w, http.StatusBadRequest, fmt.Errorf("target %q is not an IP address or a DNS name", req.Target))
			return
		}
		addr, err := resolveName(r.Context(), ns, req.Target, req.Family)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		req.Target = addr.String()
	}
	p, err := newProber(in, &req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if probes.Add(1) > agentapi.ProbeMaxSessions {
		probes.Add(-1)
		writeError(w, http.StatusTooManyRequests, fmt.Errorf("%d connectivity tests are already running", agentapi.ProbeMaxSessions))
		return
	}
	defer probes.Add(-1)

	ctx, cancel := context.WithTimeout(r.Context(), agentapi.ProbeMaxTime)
	defer cancel()
	if p.proto == "icmp" {
		if err := p.listen(ctx); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		defer p.conn.Close()
	}
	slog.Info("connectivity test started", "instance", req.Instance, "interface", req.Interface, "target", req.Target, "protocol", req.Protocol, "port", req.Port, "remote", r.RemoteAddr)

	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{}) // the server's timeout is for requests
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	// Each probe sends its result from its own goroutine.
	var sendMu sync.Mutex
	send := func(ev agentapi.ProbeEvent) bool {
		sendMu.Lock()
		defer sendMu.Unlock()
		if enc.Encode(ev) != nil {
			cancel()
			return false
		}
		_ = rc.Flush()
		return true
	}
	send(agentapi.ProbeEvent{Type: "target", Addr: p.addr.String(), Protocol: p.proto, Port: p.port})

	var running sync.WaitGroup
	tick := time.NewTicker(p.interval)
	defer tick.Stop()
loop:
	for seq := 1; ; seq++ {
		running.Go(func() {
			ev := p.probe(ctx, seq)
			if ctx.Err() == nil {
				send(ev)
			}
		})
		if seq == req.Count {
			break
		}
		select {
		case <-ctx.Done():
			break loop
		case <-tick.C:
		}
	}
	running.Wait()
	slog.Info("connectivity test ended", "instance", req.Instance, "target", req.Target, "protocol", req.Protocol)
}

// prober sends one kind of probe to one address.
type prober struct {
	netns    string
	dev      string
	proto    string
	addr     netip.Addr
	port     int
	interval time.Duration
	timeout  time.Duration
	size     int
	payload  []byte

	// ICMP: the raw socket, the echo id and the echoes waiting for an
	// answer, by sequence number.
	conn    net.PacketConn
	id      int
	mu      sync.Mutex
	pending map[uint16]chan icmpAnswer
}

// newProber checks and clamps the request.
func newProber(in *fwconfig.Instance, req *agentapi.ProbeRequest) (*prober, error) {
	addr, err := netip.ParseAddr(req.Target)
	if err != nil || addr.Zone() != "" {
		return nil, fmt.Errorf("target %q is not an IP address", req.Target)
	}
	p := &prober{netns: in.NetnsName(), proto: req.Protocol, addr: addr.Unmap()}
	switch req.Protocol {
	case "icmp":
	case "tcp", "udp":
		if req.Port < 1 || req.Port > 65535 {
			return nil, fmt.Errorf("port %d is not 1-65535", req.Port)
		}
		p.port = req.Port
	default:
		return nil, fmt.Errorf("protocol %q is not icmp, tcp or udp", req.Protocol)
	}
	if req.Interface != "" {
		if in.Interface(req.Interface) == nil {
			return nil, fmt.Errorf("instance %s has no interface %q", in.Name, req.Interface)
		}
		p.dev = req.Interface
	}
	if req.Count < 0 || req.Count > agentapi.ProbeMaxCount {
		return nil, fmt.Errorf("count must be 0-%d", agentapi.ProbeMaxCount)
	}
	if req.Interval == 0 {
		req.Interval = agentapi.ProbeDefaultInterval
	}
	req.Interval = min(max(req.Interval, agentapi.ProbeMinInterval), agentapi.ProbeMaxInterval)
	if req.Timeout <= 0 {
		req.Timeout = agentapi.ProbeDefaultTimeout
	}
	req.Timeout = min(req.Timeout, agentapi.ProbeMaxTimeout)
	if req.Size <= 0 {
		req.Size = agentapi.ProbeDefaultSize
	}
	req.Size = min(req.Size, agentapi.ProbeMaxSize)
	if len(req.Payload) > agentapi.ProbeMaxPayload {
		return nil, fmt.Errorf("the payload is longer than %d bytes", agentapi.ProbeMaxPayload)
	}
	p.interval = time.Duration(req.Interval) * time.Millisecond
	p.timeout = time.Duration(req.Timeout) * time.Millisecond
	p.size = req.Size
	p.payload = []byte(req.Payload)
	return p, nil
}

// bindDevice is a socket's Control that binds it to dev (SO_BINDTODEVICE);
// nil for none.
func bindDevice(dev string) func(network, address string, c syscall.RawConn) error {
	if dev == "" {
		return nil
	}
	return func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, dev)
		}); err != nil {
			return err
		}
		if serr != nil {
			return fmt.Errorf("bind to %s: %w", dev, serr)
		}
		return nil
	}
}

// probe sends probe seq and waits for its result.
func (p *prober) probe(ctx context.Context, seq int) agentapi.ProbeEvent {
	ev := agentapi.ProbeEvent{Type: "probe", Seq: seq, At: time.Now().UnixMilli()}
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	switch p.proto {
	case "icmp":
		p.echo(ctx, seq, &ev)
	case "tcp":
		p.connect(ctx, &ev)
	case "udp":
		p.datagram(ctx, &ev)
	}
	return ev
}

// connect opens a TCP connection: "ok" once it is up, "refused" on a reset.
func (p *prober) connect(ctx context.Context, ev *agentapi.ProbeEvent) {
	d := net.Dialer{Control: bindDevice(p.dev)}
	start := time.Now()
	var conn net.Conn
	err := withNetns(p.netns, func() error {
		var err error
		conn, err = d.DialContext(ctx, "tcp", netip.AddrPortFrom(p.addr, uint16(p.port)).String())
		return err
	})
	rtt := time.Since(start)
	if err == nil {
		conn.Close()
	}
	sockResult(ev, err, rtt)
}

// datagram sends a UDP datagram and waits for an answer: "ok" for any
// datagram back, "refused" for an ICMP port unreachable. A service that
// does not answer what it was sent times out.
func (p *prober) datagram(ctx context.Context, ev *agentapi.ProbeEvent) {
	d := net.Dialer{Control: bindDevice(p.dev)}
	var conn net.Conn
	err := withNetns(p.netns, func() error {
		var err error
		conn, err = d.DialContext(ctx, "udp", netip.AddrPortFrom(p.addr, uint16(p.port)).String())
		return err
	})
	if err != nil {
		sockResult(ev, err, 0)
		return
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()
	start := time.Now()
	if _, err = conn.Write(p.payload); err == nil {
		_, err = conn.Read(make([]byte, 2048))
	}
	sockResult(ev, err, time.Since(start))
}

// sockResult sets a TCP or UDP probe's status from its socket's error.
func sockResult(ev *agentapi.ProbeEvent, err error, rtt time.Duration) {
	switch {
	case err == nil:
		ev.Status, ev.RTTus = "ok", rtt.Microseconds()
	case errors.Is(err, syscall.ECONNREFUSED):
		ev.Status, ev.RTTus = "refused", rtt.Microseconds()
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded):
		ev.Status = "timeout"
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH),
		errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM):
		ev.Status, ev.Error = "unreachable", unwrapErrno(err)
	default:
		ev.Status, ev.Error = "error", unwrapErrno(err)
	}
}

// unwrapErrno is the errno's text when err has one ("no route to host"),
// without the addresses net.OpError adds.
func unwrapErrno(err error) string {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno.Error()
	}
	return err.Error()
}

// icmpAnswer is what came back for an echo: a reply, or an error about it
// from From.
type icmpAnswer struct {
	at     time.Time
	status string
	from   netip.Addr
	reason string
}

// listen opens the raw ICMP socket in the namespace and reads the answers
// until it is closed. Every raw socket sees all ICMP, so the echoes carry an
// id of their own.
func (p *prober) listen(ctx context.Context) error {
	network, laddr := "ip4:icmp", "0.0.0.0"
	if p.addr.Is6() {
		network, laddr = "ip6:ipv6-icmp", "::"
	}
	lc := net.ListenConfig{Control: bindDevice(p.dev)}
	err := withNetns(p.netns, func() error {
		var err error
		p.conn, err = lc.ListenPacket(ctx, network, laddr)
		return err
	})
	if err != nil {
		return fmt.Errorf("open an ICMP socket: %w", err)
	}
	p.id = rand.IntN(0x10000)
	p.pending = map[uint16]chan icmpAnswer{}
	go p.read()
	return nil
}

func (p *prober) read() {
	buf := make([]byte, 65536)
	for {
		n, from, err := p.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		at := time.Now()
		src, _ := netip.AddrFromSlice(from.(*net.IPAddr).IP)
		seq, a, ok := parseICMPAnswer(p.addr, p.id, buf[:n])
		if !ok {
			continue
		}
		a.at, a.from = at, src.Unmap()
		if a.status == "ok" && a.from != p.addr {
			continue
		}
		p.mu.Lock()
		ch := p.pending[seq]
		p.mu.Unlock()
		if ch != nil {
			select {
			case ch <- a:
			default:
			}
		}
	}
}

// parseICMPAnswer reads an ICMP message: an echo reply with our id, or an
// error that quotes an echo of ours to target. A raw IPv4 socket's packets
// come without their IP header (the net package strips it).
func parseICMPAnswer(target netip.Addr, id int, b []byte) (uint16, icmpAnswer, bool) {
	proto := 1
	if target.Is6() {
		proto = 58
	}
	m, err := icmp.ParseMessage(proto, b)
	if err != nil {
		return 0, icmpAnswer{}, false
	}
	var quoted []byte
	switch body := m.Body.(type) {
	case *icmp.Echo:
		if (m.Type != ipv4.ICMPTypeEchoReply && m.Type != ipv6.ICMPTypeEchoReply) || body.ID != id {
			return 0, icmpAnswer{}, false
		}
		return uint16(body.Seq), icmpAnswer{status: "ok"}, true
	case *icmp.DstUnreach:
		quoted = body.Data
	case *icmp.TimeExceeded:
		quoted = body.Data
	case *icmp.PacketTooBig:
		quoted = body.Data
	default:
		return 0, icmpAnswer{}, false
	}
	seq, ok := quotedEcho(target, id, quoted)
	if !ok {
		return 0, icmpAnswer{}, false
	}
	return seq, icmpAnswer{status: "unreachable", reason: icmpReason(m)}, true
}

// quotedEcho finds our echo to target in the packet an ICMP error quotes
// (its IP header and the first bytes of the echo) and returns its sequence
// number.
func quotedEcho(target netip.Addr, id int, q []byte) (uint16, bool) {
	var dst netip.Addr
	var echo []byte
	if target.Is4() {
		if len(q) < 20 || q[0]>>4 != 4 || q[9] != 1 {
			return 0, false
		}
		hl := int(q[0]&0x0f) * 4
		if len(q) < hl+8 {
			return 0, false
		}
		dst = netip.AddrFrom4([4]byte(q[16:20]))
		echo = q[hl:]
		if echo[0] != byte(ipv4.ICMPTypeEcho) {
			return 0, false
		}
	} else {
		if len(q) < 48 || q[0]>>4 != 6 || q[6] != 58 {
			return 0, false
		}
		dst = netip.AddrFrom16([16]byte(q[24:40]))
		echo = q[40:]
		if echo[0] != byte(ipv6.ICMPTypeEchoRequest) {
			return 0, false
		}
	}
	if dst != target || int(echo[4])<<8|int(echo[5]) != id {
		return 0, false
	}
	return uint16(echo[6])<<8 | uint16(echo[7]), true
}

// icmpReason names an ICMP error.
func icmpReason(m *icmp.Message) string {
	switch m.Type {
	case ipv4.ICMPTypeDestinationUnreachable:
		switch m.Code {
		case 0:
			return "network unreachable"
		case 1:
			return "host unreachable"
		case 2:
			return "protocol unreachable"
		case 3:
			return "port unreachable"
		case 4:
			return "fragmentation needed"
		case 9, 10, 13:
			return "administratively prohibited"
		}
		return fmt.Sprintf("destination unreachable (code %d)", m.Code)
	case ipv6.ICMPTypeDestinationUnreachable:
		switch m.Code {
		case 0:
			return "no route to destination"
		case 1:
			return "administratively prohibited"
		case 3:
			return "address unreachable"
		case 4:
			return "port unreachable"
		case 5, 6:
			return "rejected by policy"
		}
		return fmt.Sprintf("destination unreachable (code %d)", m.Code)
	case ipv4.ICMPTypeTimeExceeded, ipv6.ICMPTypeTimeExceeded:
		return "time to live exceeded"
	case ipv6.ICMPTypePacketTooBig:
		return "packet too big"
	}
	return fmt.Sprintf("ICMP type %v code %d", m.Type, m.Code)
}

// echo sends ICMP echo seq and waits for its answer.
func (p *prober) echo(ctx context.Context, seq int, ev *agentapi.ProbeEvent) {
	key := uint16(seq)
	ch := make(chan icmpAnswer, 1)
	p.mu.Lock()
	p.pending[key] = ch
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		if p.pending[key] == ch {
			delete(p.pending, key)
		}
		p.mu.Unlock()
	}()
	var typ icmp.Type = ipv4.ICMPTypeEcho
	if p.addr.Is6() {
		typ = ipv6.ICMPTypeEchoRequest
	}
	// The kernel fills in an ICMPv6 checksum on a raw socket.
	b, err := (&icmp.Message{Type: typ, Body: &icmp.Echo{ID: p.id, Seq: int(key), Data: make([]byte, p.size)}}).Marshal(nil)
	if err != nil {
		ev.Status, ev.Error = "error", err.Error()
		return
	}
	start := time.Now()
	if _, err := p.conn.WriteTo(b, &net.IPAddr{IP: p.addr.AsSlice()}); err != nil {
		sockResult(ev, err, 0)
		return
	}
	select {
	case a := <-ch:
		ev.Status = a.status
		if a.status == "ok" {
			ev.RTTus = a.at.Sub(start).Microseconds()
		} else {
			ev.From, ev.Error = a.from.String(), a.reason
		}
	case <-ctx.Done():
		ev.Status = "timeout"
	}
}
