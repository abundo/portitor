// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/mdlayher/packet"
	"github.com/miekg/dns"

	"github.com/abundo/portitor/internal/agentapi"
)

// setupApp checks the fields of a DNS, HTTP or HTTPS probe.
func (p *prober) setupApp(req *agentapi.ProbeRequest) error {
	switch req.Protocol {
	case "dns":
		name := strings.TrimSuffix(req.Name, ".")
		if name == "" || len(name) > 253 || !dnsName.MatchString(name) {
			return fmt.Errorf("%q is not a DNS name", req.Name)
		}
		p.name = dns.Fqdn(name)
		t := strings.ToUpper(req.Query)
		if t == "" {
			t = "A"
		}
		typ, ok := dns.StringToType[t]
		if !ok || typ == dns.TypeANY || typ == dns.TypeAXFR || typ == dns.TypeIXFR || typ == dns.TypeOPT {
			return fmt.Errorf("record type %q is not supported", req.Query)
		}
		p.qtype = typ
		if len(req.Expect) > agentapi.ProbeMaxExpect || strings.ContainsFunc(req.Expect, func(r rune) bool { return r < ' ' || r == 0x7f }) {
			return errors.New("the expected answer is too long or has control characters")
		}
		p.expect = strings.TrimSpace(req.Expect)
	case "http", "https":
		if _, err := netip.ParseAddr(req.Name); err != nil && (len(req.Name) > 253 || !dnsName.MatchString(req.Name)) {
			return fmt.Errorf("%q is not a host name", req.Name)
		}
		p.name = req.Name
		p.path = req.Path
		if p.path == "" {
			p.path = "/"
		}
		if len(p.path) > agentapi.ProbeMaxPath || p.path[0] != '/' ||
			strings.ContainsFunc(p.path, func(r rune) bool { return r <= ' ' || r == 0x7f || r > 0x7e || r == '#' }) {
			return errors.New("the path must start with / and be plain ASCII without spaces")
		}
	}
	return nil
}

// dnsQuery asks the server p.addr:p.port for p.name over UDP. Any answer
// without an error code is "ok" (with the answer in Info); with an expected
// answer, one of the answer's records has to equal it.
func (p *prober) dnsQuery(ctx context.Context, ev *agentapi.ProbeEvent) {
	d := net.Dialer{Control: bindDevice(p.dev)}
	var nc net.Conn
	err := withNetns(p.netns, func() error {
		var err error
		nc, err = d.DialContext(ctx, "udp", netip.AddrPortFrom(p.addr, uint16(p.port)).String())
		return err
	})
	if err != nil {
		sockResult(ev, err, 0)
		return
	}
	defer nc.Close()
	stop := context.AfterFunc(ctx, func() { _ = nc.SetDeadline(time.Now()) })
	defer stop()
	m := new(dns.Msg)
	m.SetQuestion(p.name, p.qtype)
	m.RecursionDesired = true
	conn := &dns.Conn{Conn: nc}
	start := time.Now()
	if err := conn.WriteMsg(m); err != nil {
		sockResult(ev, err, 0)
		return
	}
	var r *dns.Msg
	for {
		if r, err = conn.ReadMsg(); err != nil || r.Id == m.Id {
			break
		}
	}
	rtt := time.Since(start)
	if err != nil {
		sockResult(ev, err, rtt)
		return
	}
	ev.RTTus = rtt.Microseconds()
	answers := dnsAnswers(r)
	ev.Info = strings.Join(answers, ", ")
	switch {
	case r.Rcode != dns.RcodeSuccess:
		ev.Status, ev.Error = "error", dns.RcodeToString[r.Rcode]
	case p.expect != "" && !dnsMatches(answers, p.expect):
		ev.Status, ev.Error = "error", "not the expected answer"
	default:
		ev.Status = "ok"
	}
}

// dnsAnswers is the data of each record in a response's answer section.
func dnsAnswers(r *dns.Msg) []string {
	var out []string
	for _, rr := range r.Answer {
		h := rr.Header()
		s := strings.TrimPrefix(rr.String(), h.String())
		out = append(out, strings.TrimSpace(s))
	}
	return out
}

// dnsMatches reports whether one of the answers equals want, ignoring case,
// a trailing dot, the quotes around a TXT record and the form of an IPv6
// address.
func dnsMatches(answers []string, want string) bool {
	norm := func(s string) string {
		s = strings.ToLower(strings.TrimSuffix(strings.Trim(strings.TrimSpace(s), `"`), "."))
		if a, err := netip.ParseAddr(s); err == nil {
			return a.String()
		}
		return s
	}
	w := norm(want)
	for _, a := range answers {
		if norm(a) == w {
			return true
		}
	}
	return false
}

// httpGet connects to p.addr:p.port (TLS for https, with the name as SNI)
// and sends GET p.path with the name as Host: any HTTP response is "ok", its
// status line in Info. Redirects are not followed. The certificate is not
// checked: the destination is often an address.
func (p *prober) httpGet(ctx context.Context, ev *agentapi.ProbeEvent) {
	d := net.Dialer{Control: bindDevice(p.dev)}
	tr := &http.Transport{
		Proxy:             nil,
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var c net.Conn
			err := withNetns(p.netns, func() error {
				var err error
				c, err = d.DialContext(ctx, "tcp", netip.AddrPortFrom(p.addr, uint16(p.port)).String())
				return err
			})
			return c, err
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // a connectivity test, not a client
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{
		Transport:     tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	host := p.name
	if a, err := netip.ParseAddr(host); err == nil && a.Is6() {
		host = "[" + host + "]"
	}
	scheme := p.proto
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+host+":"+fmt.Sprint(p.port)+p.path, nil)
	if err != nil {
		ev.Status, ev.Error = "error", err.Error()
		return
	}
	req.Header.Set("User-Agent", "portitor-probe")
	start := time.Now()
	resp, err := client.Do(req)
	rtt := time.Since(start)
	if err != nil {
		var ue interface{ Unwrap() error }
		if errors.As(err, &ue) && ue.Unwrap() != nil {
			err = ue.Unwrap()
		}
		sockResult(ev, err, rtt)
		return
	}
	resp.Body.Close()
	ev.Status, ev.RTTus, ev.Info = "ok", rtt.Microseconds(), resp.Status
}

// ARP.

const arpEtherType = 0x0806

// arpAnswer is the MAC address that answered a request.
type arpAnswer struct {
	at  time.Time
	mac net.HardwareAddr
}

// arpFrame is a broadcast ARP request (42 bytes) for target from sender.
func arpFrame(mac net.HardwareAddr, sender, target netip.Addr) []byte {
	b := make([]byte, 42)
	copy(b[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(b[6:12], mac)
	binary.BigEndian.PutUint16(b[12:], arpEtherType)
	binary.BigEndian.PutUint16(b[14:], 1)      // Ethernet
	binary.BigEndian.PutUint16(b[16:], 0x0800) // IPv4
	b[18], b[19] = 6, 4
	binary.BigEndian.PutUint16(b[20:], 1) // request
	copy(b[22:28], mac)
	s := sender.As4()
	copy(b[28:32], s[:])
	t := target.As4()
	copy(b[38:42], t[:])
	return b
}

// parseARPReply reads an Ethernet frame: the sender's MAC address when it is
// an ARP reply from target.
func parseARPReply(target netip.Addr, b []byte) (net.HardwareAddr, bool) {
	if len(b) < 42 || binary.BigEndian.Uint16(b[12:]) != arpEtherType ||
		binary.BigEndian.Uint16(b[14:]) != 1 || binary.BigEndian.Uint16(b[16:]) != 0x0800 ||
		b[18] != 6 || b[19] != 4 || binary.BigEndian.Uint16(b[20:]) != 2 {
		return nil, false
	}
	if netip.AddrFrom4([4]byte(b[28:32])) != target {
		return nil, false
	}
	return net.HardwareAddr(bytes.Clone(b[22:28])), true
}

// listenARP opens the packet socket on the interface in the namespace and
// reads the replies until it is closed. The sender address is one of the
// interface's own IPv4 addresses (0.0.0.0, an ARP probe, with none).
func (p *prober) listenARP(ctx context.Context) error {
	var c *packet.Conn
	err := withNetns(p.netns, func() error {
		ifi, err := net.InterfaceByName(p.dev)
		if err != nil {
			return err
		}
		if len(ifi.HardwareAddr) != 6 {
			return fmt.Errorf("%s has no ethernet address", p.dev)
		}
		p.ifi = ifi
		p.senderIP = netip.IPv4Unspecified()
		if addrs, err := ifi.Addrs(); err == nil {
			for _, a := range addrs {
				if ipn, ok := a.(*net.IPNet); ok {
					if ip, ok := netip.AddrFromSlice(ipn.IP); ok && ip.Unmap().Is4() {
						p.senderIP = ip.Unmap()
						if ipn.Contains(p.addr.AsSlice()) {
							break // prefer the one on the target's network
						}
					}
				}
			}
		}
		c, err = packet.Listen(ifi, packet.Raw, arpEtherType, nil)
		return err
	})
	if err != nil {
		return fmt.Errorf("open an ARP socket on %s: %w", p.dev, err)
	}
	p.conn = packetConn{c}
	go p.readARP(c)
	return nil
}

// packetConn gives a packet socket the net.PacketConn Close the handler uses.
type packetConn struct{ *packet.Conn }

func (packetConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, errors.New("unused") }
func (packetConn) WriteTo([]byte, net.Addr) (int, error)  { return 0, errors.New("unused") }

func (p *prober) readARP(c *packet.Conn) {
	buf := make([]byte, 2048)
	for {
		n, _, err := c.ReadFrom(buf)
		if err != nil {
			return
		}
		mac, ok := parseARPReply(p.addr, buf[:n])
		if !ok {
			continue
		}
		a := arpAnswer{at: time.Now(), mac: mac}
		// A reply has no sequence number: it answers every request waiting.
		p.mu.Lock()
		for _, ch := range p.arpWait {
			select {
			case ch <- a:
			default:
			}
		}
		p.mu.Unlock()
	}
}

// arp sends an ARP request and waits for the target's reply.
func (p *prober) arp(ctx context.Context, ev *agentapi.ProbeEvent) {
	ch := make(chan arpAnswer, 1)
	p.mu.Lock()
	p.arpWait = append(p.arpWait, ch)
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		for i, c := range p.arpWait {
			if c == ch {
				p.arpWait = append(p.arpWait[:i], p.arpWait[i+1:]...)
				break
			}
		}
		p.mu.Unlock()
	}()
	start := time.Now()
	c := p.conn.(packetConn).Conn
	if _, err := c.WriteTo(arpFrame(p.ifi.HardwareAddr, p.senderIP, p.addr), &packet.Addr{HardwareAddr: net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}}); err != nil {
		sockResult(ev, err, 0)
		return
	}
	select {
	case a := <-ch:
		ev.Status, ev.RTTus, ev.Info = "ok", a.at.Sub(start).Microseconds(), a.mac.String()
	case <-ctx.Done():
		ev.Status = "timeout"
	}
}
