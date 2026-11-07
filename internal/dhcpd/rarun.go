// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package dhcpd

import (
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

var (
	allNodes   = net.ParseIP("ff02::1")
	allRouters = net.ParseIP("ff02::2")
)

// raManager runs one advertiser per interface with an RAConfig.
type raManager struct {
	ctx context.Context
	mu  sync.Mutex
	ads map[string]*advertiser
}

func newRAManager(ctx context.Context) *raManager {
	return &raManager{ctx: ctx, ads: map[string]*advertiser{}}
}

// sync starts advertising on new interfaces, gives the others their
// config (which starts over with the initial advertisements), and stops
// the ones no longer configured with a final advertisement.
func (m *raManager) sync(cfgs []RAConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()
	want := map[string]bool{}
	for i := range cfgs {
		c := cfgs[i]
		want[c.Interface] = true
		if a := m.ads[c.Interface]; a != nil {
			a.send(raEvent{cfg: &c})
			continue
		}
		a := &advertiser{name: c.Interface, events: make(chan raEvent, 4), rs: make(chan netip.Addr, 16)}
		m.ads[c.Interface] = a
		go a.run(m.ctx, &c)
	}
	for name, a := range m.ads {
		if !want[name] {
			a.send(raEvent{final: true})
			delete(m.ads, name)
		}
	}
}

// advertise sends the initial advertisements again on every interface:
// an HA takeover.
func (m *raManager) advertise() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, a := range m.ads {
		a.send(raEvent{})
	}
	return len(m.ads)
}

// raEvent is a new config (cfg), a stop (final), or neither: advertise
// again now.
type raEvent struct {
	cfg   *RAConfig
	final bool
}

type advertiser struct {
	name   string
	events chan raEvent
	rs     chan netip.Addr

	cfg   *RAConfig
	gone  []gonePrefix
	sched raSched

	index int
	mac   net.HardwareAddr
	conn  *ipv6.PacketConn
	// failed is the last socket error, logged once.
	failed string
}

func (a *advertiser) send(e raEvent) {
	select {
	case a.events <- e:
	default:
		// Full: only a config is worth waiting for.
		if e.cfg != nil || e.final {
			a.events <- e
		}
	}
}

func (a *advertiser) run(ctx context.Context, cfg *RAConfig) {
	a.cfg = cfg
	defer a.close()
	check := time.NewTicker(recheck)
	defer check.Stop()
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	a.ensure(time.Now())
	for {
		if a.conn != nil {
			timer.Reset(time.Until(a.sched.wake()))
		}
		select {
		case <-ctx.Done():
			// The process stops (a restart, an HA standby's or not):
			// clients keep the router until its lifetime ends.
			return
		case e := <-a.events:
			now := time.Now()
			switch {
			case e.final:
				if a.conn != nil {
					a.write(a.marshal(now, true), nil)
					slog.Info("ra: stopped", "interface", a.name)
				}
				return
			case e.cfg != nil:
				a.gone = deprecate(a.gone, a.cfg, e.cfg, now)
				a.cfg = e.cfg
			}
			a.sched.burst(now)
		case src := <-a.rs:
			a.sched.solicit(time.Now(), src, rand.N(raMaxReplyDelay))
		case <-check.C:
			a.ensure(time.Now())
		case <-timer.C:
			if a.conn == nil {
				continue
			}
			now := time.Now()
			mcast, ucast := a.sched.due(now)
			msg := a.marshal(now, false)
			if ucast.IsValid() {
				a.write(msg, ucast.AsSlice())
			}
			if mcast {
				iv := raMinInterval + rand.N(raMaxInterval-raMinInterval)
				a.sched.sent(now, a.write(msg, nil), iv)
			}
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}
}

func (a *advertiser) marshal(now time.Time, final bool) []byte {
	var kept []gonePrefix
	for _, g := range a.gone {
		if g.Until.After(now) {
			kept = append(kept, g)
		}
	}
	a.gone = kept
	return marshalRA(a.cfg, a.mac, a.gone, now, final)
}

// ensure opens the socket once the interface is there and up, and again
// when it is recreated; a socket newly opened starts with the initial
// advertisements.
func (a *advertiser) ensure(now time.Time) {
	ifi, err := net.InterfaceByName(a.name)
	if a.conn != nil {
		if err == nil && ifi.Index == a.index && ifi.Flags&net.FlagUp != 0 {
			return
		}
		a.close()
	}
	if err == nil && ifi.Flags&net.FlagUp == 0 {
		err = errors.New("interface is down")
	}
	var c *ipv6.PacketConn
	if err == nil {
		c, err = openRA(ifi)
	}
	if err != nil {
		if a.failed != err.Error() {
			slog.Warn("ra: not advertising yet", "interface", a.name, "err", err)
			a.failed = err.Error()
		}
		return
	}
	a.failed = ""
	a.conn, a.index, a.mac = c, ifi.Index, ifi.HardwareAddr
	go a.read(c)
	a.sched.burst(now)
	slog.Info("ra: advertising", "interface", a.name)
}

func (a *advertiser) close() {
	if a.conn != nil {
		a.conn.Close()
		a.conn = nil
	}
}

// read passes the valid router solicitations' sources to run.
func (a *advertiser) read(c *ipv6.PacketConn) {
	buf := make([]byte, 1500)
	for {
		n, cm, src, err := c.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		ip, ok := src.(*net.IPAddr)
		if !ok || cm == nil {
			continue
		}
		addr, ok := netip.AddrFromSlice(ip.IP)
		if !ok || !validRS(buf[:n], cm.HopLimit, addr.Unmap()) {
			continue
		}
		select {
		case a.rs <- addr.Unmap():
		default:
		}
	}
}

// write sends msg to dst (nil: all nodes) from the interface's link-local
// address, as RFC 4861 requires; false if it has none usable yet (DAD).
func (a *advertiser) write(msg []byte, dst net.IP) bool {
	src := linkLocal(a.index)
	if !src.IsValid() {
		return false
	}
	if dst == nil {
		dst = allNodes
	}
	cm := &ipv6.ControlMessage{HopLimit: 255, Src: src.AsSlice(), IfIndex: a.index}
	if _, err := a.conn.WriteTo(msg, cm, &net.IPAddr{IP: dst, Zone: a.name}); err != nil {
		slog.Warn("ra: not sent", "interface", a.name, "to", dst, "err", err)
		return false
	}
	return true
}

// linkLocal is the interface's link-local address, once DAD is done.
func linkLocal(index int) netip.Addr {
	link, err := netlink.LinkByIndex(index)
	if err != nil {
		return netip.Addr{}
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V6)
	if err != nil {
		return netip.Addr{}
	}
	for _, ad := range addrs {
		if ad.Flags&(unix.IFA_F_TENTATIVE|unix.IFA_F_DADFAILED) != 0 {
			continue
		}
		if a, ok := netip.AddrFromSlice(ad.IP); ok && a.Is6() && a.IsLinkLocalUnicast() {
			return a
		}
	}
	return netip.Addr{}
}

// openRA opens a raw ICMPv6 socket on the interface that hears router
// solicitations alone and sends with hop limit 255.
func openRA(ifi *net.Interface) (*ipv6.PacketConn, error) {
	lc := net.ListenConfig{Control: func(_, _ string, rc syscall.RawConn) error {
		var serr error
		if err := rc.Control(func(fd uintptr) {
			serr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, ifi.Name)
		}); err != nil {
			return err
		}
		return serr
	}}
	c, err := lc.ListenPacket(context.Background(), "ip6:ipv6-icmp", "::")
	if err != nil {
		return nil, err
	}
	p := ipv6.NewPacketConn(c)
	var f ipv6.ICMPFilter
	f.SetAll(true)
	f.Accept(ipv6.ICMPTypeRouterSolicitation)
	for _, err := range []error{
		p.SetICMPFilter(&f),
		p.SetControlMessage(ipv6.FlagHopLimit, true),
		p.SetHopLimit(255),
		p.SetMulticastHopLimit(255),
		p.SetMulticastLoopback(false),
		p.SetMulticastInterface(ifi),
		p.JoinGroup(ifi, &net.IPAddr{IP: allRouters}),
	} {
		if err != nil {
			p.Close()
			return nil, err
		}
	}
	return p, nil
}
