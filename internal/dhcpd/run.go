// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package dhcpd

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

// Options are where the process finds its files.
type Options struct {
	// Config is dhcpd.json.
	Config string
	// LeaseDir holds the lease log, written by this process alone.
	LeaseDir string
	// Socket is the control socket the agent connects to.
	Socket string
}

// LeaseFile is the lease log's name in LeaseDir.
const LeaseFile = "leases.log"

// recheck is how often the sockets are matched to the interfaces: one
// that is missing or down is retried, one recreated reopened.
const recheck = 2 * time.Second

// Run serves until ctx ends. SIGHUP reads the config again.
func Run(ctx context.Context, o Options) error {
	// First: a SIGHUP before the handler would end the process.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	cfg, err := LoadConfig(o.Config)
	if err != nil {
		return err
	}
	st, err := OpenStore(filepath.Join(o.LeaseDir, LeaseFile))
	if err != nil {
		return err
	}
	defer st.Close()
	srv := NewServer(cfg, st)
	srv.probe = arpProbe

	ra := newRAManager(ctx)
	ra.sync(cfg.RA)

	ctl, err := listenControl(o.Socket)
	if err != nil {
		return err
	}
	defer ctl.Close()
	go serveControl(ctl, srv, ra)

	ls := &listeners{srv: srv, open: map[string]*listener{}}
	defer ls.closeAll()
	ls.sync(cfg)

	flush := time.NewTicker(time.Second)
	defer flush.Stop()
	check := time.NewTicker(recheck)
	defer check.Stop()
	slog.Info("dhcpd started", "instance", cfg.Instance, "subnets4", len(cfg.Subnets4), "subnets6", len(cfg.Subnets6), "ra", len(cfg.RA))
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-hup:
			c, err := LoadConfig(o.Config)
			if err != nil {
				slog.Error("dhcpd: config not reloaded", "err", err)
				continue
			}
			cfg = c
			srv.SetConfig(cfg)
			ls.sync(cfg)
			ra.sync(cfg.RA)
			slog.Info("dhcpd: config reloaded", "subnets4", len(cfg.Subnets4), "subnets6", len(cfg.Subnets6), "ra", len(cfg.RA))
		case <-check.C:
			ls.sync(cfg)
		case <-flush.C:
			if err := srv.Flush(); err != nil {
				slog.Error("dhcpd: lease log", "err", err)
			}
		}
	}
}

// listener is one socket: DHCPv4 or DHCPv6 on one interface.
type listener struct {
	ifname string
	index  int
	v6     bool
	conn   *net.UDPConn
}

func (l *listener) key() string {
	if l.v6 {
		return "6/" + l.ifname
	}
	return "4/" + l.ifname
}

type listeners struct {
	srv  *Server
	mu   sync.Mutex
	open map[string]*listener
	// failed remembers the last error per socket, logged once.
	failed map[string]string
}

// sync opens the sockets the config wants and closes the rest; a socket
// whose interface was recreated (a new index) is opened again.
func (ls *listeners) sync(cfg *Config) {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	if ls.failed == nil {
		ls.failed = map[string]string{}
	}
	want := map[string]bool{}
	for _, v6 := range []bool{false, true} {
		for _, name := range cfg.Interfaces(v6) {
			l := &listener{ifname: name, v6: v6}
			k := l.key()
			want[k] = true
			ifi, err := net.InterfaceByName(name)
			if cur := ls.open[k]; cur != nil {
				if err == nil && ifi.Index == cur.index {
					continue
				}
				cur.conn.Close()
				delete(ls.open, k)
			}
			if err == nil && ifi.Flags&net.FlagUp == 0 {
				err = errors.New("interface is down")
			}
			if err == nil {
				l.index = ifi.Index
				if v6 {
					l.conn, err = open6(ifi)
				} else {
					l.conn, err = open4(name)
				}
			}
			if err != nil {
				if ls.failed[k] != err.Error() {
					slog.Warn("dhcpd: not listening yet", "socket", k, "err", err)
					ls.failed[k] = err.Error()
				}
				continue
			}
			delete(ls.failed, k)
			ls.open[k] = l
			slog.Info("dhcpd: listening", "socket", k)
			if v6 {
				go ls.serve6(l)
			} else {
				go ls.serve4(l)
			}
		}
	}
	for k, l := range ls.open {
		if !want[k] {
			l.conn.Close()
			delete(ls.open, k)
			slog.Info("dhcpd: closed", "socket", k)
		}
	}
}

func (ls *listeners) closeAll() {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	for k, l := range ls.open {
		l.conn.Close()
		delete(ls.open, k)
	}
}

// listen opens a UDP socket bound to the interface, so each interface has
// its own on the same port.
func listen(network, addr, ifname string, broadcast bool) (*net.UDPConn, error) {
	lc := net.ListenConfig{Control: func(_, _ string, rc syscall.RawConn) error {
		var serr error
		err := rc.Control(func(fd uintptr) {
			if serr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, ifname); serr != nil {
				return
			}
			if serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); serr != nil {
				return
			}
			if broadcast {
				serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_BROADCAST, 1)
			}
		})
		if err != nil {
			return err
		}
		return serr
	}}
	c, err := lc.ListenPacket(context.Background(), network, addr)
	if err != nil {
		return nil, err
	}
	return c.(*net.UDPConn), nil
}

func open4(ifname string) (*net.UDPConn, error) {
	return listen("udp4", "0.0.0.0:67", ifname, true)
}

var allServers = &net.UDPAddr{IP: net.ParseIP("ff02::1:2")}

func open6(ifi *net.Interface) (*net.UDPConn, error) {
	c, err := listen("udp6", "[::]:547", ifi.Name, false)
	if err != nil {
		return nil, err
	}
	if err := ipv6.NewPacketConn(c).JoinGroup(ifi, allServers); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

func (ls *listeners) serve4(l *listener) {
	buf := make([]byte, 1500)
	for {
		n, src, err := l.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		req, err := Parse4(buf[:n])
		if err != nil {
			continue
		}
		r, dst := ls.srv.Serve4(l.ifname, req, src)
		if r == nil {
			continue
		}
		if _, err := l.conn.WriteToUDPAddrPort(r.Marshal(req.MaxSize()), dst); err != nil {
			slog.Warn("dhcp: reply not sent", "interface", l.ifname, "to", dst, "err", err)
		}
	}
}

func (ls *listeners) serve6(l *listener) {
	buf := make([]byte, 65536)
	for {
		n, src, err := l.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		pkt, err := dhcpv6.FromBytes(buf[:n])
		if err != nil {
			continue
		}
		msg, ok := pkt.(*dhcpv6.Message)
		if !ok {
			// Relayed messages: Portitor runs no relays.
			continue
		}
		// The MAC address, for reservations and the lease list. A REQUEST
		// follows our ADVERTISE, so the neighbour table has it by then;
		// only reservations are worth waiting for it.
		mac := ""
		if m := neighbourMAC(l.index, src, ls.srv.NeedsMAC6(l.ifname)); m != nil {
			mac = m.String()
		}
		r := ls.srv.Serve6(l.ifname, msg, src, mac)
		if r == nil {
			continue
		}
		if _, err := l.conn.WriteToUDPAddrPort(r.ToBytes(), src); err != nil {
			slog.Warn("dhcpv6: reply not sent", "interface", l.ifname, "to", src, "err", err)
		}
	}
}

// neighbourMAC is the MAC address of src in the neighbour table. Without
// an entry, and with wait, it sends src a datagram, which makes the kernel
// solicit it, and looks again for up to 500 ms.
func neighbourMAC(index int, src netip.AddrPort, wait bool) net.HardwareAddr {
	a := src.Addr().WithZone("")
	lookup := func() net.HardwareAddr {
		ns, err := netlink.NeighList(index, netlink.FAMILY_V6)
		if err != nil {
			return nil
		}
		for _, n := range ns {
			if ip, ok := netip.AddrFromSlice(n.IP); ok && ip == a && len(n.HardwareAddr) == 6 &&
				n.State&(netlink.NUD_INCOMPLETE|netlink.NUD_FAILED) == 0 {
				return n.HardwareAddr
			}
		}
		return nil
	}
	if m := lookup(); m != nil || !wait {
		return m
	}
	if c, err := net.DialUDP("udp6", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(src.Addr(), 9))); err == nil {
		c.Write([]byte{0})
		c.Close()
	}
	for range 10 {
		time.Sleep(50 * time.Millisecond)
		if m := lookup(); m != nil {
			return m
		}
	}
	return nil
}

// The control socket takes one JSON request per connection and answers
// it: "leases" is every lease; "changes", "acked" and "apply" are the
// replication to an HA pair's standby (repl.go); "advertise" sends the
// initial router advertisements again (an HA takeover).

// Control is a request on the control socket.
type Control struct {
	Op string `json:"op"`
	// changes: the poller's last batch, and how long to wait (ms).
	Epoch  uint64 `json:"epoch,omitempty"`
	Seq    uint64 `json:"seq,omitempty"`
	WaitMS int    `json:"wait_ms,omitempty"`
	// apply: the active host's leases.
	Leases []Lease `json:"leases,omitempty"`
}

// ControlReply is its answer.
type ControlReply struct {
	Leases []Lease `json:"leases,omitempty"`
	// changes.
	Changes *Changes `json:"changes,omitempty"`
	// apply: how many leases it took; advertise: on how many interfaces.
	Applied int    `json:"applied,omitempty"`
	Error   string `json:"error,omitempty"`
}

func listenControl(path string) (net.Listener, error) {
	_ = os.Remove(path)
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	// The agent (root) alone connects.
	os.Chmod(path, 0o600)
	return l, nil
}

func serveControl(l net.Listener, srv *Server, ra *raManager) {
	for {
		c, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		go func() {
			defer c.Close()
			c.SetDeadline(time.Now().Add(10 * time.Second))
			var req Control
			if err := json.NewDecoder(bufio.NewReader(c)).Decode(&req); err != nil {
				return
			}
			var rep ControlReply
			switch req.Op {
			case "leases":
				rep.Leases = srv.Leases()
			case "changes":
				wait := min(time.Duration(req.WaitMS)*time.Millisecond, 5*time.Second)
				ch := srv.Changes(context.Background(), req.Epoch, req.Seq, wait)
				rep.Changes = &ch
			case "acked":
				srv.Acked(req.Seq)
			case "apply":
				n, err := srv.Apply(req.Leases)
				rep.Applied = n
				if err != nil {
					rep.Error = err.Error()
				}
			case "advertise":
				rep.Applied = ra.advertise()
			default:
				rep.Error = "unknown op " + req.Op
			}
			json.NewEncoder(c).Encode(rep)
		}()
	}
}

// Query asks the dhcpd at socket.
func Query(ctx context.Context, socket string, req Control) (*ControlReply, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", socket)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	} else {
		c.SetDeadline(time.Now().Add(5 * time.Second))
	}
	if err := json.NewEncoder(c).Encode(req); err != nil {
		return nil, err
	}
	var rep ControlReply
	if err := json.NewDecoder(c).Decode(&rep); err != nil {
		return nil, err
	}
	if rep.Error != "" {
		return nil, errors.New(rep.Error)
	}
	return &rep, nil
}
