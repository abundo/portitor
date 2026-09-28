// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	nflog "github.com/florianl/go-nflog/v2"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/render"
)

// packetSnaplen is how much of a logged packet the kernel copies to the
// agent: the IP and transport headers, with room for IPv6 extension
// headers.
const packetSnaplen = 160

// packetLog keeps the packets the rulesets log (to nflog group
// render.LogGroup) for the GUI's log panel. It listens in the namespace of
// each instance whose ruleset logs.
type packetLog struct {
	dryRun  bool
	entries *ring[agentapi.PacketLogEntry]

	mu        sync.Mutex
	listeners map[string]*packetLogRun // by instance
	wg        sync.WaitGroup
}

type packetLogRun struct {
	netns  string
	cancel context.CancelFunc
}

func newPacketLog(dryRun bool) *packetLog {
	return &packetLog{
		dryRun:    dryRun,
		entries:   newRing(2000, func(e *agentapi.PacketLogEntry) *int64 { return &e.ID }),
		listeners: map[string]*packetLogRun{},
	}
}

// logsPackets tells whether an instance's ruleset has a log statement.
func logsPackets(in *fwconfig.Instance) bool {
	if len(in.LogDrops) > 0 || len(in.LogInvalid) > 0 || len(in.LogAuto) > 0 {
		return true
	}
	for _, r := range in.Rules {
		if r.Log && r.Kind != fwconfig.RuleKindComment {
			return true
		}
	}
	return false
}

// After returns the logged packets with an id above after.
func (p *packetLog) After(after int64) []agentapi.PacketLogEntry {
	return p.entries.After(after)
}

// Reconcile listens in the namespaces of want (network namespace by
// instance) and stops listening in the others.
func (p *packetLog) Reconcile(want map[string]string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for name, r := range p.listeners {
		if ns, ok := want[name]; !ok || ns != r.netns {
			r.cancel()
			delete(p.listeners, name)
		}
	}
	for name, ns := range want {
		if _, ok := p.listeners[name]; ok {
			continue
		}
		log := slog.With("instance", name)
		if p.dryRun {
			log.Info("dry-run: not listening for logged packets")
			continue
		}
		ctx, cancel := context.WithCancel(context.Background())
		p.listeners[name] = &packetLogRun{netns: ns, cancel: cancel}
		p.wg.Go(func() { p.run(ctx, name, ns, log) })
	}
}

func (p *packetLog) Stop() {
	p.Reconcile(nil)
	p.wg.Wait()
}

// run listens until ctx is done, starting again when listening fails.
func (p *packetLog) run(ctx context.Context, instance, nsName string, log *slog.Logger) {
	for {
		err := p.listen(ctx, instance, nsName)
		if ctx.Err() != nil {
			return
		}
		log.Warn("packet log", "err", err)
		if !sleepCtx(ctx, 5*time.Second) {
			return
		}
	}
}

func (p *packetLog) listen(ctx context.Context, instance, nsName string) error {
	cfg := nflog.Config{Group: render.LogGroup, Copymode: nflog.CopyPacket, Bufsize: packetSnaplen}
	if nsName != "" {
		ns, err := netns.GetFromName(nsName)
		if err != nil {
			return err
		}
		defer ns.Close() // only needed to open the socket
		cfg.NetNS = int(ns)
	}
	nf, err := nflog.Open(&cfg)
	if err != nil {
		return err
	}
	defer nf.Close()
	h, err := netlinkHandle(nsName)
	if err != nil {
		return err
	}
	defer h.Close()
	// Interface names by index. Indexes are not reused, so an entry only
	// goes stale when its interface is renamed, which apply doesn't do.
	names := map[uint32]string{}
	ifname := func(index *uint32) string {
		if index == nil {
			return ""
		}
		if n, ok := names[*index]; ok {
			return n
		}
		n := strconv.FormatUint(uint64(*index), 10)
		if link, err := h.LinkByIndex(int(*index)); err == nil {
			n = link.Attrs().Name
		}
		names[*index] = n
		return n
	}

	lctx, cancel := context.WithCancel(ctx)
	defer cancel()
	failed := make(chan error, 1)
	err = nf.RegisterWithErrorFunc(lctx, func(a nflog.Attribute) int {
		if a.Prefix == nil || a.Payload == nil {
			return 0
		}
		e, ok := parseLoggedPacket(*a.Prefix, *a.Payload)
		if !ok {
			return 0
		}
		e.Time = time.Now()
		if a.Timestamp != nil {
			e.Time = *a.Timestamp
		}
		e.Instance = instance
		e.InInterface, e.OutInterface = ifname(a.InDev), ifname(a.OutDev)
		e.DstService = serviceName(e.Protocol, e.DstPort)
		p.entries.add(e)
		return 0
	}, func(err error) int {
		if lctx.Err() != nil {
			return 1
		}
		// The kernel dropped messages the agent didn't read in time.
		if errors.Is(err, unix.ENOBUFS) {
			return 0
		}
		failed <- err
		return 1
	})
	if err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return nil
	case err := <-failed:
		return err
	}
}

// parseLoggedPacket makes an entry of a logged packet's prefix (see
// render.LogPrefix) and its IP header onwards; ok is false for a prefix
// that isn't Portitor's or a packet that isn't IP.
func parseLoggedPacket(prefix string, pkt []byte) (e agentapi.PacketLogEntry, ok bool) {
	src, ok := render.ParseLogPrefix(prefix)
	if !ok || len(pkt) < 1 {
		return e, false
	}
	e.Chain, e.Rule, e.Builtin, e.Service, e.Action = src.Chain, src.Rule, src.Builtin, src.Service, src.Action
	var proto uint8
	var l4 []byte // nil when the packet holds no transport header
	switch pkt[0] >> 4 {
	case 4:
		ihl := int(pkt[0]&0x0f) * 4
		if len(pkt) < 20 || ihl < 20 {
			return e, false
		}
		e.Family = "ipv4"
		e.Length = int(binary.BigEndian.Uint16(pkt[2:4]))
		proto = pkt[9]
		e.Src = netip.AddrFrom4([4]byte(pkt[12:16])).String()
		e.Dst = netip.AddrFrom4([4]byte(pkt[16:20])).String()
		// Only the first fragment has the transport header.
		if binary.BigEndian.Uint16(pkt[6:8])&0x1fff == 0 && len(pkt) >= ihl {
			l4 = pkt[ihl:]
		}
	case 6:
		if len(pkt) < 40 {
			return e, false
		}
		e.Family = "ipv6"
		e.Length = 40 + int(binary.BigEndian.Uint16(pkt[4:6]))
		e.Src = netip.AddrFrom16([16]byte(pkt[8:24])).String()
		e.Dst = netip.AddrFrom16([16]byte(pkt[24:40])).String()
		proto, l4 = ipv6Transport(pkt[6], pkt[40:])
	default:
		return e, false
	}
	e.Protocol = protocolName(proto)
	switch proto {
	case unix.IPPROTO_TCP, unix.IPPROTO_UDP, unix.IPPROTO_UDPLITE, unix.IPPROTO_SCTP:
		if len(l4) >= 4 {
			e.SrcPort = binary.BigEndian.Uint16(l4[0:2])
			e.DstPort = binary.BigEndian.Uint16(l4[2:4])
		}
		if proto == unix.IPPROTO_TCP && len(l4) >= 14 {
			e.Info = tcpFlags(l4[13])
		}
	case unix.IPPROTO_ICMP, unix.IPPROTO_ICMPV6:
		if len(l4) >= 2 {
			e.Info = "type " + strconv.Itoa(int(l4[0])) + " code " + strconv.Itoa(int(l4[1]))
		}
	}
	return e, true
}

// ipv6Transport skips the extension headers after the fixed header to the
// transport protocol and its header (nil when not in b, or not in the
// first fragment).
func ipv6Transport(next uint8, b []byte) (uint8, []byte) {
	for {
		switch next {
		case unix.IPPROTO_HOPOPTS, unix.IPPROTO_ROUTING, unix.IPPROTO_DSTOPTS:
			if len(b) < 2 || len(b) < (int(b[1])+1)*8 {
				return next, nil
			}
			next, b = b[0], b[(int(b[1])+1)*8:]
		case unix.IPPROTO_FRAGMENT:
			if len(b) < 8 {
				return next, nil
			}
			if binary.BigEndian.Uint16(b[2:4])&0xfff8 != 0 {
				return b[0], nil
			}
			next, b = b[0], b[8:]
		case unix.IPPROTO_AH:
			if len(b) < 2 || len(b) < (int(b[1])+2)*4 {
				return next, nil
			}
			next, b = b[0], b[(int(b[1])+2)*4:]
		default:
			return next, b
		}
	}
}

func protocolName(p uint8) string {
	switch p {
	case unix.IPPROTO_ICMP:
		return "icmp"
	case unix.IPPROTO_TCP:
		return "tcp"
	case unix.IPPROTO_UDP:
		return "udp"
	case unix.IPPROTO_GRE:
		return "gre"
	case unix.IPPROTO_ESP:
		return "esp"
	case unix.IPPROTO_AH:
		return "ah"
	case unix.IPPROTO_ICMPV6:
		return "ipv6-icmp"
	case unix.IPPROTO_SCTP:
		return "sctp"
	case unix.IPPROTO_UDPLITE:
		return "udplite"
	}
	return strconv.Itoa(int(p))
}

func tcpFlags(f uint8) string {
	var out []string
	for i, name := range []string{"FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"} {
		if f&(1<<i) != 0 {
			out = append(out, name)
		}
	}
	return strings.Join(out, ",")
}
