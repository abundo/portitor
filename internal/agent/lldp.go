// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/mdlayher/packet"
	"golang.org/x/sys/unix"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/buildinfo"
)

type (
	LLDPNeighbour = agentapi.LLDPNeighbour
	LLDPPort      = agentapi.LLDPPort
)

// LLDP (IEEE 802.1AB): on each interface with LLDP on, the agent sends a
// frame every lldpInterval announcing the firewall, and keeps what the
// neighbours' frames say until their TTL runs out. Stopping sends a
// shutdown frame (TTL 0), so the neighbours forget the firewall at once.
const (
	lldpEtherType = 0x88cc
	lldpInterval  = 30 * time.Second
	lldpTTL       = 4 * lldpInterval
	lldpRetry     = 10 * time.Second
)

// lldpMulticast is the nearest-bridge address: no bridge forwards it.
var lldpMulticast = net.HardwareAddr{0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e}

// lldpKey is one interface LLDP runs on; descr is its description, sent as
// the port description (changing it restarts the port).
type lldpKey struct {
	instance, netns, iface, descr string
}

// lldpManager runs one goroutine per interface with LLDP on.
type lldpManager struct {
	dryRun bool

	mu    sync.Mutex
	ports map[lldpKey]*lldpPort
	wg    sync.WaitGroup
}

type lldpPort struct {
	cancel     context.CancelFunc
	err        string
	neighbours map[string]*LLDPNeighbour // by chassis and port id
}

func newLLDPManager(dryRun bool) *lldpManager {
	return &lldpManager{dryRun: dryRun, ports: map[lldpKey]*lldpPort{}}
}

// Reconcile starts LLDP on new interfaces and stops it on removed ones.
func (m *lldpManager) Reconcile(want []lldpKey) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, p := range m.ports {
		if !slices.Contains(want, k) {
			p.cancel()
			delete(m.ports, k)
		}
	}
	for _, k := range want {
		if _, ok := m.ports[k]; ok {
			continue
		}
		ctx, cancel := context.WithCancel(context.Background())
		m.ports[k] = &lldpPort{cancel: cancel, neighbours: map[string]*LLDPNeighbour{}}
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			m.loop(ctx, k)
		}()
	}
}

func (m *lldpManager) Stop() {
	m.Reconcile(nil)
	m.wg.Wait()
}

// Snapshot returns the interfaces LLDP runs on and the neighbours heard
// whose TTL has not run out, sorted by instance and interface.
func (m *lldpManager) Snapshot() ([]LLDPPort, []LLDPNeighbour) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	ports := []LLDPPort{}
	neighbours := []LLDPNeighbour{}
	for k, p := range m.ports {
		ports = append(ports, LLDPPort{Instance: k.instance, Interface: k.iface, Error: p.err})
		for id, n := range p.neighbours {
			if !n.Expires.After(now) {
				delete(p.neighbours, id)
				continue
			}
			neighbours = append(neighbours, *n)
		}
	}
	slices.SortFunc(ports, func(a, b LLDPPort) int {
		return strings.Compare(a.Instance+"\x00"+a.Interface, b.Instance+"\x00"+b.Interface)
	})
	slices.SortFunc(neighbours, func(a, b LLDPNeighbour) int {
		return strings.Compare(
			a.Instance+"\x00"+a.Interface+"\x00"+a.SystemName+"\x00"+a.ChassisID+"\x00"+a.PortID,
			b.Instance+"\x00"+b.Interface+"\x00"+b.SystemName+"\x00"+b.ChassisID+"\x00"+b.PortID)
	})
	return ports, neighbours
}

// port runs fn on k's state, if LLDP still runs on k.
func (m *lldpManager) port(k lldpKey, fn func(p *lldpPort)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p, ok := m.ports[k]; ok {
		fn(p)
	}
}

func (m *lldpManager) setErr(k lldpKey, err error) {
	m.port(k, func(p *lldpPort) {
		p.err = ""
		if err != nil {
			p.err = err.Error()
		}
	})
}

func (m *lldpManager) loop(ctx context.Context, k lldpKey) {
	log := slog.With("instance", k.instance, "interface", k.iface)
	if m.dryRun {
		log.Info("dry-run: not starting LLDP")
		m.setErr(k, errors.New("dry-run"))
		return
	}
	for ctx.Err() == nil {
		conn, mac, err := openLLDP(k.netns, k.iface)
		if err == nil {
			m.setErr(k, nil)
			err = m.serve(ctx, k, conn, mac)
			conn.Close()
		}
		if ctx.Err() != nil {
			return
		}
		// The interface may be down, missing or moving namespace: reopen.
		log.Warn("lldp", "err", err)
		m.setErr(k, err)
		if !sleepCtx(ctx, lldpRetry) {
			return
		}
	}
}

// serve sends LLDP frames on conn and records the neighbours' until ctx
// ends (it then sends a shutdown frame) or the socket fails.
func (m *lldpManager) serve(ctx context.Context, k lldpKey, conn *packet.Conn, mac net.HardwareAddr) error {
	readErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 9216)
		for {
			n, _, err := conn.ReadFrom(buf)
			if err != nil {
				readErr <- err
				return
			}
			nb, ok := parseLLDP(buf[:n])
			if !ok || nb.SourceMAC == mac.String() { // our own, sent
				continue
			}
			m.record(k, nb, time.Now())
		}
	}()
	send := func(ttl time.Duration) error {
		_, err := conn.WriteTo(lldpFrame(mac, lldpLocalInfo(k, ttl)), &packet.Addr{HardwareAddr: lldpMulticast})
		return err
	}
	t := time.NewTicker(lldpInterval)
	defer t.Stop()
	for {
		if err := send(lldpTTL); err != nil {
			return fmt.Errorf("send: %w", err)
		}
		select {
		case <-ctx.Done():
			_ = send(0)
			return nil
		case err := <-readErr:
			return fmt.Errorf("receive: %w", err)
		case <-t.C:
		}
	}
}

// record keeps a neighbour's frame; a TTL of 0 (a shutdown) forgets it.
func (m *lldpManager) record(k lldpKey, nb LLDPNeighbour, now time.Time) {
	m.port(k, func(p *lldpPort) {
		id := nb.ChassisIDSubtype + "\x00" + nb.ChassisID + "\x00" + nb.PortIDSubtype + "\x00" + nb.PortID
		if nb.TTL == 0 {
			delete(p.neighbours, id)
			return
		}
		nb.Instance, nb.Interface = k.instance, k.iface
		nb.FirstSeen, nb.LastSeen = now, now
		nb.Expires = now.Add(time.Duration(nb.TTL) * time.Second)
		if old := p.neighbours[id]; old != nil {
			nb.FirstSeen = old.FirstSeen
		}
		p.neighbours[id] = &nb
	})
}

// openLLDP opens a packet socket for LLDP frames on iface in the named
// network namespace, joined to the LLDP multicast address.
func openLLDP(nsName, iface string) (*packet.Conn, net.HardwareAddr, error) {
	var conn *packet.Conn
	var mac net.HardwareAddr
	err := withNetns(nsName, func() error {
		ifi, err := net.InterfaceByName(iface)
		if err != nil {
			return err
		}
		if len(ifi.HardwareAddr) != 6 {
			return fmt.Errorf("%s has no ethernet address", iface)
		}
		c, err := packet.Listen(ifi, packet.Raw, lldpEtherType, nil)
		if err != nil {
			return err
		}
		rc, err := c.SyscallConn()
		if err != nil {
			c.Close()
			return err
		}
		mreq := unix.PacketMreq{Ifindex: int32(ifi.Index), Type: unix.PACKET_MR_MULTICAST, Alen: 6}
		copy(mreq.Address[:], lldpMulticast)
		var serr error
		if err := rc.Control(func(fd uintptr) {
			serr = unix.SetsockoptPacketMreq(int(fd), unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &mreq)
		}); err != nil {
			serr = err
		}
		if serr != nil {
			c.Close()
			return fmt.Errorf("join LLDP multicast: %w", serr)
		}
		conn, mac = c, ifi.HardwareAddr
		return nil
	})
	return conn, mac, err
}

// lldpLocal is what the firewall announces on an interface.
type lldpLocal struct {
	SystemName, SystemDescription string
	PortID, PortDescription       string
	TTL                           time.Duration
}

// lldpLocalInfo is the firewall's announcement on k: the system name is
// the host name, and instance name for an instance with a namespace of its
// own (another router to the neighbours).
func lldpLocalInfo(k lldpKey, ttl time.Duration) lldpLocal {
	host, _ := os.Hostname()
	if host == "" {
		host = "portitor"
	}
	name := host
	if k.netns != "" {
		name += "/" + k.instance
	}
	descr := k.descr
	if descr == "" {
		descr = k.iface
	}
	return lldpLocal{
		SystemName:        name,
		SystemDescription: "Portitor firewall " + buildinfo.Version,
		PortID:            k.iface,
		PortDescription:   descr,
		TTL:               ttl,
	}
}

// LLDP TLV types, chassis and port id subtypes, and capability bits.
const (
	tlvEnd         = 0
	tlvChassisID   = 1
	tlvPortID      = 2
	tlvTTL         = 3
	tlvPortDescr   = 4
	tlvSystemName  = 5
	tlvSystemDescr = 6
	tlvCaps        = 7
	tlvMgmtAddr    = 8
	tlvOrg         = 127

	chassisLocal  = 7
	portIfaceName = 5
	capRouter     = 0x10
)

var chassisSubtypes = map[byte]string{
	1: "chassis component", 2: "interface alias", 3: "port component", 4: "mac",
	5: "network address", 6: "interface name", 7: "local",
}

var portSubtypes = map[byte]string{
	1: "interface alias", 2: "port component", 3: "mac", 4: "network address",
	5: "interface name", 6: "agent circuit id", 7: "local",
}

var capNames = []string{
	"other", "repeater", "bridge", "wlan access point", "router", "telephone",
	"docsis cable device", "station", "c-vlan", "s-vlan", "two-port mac relay",
}

// lldpFrame is an ethernet frame with the LLDP data unit announcing l, from
// src.
func lldpFrame(src net.HardwareAddr, l lldpLocal) []byte {
	b := make([]byte, 0, 128)
	b = append(b, lldpMulticast...)
	b = append(b, src...)
	b = binary.BigEndian.AppendUint16(b, lldpEtherType)
	tlv := func(typ int, value ...[]byte) {
		n := 0
		for _, v := range value {
			n += len(v)
		}
		b = binary.BigEndian.AppendUint16(b, uint16(typ)<<9|uint16(n))
		for _, v := range value {
			b = append(b, v...)
		}
	}
	str := func(s string) []byte {
		if len(s) > 255 {
			s = s[:255]
		}
		return []byte(s)
	}
	tlv(tlvChassisID, []byte{chassisLocal}, str(l.SystemName))
	tlv(tlvPortID, []byte{portIfaceName}, str(l.PortID))
	tlv(tlvTTL, binary.BigEndian.AppendUint16(nil, uint16(l.TTL/time.Second)))
	tlv(tlvPortDescr, str(l.PortDescription))
	tlv(tlvSystemName, str(l.SystemName))
	tlv(tlvSystemDescr, str(l.SystemDescription))
	tlv(tlvCaps, binary.BigEndian.AppendUint16(binary.BigEndian.AppendUint16(nil, capRouter), capRouter))
	tlv(tlvEnd)
	for len(b) < 60 { // the ethernet minimum, without the FCS
		b = append(b, 0)
	}
	return b
}

// parseLLDP reads an ethernet frame with an LLDP data unit; ok is false
// when it isn't one or lacks the mandatory chassis id, port id and TTL.
func parseLLDP(frame []byte) (nb LLDPNeighbour, ok bool) {
	if len(frame) < 14 {
		return nb, false
	}
	nb.SourceMAC = net.HardwareAddr(frame[6:12]).String()
	et, data := binary.BigEndian.Uint16(frame[12:14]), frame[14:]
	if et == 0x8100 && len(data) >= 4 { // a VLAN tag left in place
		et, data = binary.BigEndian.Uint16(data[2:4]), data[4:]
	}
	if et != lldpEtherType {
		return nb, false
	}
	var seen [3]bool
	for len(data) >= 2 {
		h := binary.BigEndian.Uint16(data)
		typ, n := int(h>>9), int(h&0x1ff)
		if len(data) < 2+n {
			return nb, false
		}
		v := data[2 : 2+n]
		data = data[2+n:]
		switch typ {
		case tlvEnd:
			data = nil
		case tlvChassisID, tlvPortID:
			if n < 2 {
				return nb, false
			}
			if typ == tlvChassisID {
				nb.ChassisIDSubtype, nb.ChassisID = idText(chassisSubtypes, v[0], v[1:], 4, 5)
			} else {
				nb.PortIDSubtype, nb.PortID = idText(portSubtypes, v[0], v[1:], 3, 4)
			}
			seen[typ-1] = true
		case tlvTTL:
			if n < 2 {
				return nb, false
			}
			nb.TTL = int(binary.BigEndian.Uint16(v))
			seen[2] = true
		case tlvPortDescr:
			nb.PortDescription = text(v)
		case tlvSystemName:
			nb.SystemName = text(v)
		case tlvSystemDescr:
			nb.SystemDescription = text(v)
		case tlvCaps:
			if n >= 4 {
				nb.Capabilities = capList(binary.BigEndian.Uint16(v))
				nb.EnabledCapabilities = capList(binary.BigEndian.Uint16(v[2:]))
			}
		case tlvMgmtAddr:
			// Address string length (subtype and address), address
			// subtype (IANA family), address, then interface numbering.
			if n >= 2 && int(v[0]) >= 1 && 1+int(v[0]) <= n {
				if a := familyAddr(v[1], v[2:1+v[0]]); a != "" {
					nb.ManagementAddresses = append(nb.ManagementAddresses, a)
				}
			}
		case tlvOrg:
			orgTLV(&nb, v)
		}
	}
	return nb, seen[0] && seen[1] && seen[2]
}

// orgTLV reads the organizationally specific TLVs worth showing: IEEE
// 802.1's port VLAN id and VLAN names, and IEEE 802.3's maximum frame size.
func orgTLV(nb *LLDPNeighbour, v []byte) {
	if len(v) < 4 {
		return
	}
	oui, sub, v := [3]byte(v[:3]), v[3], v[4:]
	switch {
	case oui == [3]byte{0x00, 0x80, 0xc2} && sub == 1 && len(v) >= 2:
		nb.PortVLAN = int(binary.BigEndian.Uint16(v))
	case oui == [3]byte{0x00, 0x80, 0xc2} && sub == 3 && len(v) >= 3 && len(v) >= 3+int(v[2]):
		nb.VLANNames = append(nb.VLANNames, strconv.Itoa(int(binary.BigEndian.Uint16(v)))+" "+text(v[3:3+v[2]]))
	case oui == [3]byte{0x00, 0x12, 0x0f} && sub == 4 && len(v) >= 2:
		nb.MaxFrame = int(binary.BigEndian.Uint16(v))
	}
}

// idText is a chassis or port id as text, with its subtype's name: a MAC
// address (subtype macSub) and a network address (netSub) are formatted,
// other subtypes are text.
func idText(names map[byte]string, sub byte, v []byte, macSub, netSub byte) (string, string) {
	name := names[sub]
	if name == "" {
		name = "subtype " + strconv.Itoa(int(sub))
	}
	switch {
	case sub == macSub && len(v) == 6:
		return name, net.HardwareAddr(v).String()
	case sub == netSub && len(v) > 1:
		if a := familyAddr(v[0], v[1:]); a != "" {
			return name, a
		}
	}
	return name, text(v)
}

// familyAddr is an address of IANA address family fam (1 IPv4, 2 IPv6, 6
// 802 MAC) as text; "" for others.
func familyAddr(fam byte, v []byte) string {
	switch {
	case fam == 1 && len(v) == 4:
		return netip.AddrFrom4([4]byte(v)).String()
	case fam == 2 && len(v) == 16:
		return netip.AddrFrom16([16]byte(v)).String()
	case fam == 6 && len(v) == 6:
		return net.HardwareAddr(v).String()
	}
	return ""
}

// text is a TLV's string: printable UTF-8 as is, anything else in hex.
func text(v []byte) string {
	s := strings.TrimRight(string(v), "\x00")
	if utf8.ValidString(s) && !strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 && r != '\t' && r != '\n' && r != '\r' || r == 0x7f }) {
		return s
	}
	parts := make([]string, len(v))
	for i, c := range v {
		parts[i] = fmt.Sprintf("%02x", c)
	}
	return strings.Join(parts, ":")
}

func capList(bits uint16) []string {
	var out []string
	for i, name := range capNames {
		if bits&(1<<i) != 0 {
			out = append(out, name)
		}
	}
	return out
}
