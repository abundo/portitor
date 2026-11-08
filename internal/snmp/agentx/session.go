// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agentx

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"syscall"
	"time"
)

// Handler answers the master's reads of the registered subtree.
type Handler interface {
	// Get is the value of exactly oid; false when there is none.
	Get(oid OID) (Value, bool)
	// Next is the first object after oid (oid itself too when include)
	// and before end (no bound when empty); false when there is none.
	Next(oid OID, include bool, end OID) (VarBind, bool)
}

// Session is a subagent's session with the master agent over its Unix
// socket, Path: it registers Subtree and answers from Handler until its
// context ends, connecting again when the master goes away.
type Session struct {
	Path    string
	Subtree OID
	// Name describes the subagent to the master.
	Name    string
	Handler Handler
	// Retry is the wait before connecting again (default 10 s).
	Retry time.Duration
	Log   *slog.Logger

	mu        sync.Mutex
	connected bool
}

// Connected reports whether the session is registered with the master.
func (s *Session) Connected() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connected
}

// Run keeps the session until ctx ends.
func (s *Session) Run(ctx context.Context) {
	retry := s.Retry
	if retry == 0 {
		retry = 10 * time.Second
	}
	log := s.Log
	if log == nil {
		log = slog.Default()
	}
	var last string
	for ctx.Err() == nil {
		err := s.connect(ctx)
		if ctx.Err() != nil {
			return
		}
		// Say it once, not every retry; no master there (SNMP off, snmpd
		// starting) is no news.
		switch msg := fmt.Sprint(err); {
		case errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ECONNREFUSED):
			log.Debug("snmp: no AgentX master", "socket", s.Path, "err", err)
		case msg != last:
			log.Warn("snmp: the AgentX session with snmpd ended; trying again", "socket", s.Path, "err", err)
			last = msg
		}
		select {
		case <-ctx.Done():
		case <-time.After(retry):
		}
	}
}

func (s *Session) connect(ctx context.Context) error {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", s.Path)
	if err != nil {
		return err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	defer func() {
		s.mu.Lock()
		s.connected = false
		s.mu.Unlock()
	}()
	return s.Serve(conn)
}

// Serve runs the session on conn: open, register, then answer until the
// master closes it.
func (s *Session) Serve(conn io.ReadWriter) error {
	var packet uint32
	call := func(h header, payload []byte) (header, *decoder, error) {
		packet++
		h.PacketID = packet
		if _, err := conn.Write(pdu(h, payload)); err != nil {
			return header{}, nil, err
		}
		for {
			rh, d, err := readPDU(conn)
			if err != nil {
				return header{}, nil, err
			}
			if rh.Type == pduResponse && rh.PacketID == packet {
				return rh, d, nil
			}
		}
	}
	// Open: the subagent's id and name (RFC 2741 6.2.1).
	open := &encoder{}
	open.u8(0) // the master's default timeout
	open.u8(0)
	open.u8(0)
	open.u8(0)
	open.oid(s.Subtree, false)
	open.octets([]byte(s.Name))
	rh, d, err := call(header{Type: pduOpen}, open.b)
	if err != nil {
		return err
	}
	if _, e, _ := response(d); e != errNone {
		return fmt.Errorf("agentx: open refused (error %d)", e)
	}
	session := rh.SessionID
	reg := &encoder{}
	reg.u8(0)   // timeout
	reg.u8(127) // priority
	reg.u8(0)   // range_subid
	reg.u8(0)
	reg.oid(s.Subtree, false)
	_, d, err = call(header{Type: pduRegister, SessionID: session}, reg.b)
	if err != nil {
		return err
	}
	if _, e, _ := response(d); e != errNone {
		return fmt.Errorf("agentx: registering %s refused (error %d)", s.Subtree, e)
	}
	s.mu.Lock()
	s.connected = true
	s.mu.Unlock()

	for {
		h, d, err := readPDU(conn)
		if err != nil {
			return err
		}
		if h.Flags&flagNonDefaultContext != 0 {
			d.octets()
		}
		var out []VarBind
		code, index := uint16(errNone), uint16(0)
		switch h.Type {
		case pduGet:
			for _, r := range d.ranges() {
				v, ok := s.Handler.Get(r.Start)
				if !ok {
					v = Value{Type: NoSuchObject}
					if r.Start.HasPrefix(s.Subtree) {
						v.Type = NoSuchInstance
					}
				}
				out = append(out, VarBind{Name: r.Start, Value: v})
			}
		case pduGetNext:
			for _, r := range d.ranges() {
				out = append(out, s.next(r))
			}
		case pduGetBulk:
			nonRep, maxRep := int(d.u16()), int(d.u16())
			out = s.bulk(d.ranges(), nonRep, maxRep)
		case pduTestSet:
			code, index = errNotWritable, 1
		case pduCommitSet, pduUndoSet:
		case pduCleanupSet:
			continue // no response
		case pduClose:
			return errors.New("agentx: the master closed the session")
		case pduResponse:
			continue
		default:
			code = errProcessing
		}
		if d.err != nil {
			code, out = errParse, nil
		}
		e := &encoder{}
		e.u32(0) // sysUpTime: the master's
		e.u16(code)
		e.u16(index)
		for _, v := range out {
			if err := e.varbind(v); err != nil {
				return err
			}
		}
		resp := header{Type: pduResponse, SessionID: h.SessionID, TransactionID: h.TransactionID, PacketID: h.PacketID}
		if _, err := conn.Write(pdu(resp, e.b)); err != nil {
			return err
		}
	}
}

func (s *Session) next(r searchRange) VarBind {
	if v, ok := s.Handler.Next(r.Start, r.Include, r.End); ok {
		return v
	}
	return VarBind{Name: r.Start, Value: Value{Type: EndOfMibView}}
}

// bulk answers a GetBulk (RFC 2741 7.2.3.2): the first nonRep ranges once,
// the others up to maxRep times each, row by row.
func (s *Session) bulk(ranges []searchRange, nonRep, maxRep int) []VarBind {
	var out []VarBind
	if nonRep > len(ranges) {
		nonRep = len(ranges)
	}
	for _, r := range ranges[:nonRep] {
		out = append(out, s.next(r))
	}
	reps := append([]searchRange(nil), ranges[nonRep:]...)
	done := make([]bool, len(reps))
	for i := 0; i < maxRep && len(reps) > 0; i++ {
		all := true
		for j := range reps {
			if done[j] {
				out = append(out, VarBind{Name: reps[j].Start, Value: Value{Type: EndOfMibView}})
				continue
			}
			v := s.next(reps[j])
			out = append(out, v)
			if v.Value.Type == EndOfMibView {
				done[j] = true
			} else {
				reps[j].Start, reps[j].Include = v.Name, false
				all = false
			}
		}
		if all {
			break
		}
	}
	return out
}

// response reads a Response's sysUpTime, error and index.
func response(d *decoder) (uint32, uint16, uint16) {
	return d.u32(), d.u16(), d.u16()
}

// maxPayload bounds a PDU from the master.
const maxPayload = 1 << 20

func readPDU(r io.Reader) (header, *decoder, error) {
	hb := make([]byte, headerLen)
	if _, err := io.ReadFull(r, hb); err != nil {
		return header{}, nil, err
	}
	h, ord, n, err := readHeader(hb)
	if err != nil {
		return header{}, nil, err
	}
	if n > maxPayload {
		return header{}, nil, fmt.Errorf("agentx: a PDU of %d bytes", n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return header{}, nil, err
	}
	return h, &decoder{b: body, ord: ord}, nil
}
