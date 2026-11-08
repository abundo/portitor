// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agentx

import (
	"fmt"
	"io"
	"net"
)

// Master is a minimal master agent's side of one session, for tests and
// checks without snmpd: it takes a subagent's Open and Register, then asks.
type Master struct {
	conn    io.ReadWriter
	session uint32
	packet  uint32
	// Subtree is what the subagent registered.
	Subtree OID
}

// Accept takes one subagent from l and its Open and Register.
func Accept(l net.Listener) (*Master, error) {
	c, err := l.Accept()
	if err != nil {
		return nil, err
	}
	return NewMaster(c)
}

// NewMaster takes a subagent's Open and Register on conn.
func NewMaster(conn io.ReadWriter) (*Master, error) {
	m := &Master{conn: conn, session: 1}
	for _, want := range []byte{pduOpen, pduRegister} {
		h, d, err := readPDU(conn)
		if err != nil {
			return nil, err
		}
		if h.Type != want {
			return nil, fmt.Errorf("agentx: PDU %d, want %d", h.Type, want)
		}
		if want == pduRegister {
			d.u32()
			m.Subtree, _ = d.oid()
		}
		e := &encoder{}
		e.u32(0)
		e.u16(errNone)
		e.u16(0)
		if _, err := conn.Write(pdu(header{Type: pduResponse, SessionID: m.session, PacketID: h.PacketID}, e.b)); err != nil {
			return nil, err
		}
	}
	return m, nil
}

func (m *Master) ask(typ byte, payload []byte) ([]VarBind, error) {
	m.packet++
	if _, err := m.conn.Write(pdu(header{Type: typ, SessionID: m.session, PacketID: m.packet}, payload)); err != nil {
		return nil, err
	}
	h, d, err := readPDU(m.conn)
	if err != nil {
		return nil, err
	}
	if h.Type != pduResponse || h.PacketID != m.packet {
		return nil, fmt.Errorf("agentx: answer %d to packet %d", h.Type, h.PacketID)
	}
	if _, code, _ := response(d); code != errNone {
		return nil, fmt.Errorf("agentx: error %d", code)
	}
	var out []VarBind
	for len(d.b) > 0 && d.err == nil {
		out = append(out, d.varbind())
	}
	return out, d.err
}

// Get asks for the values of oids.
func (m *Master) Get(oids ...OID) ([]VarBind, error) {
	e := &encoder{}
	for _, o := range oids {
		e.oid(o, false)
		e.oid(nil, false)
	}
	return m.ask(pduGet, e.b)
}

// GetNext asks for the objects after oids.
func (m *Master) GetNext(oids ...OID) ([]VarBind, error) {
	e := &encoder{}
	for _, o := range oids {
		e.oid(o, false)
		e.oid(nil, false)
	}
	return m.ask(pduGetNext, e.b)
}

// Walk is every object under root, by GetNext.
func (m *Master) Walk(root OID) ([]VarBind, error) {
	var out []VarBind
	for o := root; ; {
		vbs, err := m.GetNext(o)
		if err != nil {
			return out, err
		}
		v := vbs[0]
		if v.Value.Type == EndOfMibView || !v.Name.HasPrefix(root) {
			return out, nil
		}
		out = append(out, v)
		o = v.Name
	}
}
