// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agentx

import (
	"encoding/binary"
	"net"
	"sort"
	"testing"
)

// table is a Handler over a sorted list.
type table []VarBind

func (t table) Get(o OID) (Value, bool) {
	for _, v := range t {
		if v.Name.Compare(o) == 0 {
			return v.Value, true
		}
	}
	return Value{}, false
}

func (t table) Next(o OID, include bool, end OID) (VarBind, bool) {
	i := sort.Search(len(t), func(i int) bool {
		c := t[i].Name.Compare(o)
		return c > 0 || (include && c == 0)
	})
	if i == len(t) || (len(end) > 0 && t[i].Name.Compare(end) >= 0) {
		return VarBind{}, false
	}
	return t[i], true
}

// master is the test's end of the session.
type master struct {
	t      *testing.T
	conn   net.Conn
	packet uint32
}

func (m *master) read() (header, *decoder) {
	m.t.Helper()
	h, d, err := readPDU(m.conn)
	if err != nil {
		m.t.Fatal(err)
	}
	return h, d
}

func (m *master) respond(h header, session uint32) {
	e := &encoder{}
	e.u32(0)
	e.u16(0)
	e.u16(0)
	m.conn.Write(pdu(header{Type: pduResponse, SessionID: session, PacketID: h.PacketID}, e.b))
}

// ask sends a request and returns the response's error and varbinds.
func (m *master) ask(typ byte, payload []byte) (uint16, []VarBind) {
	m.t.Helper()
	m.packet++
	m.conn.Write(pdu(header{Type: typ, SessionID: 7, PacketID: m.packet}, payload))
	h, d := m.read()
	if h.Type != pduResponse || h.PacketID != m.packet {
		m.t.Fatalf("response %+v", h)
	}
	_, code, _ := response(d)
	var out []VarBind
	for len(d.b) > 0 {
		out = append(out, d.varbind())
	}
	return code, out
}

func TestSession(t *testing.T) {
	base := OID{1, 3, 6, 1, 4, 1, 8072, 9999, 9999, 1}
	data := table{
		{base.Append(1, 1, 0), Value{OctetString, []byte("fw1")}},
		{base.Append(1, 2, 0), Value{Counter64, uint64(1) << 40}},
		{base.Append(2, 1, 1, 1), Value{Integer, int64(-3)}},
		{base.Append(2, 1, 1, 2), Value{Integer, int64(4)}},
	}
	a, b := net.Pipe()
	defer a.Close()
	s := &Session{Subtree: base, Name: "test", Handler: data}
	done := make(chan error, 1)
	go func() { done <- s.Serve(b) }()
	m := &master{t: t, conn: a}

	h, d := m.read()
	if h.Type != pduOpen {
		t.Fatalf("first PDU %d", h.Type)
	}
	d.u32()
	if id, _ := d.oid(); id.Compare(base) != 0 || string(d.octets()) != "test" {
		t.Errorf("open: %v", id)
	}
	m.respond(h, 7)
	h, d = m.read()
	d.u32()
	if sub, _ := d.oid(); h.Type != pduRegister || h.SessionID != 7 || sub.Compare(base) != 0 {
		t.Fatalf("register: %+v %v", h, sub)
	}
	m.respond(h, 7)

	// Get: one there, one not.
	e := &encoder{}
	e.oid(base.Append(1, 2, 0), false)
	e.oid(nil, false)
	e.oid(base.Append(1, 3, 0), false)
	e.oid(nil, false)
	_, vbs := m.ask(pduGet, e.b)
	if len(vbs) != 2 || vbs[0].Value.Data != uint64(1)<<40 || vbs[1].Value.Type != NoSuchInstance {
		t.Errorf("get: %+v", vbs)
	}
	// GetNext from the base, and past the end.
	e = &encoder{}
	e.oid(base, false)
	e.oid(nil, false)
	e.oid(base.Append(9), false)
	e.oid(nil, false)
	_, vbs = m.ask(pduGetNext, e.b)
	if len(vbs) != 2 || string(vbs[0].Value.Data.([]byte)) != "fw1" || vbs[1].Value.Type != EndOfMibView {
		t.Errorf("getnext: %+v", vbs)
	}
	// GetBulk: no non-repeaters, 10 repetitions of one column.
	e = &encoder{}
	e.u16(0)
	e.u16(10)
	e.oid(base.Append(2), false)
	e.oid(nil, false)
	_, vbs = m.ask(pduGetBulk, e.b)
	if len(vbs) != 3 || vbs[0].Value.Data != int64(-3) || vbs[1].Value.Data != int64(4) || vbs[2].Value.Type != EndOfMibView {
		t.Errorf("getbulk: %+v", vbs)
	}
	// Sets are refused.
	if code, _ := m.ask(pduTestSet, nil); code != errNotWritable {
		t.Errorf("testset: %d", code)
	}
	a.Close()
	if err := <-done; err == nil {
		t.Error("serve ended without an error")
	}
}

func TestOIDCompression(t *testing.T) {
	for _, o := range []OID{{1, 3, 6, 1, 4, 1, 8072}, {1, 3, 6, 2}, {1, 3, 6, 1, 0, 5}, {}} {
		e := &encoder{}
		e.oid(o, true)
		d := &decoder{b: e.b, ord: binaryOrder()}
		got, inc := d.oid()
		if got.Compare(o) != 0 || !inc {
			t.Errorf("%v: %v %v", o, got, inc)
		}
	}
}

func binaryOrder() binary.ByteOrder { return binary.BigEndian }
