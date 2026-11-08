// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package agentx is the subagent side of AgentX (RFC 2741): a session with
// the master agent (net-snmp's snmpd), which registers a subtree and
// answers the master's Get, GetNext and GetBulk from a Handler. Read-only:
// sets are refused.
package agentx

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// PDU types (RFC 2741 6.1).
const (
	pduOpen       = 1
	pduClose      = 2
	pduRegister   = 3
	pduUnregister = 4
	pduGet        = 5
	pduGetNext    = 6
	pduGetBulk    = 7
	pduTestSet    = 8
	pduCommitSet  = 9
	pduUndoSet    = 10
	pduCleanupSet = 11
	pduNotify     = 12
	pduPing       = 13
	pduResponse   = 18
)

// Header flags.
const (
	flagInstanceRegistration = 1 << 0
	flagNewIndex             = 1 << 1
	flagAnyIndex             = 1 << 2
	flagNonDefaultContext    = 1 << 3
	flagNetworkByteOrder     = 1 << 4
)

// Response errors (RFC 2741 6.2.16).
const (
	errNone           = 0
	errGenErr         = 5
	errNotWritable    = 17
	errProcessing     = 268
	errParse          = 266
	errRequestDenied  = 267
	errUnknownContext = 263
)

// Type is a value's SNMP type, as AgentX encodes it.
type Type uint16

// Value types (RFC 2741 5.4).
const (
	Integer        Type = 2
	OctetString    Type = 4
	Null           Type = 5
	ObjectID       Type = 6
	IPAddress      Type = 64
	Counter32      Type = 65
	Gauge32        Type = 66
	TimeTicks      Type = 67
	Opaque         Type = 68
	Counter64      Type = 70
	NoSuchObject   Type = 128
	NoSuchInstance Type = 129
	EndOfMibView   Type = 130
)

// OID is an object identifier.
type OID []uint32

// ParseOID reads a dotted OID, "1.3.6.1.4.1.8072", with or without a
// leading dot.
func ParseOID(s string) (OID, error) {
	s = strings.TrimPrefix(strings.TrimSpace(s), ".")
	if s == "" {
		return nil, errors.New("empty OID")
	}
	var o OID
	for _, p := range strings.Split(s, ".") {
		n, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("OID %q: %v", s, err)
		}
		o = append(o, uint32(n))
	}
	return o, nil
}

func (o OID) String() string {
	parts := make([]string, len(o))
	for i, n := range o {
		parts[i] = strconv.FormatUint(uint64(n), 10)
	}
	return strings.Join(parts, ".")
}

// Compare orders OIDs lexicographically, as SNMP walks them.
func (o OID) Compare(p OID) int {
	for i := 0; i < len(o) && i < len(p); i++ {
		switch {
		case o[i] < p[i]:
			return -1
		case o[i] > p[i]:
			return 1
		}
	}
	switch {
	case len(o) < len(p):
		return -1
	case len(o) > len(p):
		return 1
	}
	return 0
}

// HasPrefix reports whether o is p or below it.
func (o OID) HasPrefix(p OID) bool {
	return len(o) >= len(p) && o[:len(p)].Compare(p) == 0
}

// Append is o with more sub-identifiers, a copy.
func (o OID) Append(n ...uint32) OID {
	out := make(OID, 0, len(o)+len(n))
	return append(append(out, o...), n...)
}

// Value is a typed value. Data is an int64 (Integer), a uint32 (Counter32,
// Gauge32, TimeTicks), a uint64 (Counter64), a []byte (OctetString,
// Opaque, IPAddress) or an OID (ObjectID); nothing for the others.
type Value struct {
	Type Type
	Data any
}

// VarBind is a name and its value.
type VarBind struct {
	Name  OID
	Value Value
}

// header is a PDU's header (RFC 2741 6.1).
type header struct {
	Type          byte
	Flags         byte
	SessionID     uint32
	TransactionID uint32
	PacketID      uint32
}

const headerLen = 20

// encoder writes a PDU's payload in network byte order.
type encoder struct{ b []byte }

func (e *encoder) u8(v byte)    { e.b = append(e.b, v) }
func (e *encoder) u16(v uint16) { e.b = binary.BigEndian.AppendUint16(e.b, v) }
func (e *encoder) u32(v uint32) { e.b = binary.BigEndian.AppendUint32(e.b, v) }
func (e *encoder) u64(v uint64) { e.b = binary.BigEndian.AppendUint64(e.b, v) }

// oid writes o, with the internet prefix compressed (RFC 2741 5.1).
func (e *encoder) oid(o OID, include bool) {
	prefix := byte(0)
	if len(o) >= 5 && o[0] == 1 && o[1] == 3 && o[2] == 6 && o[3] == 1 && o[4] > 0 && o[4] < 256 {
		prefix, o = byte(o[4]), o[5:]
	}
	e.u8(byte(len(o)))
	e.u8(prefix)
	inc := byte(0)
	if include {
		inc = 1
	}
	e.u8(inc)
	e.u8(0)
	for _, n := range o {
		e.u32(n)
	}
}

func (e *encoder) octets(s []byte) {
	e.u32(uint32(len(s)))
	e.b = append(e.b, s...)
	for len(e.b)%4 != 0 {
		e.b = append(e.b, 0)
	}
}

func (e *encoder) varbind(v VarBind) error {
	e.u16(uint16(v.Value.Type))
	e.u16(0)
	e.oid(v.Name, false)
	switch v.Value.Type {
	case Integer:
		n, _ := v.Value.Data.(int64)
		e.u32(uint32(int32(n)))
	case Counter32, Gauge32, TimeTicks:
		n, _ := v.Value.Data.(uint32)
		e.u32(n)
	case Counter64:
		n, _ := v.Value.Data.(uint64)
		e.u64(n)
	case OctetString, Opaque, IPAddress:
		s, _ := v.Value.Data.([]byte)
		e.octets(s)
	case ObjectID:
		o, _ := v.Value.Data.(OID)
		e.oid(o, false)
	case Null, NoSuchObject, NoSuchInstance, EndOfMibView:
	default:
		return fmt.Errorf("agentx: value type %d", v.Value.Type)
	}
	return nil
}

// pdu is a whole PDU: header and payload.
func pdu(h header, payload []byte) []byte {
	b := make([]byte, headerLen, headerLen+len(payload))
	b[0] = 1 // version
	b[1] = h.Type
	b[2] = h.Flags | flagNetworkByteOrder
	binary.BigEndian.PutUint32(b[4:], h.SessionID)
	binary.BigEndian.PutUint32(b[8:], h.TransactionID)
	binary.BigEndian.PutUint32(b[12:], h.PacketID)
	binary.BigEndian.PutUint32(b[16:], uint32(len(payload)))
	return append(b, payload...)
}

// decoder reads a payload in the byte order of its header.
type decoder struct {
	b   []byte
	ord binary.ByteOrder
	err error
}

func (d *decoder) need(n int) bool {
	if d.err == nil && len(d.b) < n {
		d.err = errors.New("agentx: short PDU")
	}
	return d.err == nil
}

func (d *decoder) u8() byte {
	if !d.need(1) {
		return 0
	}
	v := d.b[0]
	d.b = d.b[1:]
	return v
}

func (d *decoder) u16() uint16 {
	if !d.need(2) {
		return 0
	}
	v := d.ord.Uint16(d.b)
	d.b = d.b[2:]
	return v
}

func (d *decoder) u32() uint32 {
	if !d.need(4) {
		return 0
	}
	v := d.ord.Uint32(d.b)
	d.b = d.b[4:]
	return v
}

func (d *decoder) u64() uint64 {
	if !d.need(8) {
		return 0
	}
	v := d.ord.Uint64(d.b)
	d.b = d.b[8:]
	return v
}

func (d *decoder) oid() (OID, bool) {
	n, prefix, include := d.u8(), d.u8(), d.u8()
	d.u8()
	var o OID
	if prefix != 0 {
		o = OID{1, 3, 6, 1, uint32(prefix)}
	}
	for i := 0; i < int(n) && d.err == nil; i++ {
		o = append(o, d.u32())
	}
	return o, include != 0
}

func (d *decoder) octets() []byte {
	n := int(d.u32())
	padded := (n + 3) &^ 3
	if !d.need(padded) {
		return nil
	}
	s := append([]byte(nil), d.b[:n]...)
	d.b = d.b[padded:]
	return s
}

func (d *decoder) varbind() VarBind {
	t := Type(d.u16())
	d.u16()
	name, _ := d.oid()
	v := VarBind{Name: name, Value: Value{Type: t}}
	switch t {
	case Integer:
		v.Value.Data = int64(int32(d.u32()))
	case Counter32, Gauge32, TimeTicks:
		v.Value.Data = d.u32()
	case Counter64:
		v.Value.Data = d.u64()
	case OctetString, Opaque, IPAddress:
		v.Value.Data = d.octets()
	case ObjectID:
		o, _ := d.oid()
		v.Value.Data = o
	}
	return v
}

// searchRange is a Get, GetNext or GetBulk's range (RFC 2741 5.2): from
// Start (itself too when Include) up to End, exclusive; End empty is no
// bound.
type searchRange struct {
	Start   OID
	Include bool
	End     OID
}

func (d *decoder) ranges() []searchRange {
	var out []searchRange
	for len(d.b) > 0 && d.err == nil {
		start, inc := d.oid()
		end, _ := d.oid()
		out = append(out, searchRange{Start: start, Include: inc, End: end})
	}
	return out
}

// readHeader parses a header; the payload's length is in it.
func readHeader(b []byte) (header, binary.ByteOrder, uint32, error) {
	if len(b) < headerLen {
		return header{}, nil, 0, errors.New("agentx: short header")
	}
	if b[0] != 1 {
		return header{}, nil, 0, fmt.Errorf("agentx: version %d", b[0])
	}
	var ord binary.ByteOrder = binary.LittleEndian
	if b[2]&flagNetworkByteOrder != 0 {
		ord = binary.BigEndian
	}
	h := header{Type: b[1], Flags: b[2], SessionID: ord.Uint32(b[4:]), TransactionID: ord.Uint32(b[8:]), PacketID: ord.Uint32(b[12:])}
	return h, ord, ord.Uint32(b[16:]), nil
}
