// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package dhcpd

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func TestReplication(t *testing.T) {
	active := newTestServer(t, testConfig())
	standby := newTestServer(t, testConfig())
	ctx := context.Background()

	// A poller of another process gets a snapshot.
	ch := active.Changes(ctx, 0, 0, 0)
	if !ch.Snapshot || ch.Epoch == 0 {
		t.Fatalf("first poll: %+v", ch)
	}
	epoch, seq := ch.Epoch, ch.Seq

	// A new binding comes out at once.
	done := make(chan Changes)
	go func() { done <- active.Changes(ctx, epoch, seq, 5*time.Second) }()
	time.Sleep(20 * time.Millisecond)
	a := active.bind(macA)
	select {
	case ch = <-done:
	case <-time.After(time.Second):
		t.Fatal("a new binding waited")
	}
	if ch.Snapshot || len(ch.Leases) != 1 || ch.Leases[0].Addr != a || ch.Leases[0].Updated == 0 {
		t.Fatalf("changes: %+v", ch)
	}
	if n, err := standby.Apply(ch.Leases); n != 1 || err != nil {
		t.Fatalf("apply: %d %v", n, err)
	}
	if l := standby.store.Get(a); l == nil || l.MAC != macA.String() {
		t.Errorf("standby: %+v", l)
	}
	seq = ch.Seq

	// A renewal waits for the batch.
	active.now = func() time.Time { return t0.Add(time.Minute) }
	start := time.Now()
	go func() { done <- active.Changes(ctx, epoch, seq, 5*time.Second) }()
	time.Sleep(20 * time.Millisecond)
	active.send(withType(Request), withCIAddr(a.String()))
	ch = <-done
	if took := time.Since(start); took < batchWait/2 || len(ch.Leases) != 1 {
		t.Errorf("renewal batch after %v: %+v", took, ch)
	}

	// An older copy doesn't replace a newer one.
	old := ch.Leases[0]
	old.Updated--
	old.MAC = "02:00:00:00:00:ff"
	standby.Apply(ch.Leases)
	if n, _ := standby.Apply([]Lease{old}); n != 0 || standby.store.Get(a).MAC != macA.String() {
		t.Errorf("an older copy won")
	}

	// A poller that fell behind, or of an unknown seq, gets a snapshot.
	if ch := active.Changes(ctx, epoch, ch.Seq+5, 0); !ch.Snapshot {
		t.Errorf("seq ahead: %+v", ch)
	}
}

func TestAckWait(t *testing.T) {
	ts := newTestServer(t, testConfig())
	ts.now = time.Now
	// No standby has acknowledged anything: no wait.
	start := time.Now()
	ts.serveBind(macA)
	if time.Since(start) > ackWait/2 {
		t.Errorf("waited without a standby: %v", time.Since(start))
	}
	// With one, a new binding waits for its acknowledgement...
	ts.Acked(0)
	go func() {
		time.Sleep(30 * time.Millisecond)
		ts.mu.Lock()
		seq := ts.r.seq
		ts.mu.Unlock()
		ts.Acked(seq)
	}()
	start = time.Now()
	ts.serveBind(macB)
	if took := time.Since(start); took < 25*time.Millisecond || took > ackWait {
		t.Errorf("ack wait %v", took)
	}
	// ...but no longer than ackWait.
	start = time.Now()
	ts.serveBind(netipMAC(0xe))
	if took := time.Since(start); took < ackWait || took > 3*ackWait {
		t.Errorf("unacknowledged wait %v", took)
	}
}

func netipMAC(b byte) []byte { return []byte{2, 0, 0, 0, 0, b} }

// serveBind binds through Serve4, which waits for the standby.
func (ts *testServer) serveBind(mac []byte) netip.Addr {
	ts.t.Helper()
	req := &Packet4{Op: bootRequest, HType: 1, HLen: 6, XID: 1, CHAddr: mac}
	req.Set(optMessageType, []byte{Request})
	r, _ := ts.Serve4("lan", req, netip.MustParseAddrPort("0.0.0.0:68"))
	if r == nil || r.Type() != Ack {
		ts.t.Fatalf("no ack: %+v", r)
	}
	return r.YIAddr
}
