#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 The Portitor contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests the HA cluster's gate (dev/design-ha-cluster.md, phase 1) on this kernel.

The gate is a netdev table that keeps a passive standby's traffic interfaces
silent with their carrier up. Everything runs in namespaces this script makes,
so it changes nothing on the host. It needs python3 (3.12+), ip, nft and ping;
run it as root, or as a user that may make user namespaces.
"""

import errno
import os
import shutil
import socket
import statistics
import struct
import subprocess
import sys
import time

GATE = "table netdev portitor_gate"
BROADCAST = b"\xff" * 6
MAC_SB = "02:00:00:00:00:0a"
MAC_PEER = "02:00:00:00:00:0b"
SOL_PACKET = 263  # not in Python's socket module
PACKET_QDISC_BYPASS = 20
LLDP = 0x88cc
TEST_ETHERTYPE = 0x88b5  # local experimental
results = []


def need_ns():
    """Re-runs the script in a private mount and network namespace."""
    if os.environ.get("GATE_TEST_INNER"):
        return
    os.environ["GATE_TEST_INNER"] = "1"
    flags = ["-mn"] if os.geteuid() == 0 else ["-Urmn"]
    os.execvp("unshare", ["unshare", *flags, sys.executable, *sys.argv])


def sh(ns, cmd, check=True, stdin=None):
    argv = ["ip", "netns", "exec", ns, "sh", "-c", cmd] if ns else ["sh", "-c", cmd]
    p = subprocess.run(argv, input=stdin, text=True, capture_output=True)
    if check and p.returncode:
        raise RuntimeError(f"{cmd}: {p.stderr.strip()}")
    return p


class In:
    """Runs the block's socket calls in a namespace."""

    def __init__(self, ns):
        self.ns = ns

    def __enter__(self):
        self.old = os.open("/proc/self/ns/net", os.O_RDONLY)
        fd = os.open(f"/run/netns/{self.ns}", os.O_RDONLY)
        os.setns(fd, os.CLONE_NEWNET)
        os.close(fd)

    def __exit__(self, *_):
        os.setns(self.old, os.CLONE_NEWNET)
        os.close(self.old)


def raw(ns, dev, proto=0x0003):
    with In(ns):
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(proto))
        s.bind((dev, proto))
    s.setblocking(False)
    return s


def frames(s, seconds, mac=None):
    """Frames read from s for a while, those from mac alone when given."""
    out = []
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        try:
            f = s.recv(2048)
        except BlockingIOError:
            time.sleep(0.005)
            continue
        if mac is None or f[6:12] == bytes.fromhex(mac.replace(":", "")):
            out.append(f)
    return out


def describe(fs):
    return sorted({f"0x{struct.unpack('!H', f[12:14])[0]:04x}" for f in fs})


def frame(mac, ethertype, dst=BROADCAST):
    return dst + bytes.fromhex(mac.replace(":", "")) + struct.pack("!H", ethertype) + b"\0" * 46


def send(s, f):
    """Sends f; the errno's name when the send failed."""
    try:
        s.send(f)
    except OSError as e:
        return errno.errorcode[e.errno]
    return "no error"


def gate(ns, devs, policy="drop"):
    d = ", ".join(devs)
    sh(ns, "nft -f -", stdin=f"""{GATE} {{
  chain in {{ type filter hook ingress devices = {{ {d} }} priority -500; policy {policy}; ether type 0x88cc accept; }}
  chain out {{ type filter hook egress devices = {{ {d} }} priority -500; policy {policy}; ether type 0x88cc accept; }}
}}
""")


def setpolicy(ns, devs, policy):
    d = ", ".join(devs)
    sh(ns, "nft -f -", stdin=f"""chain netdev portitor_gate in {{ type filter hook ingress devices = {{ {d} }} priority -500; policy {policy}; }}
chain netdev portitor_gate out {{ type filter hook egress devices = {{ {d} }} priority -500; policy {policy}; }}
""")


def topo(up=True):
    """Namespaces sb and peer joined by a veth, a0 in sb, b0 in peer."""
    for ns in ("sb", "peer"):
        sh(None, f"ip netns del {ns}", check=False)
        sh(None, f"ip netns add {ns}")
        sh(ns, "ip link set lo up")
    sh("sb", "ip link add a0 type veth peer name b0 && ip link set b0 netns peer")
    sh("sb", f"ip link set a0 address {MAC_SB}")
    sh("peer", f"ip link set b0 address {MAC_PEER} && ip addr add 192.0.2.2/24 dev b0 && ip link set b0 up")
    sh("sb", "ip addr add 192.0.2.1/24 dev a0")
    if up:
        sh("sb", "ip link set a0 up")
        time.sleep(0.1)


def ping(ns, addr, extra=""):
    return sh(ns, f"ping -c 2 -i 0.2 -W 1 {extra} {addr}", check=False).returncode == 0


def report(name, ok, detail=""):
    results.append(ok)
    print(f"{'PASS' if ok else 'FAIL'}  {name}{': ' + detail if detail else ''}", flush=True)


def info(name, detail):
    print(f"INFO  {name}: {detail}", flush=True)


def test_ping():
    topo()
    report("control: without a gate the peer pings the standby", ping("peer", "192.0.2.1"))
    gate("sb", ["a0"])
    cap = raw("peer", "b0")
    frames(cap, 0.05)
    answered = ping("peer", "192.0.2.1")
    seen = frames(cap, 0.2, MAC_SB)
    carrier = "LOWER_UP" in sh("sb", "ip link show a0").stdout
    report("closed: no answer to ping or ARP, nothing on the wire", not answered and not seen, f"frames {describe(seen)}")
    report("closed: carrier stays up", carrier)
    setpolicy("sb", ["a0"], "accept")
    report("opened by changing the policy: answers again", ping("peer", "192.0.2.1"))


def dad_frames(with_gate):
    topo(up=False)
    sh("sb", "ip -6 addr add 2001:db8::1/64 dev a0")
    sh("peer", "ip -6 addr add 2001:db8::1/64 dev b0 nodad")
    if with_gate:
        gate("sb", ["a0"])
    cap = raw("peer", "b0")
    sh("sb", "ip link set a0 up")
    seen = frames(cap, 3, MAC_SB)
    return seen, sh("sb", "ip -6 addr show dev a0").stdout


def test_boot():
    seen, _ = dad_frames(False)
    report("control: without a gate a new interface sends DAD, MLD or RS", bool(seen), f"frames {describe(seen)}")
    seen, addrs = dad_frames(True)
    report("gate before up: nothing leaves when the interface comes up", not seen, f"frames {describe(seen)}")
    report("gate before up: an address in use elsewhere passes DAD", "dadfailed" not in addrs and "tentative" not in addrs)


def test_packet_sockets():
    topo()
    gate("sb", ["a0"])
    cap = raw("peer", "b0", TEST_ETHERTYPE)
    tx = raw("sb", "a0", TEST_ETHERTYPE)
    result = send(tx, frame(MAC_SB, TEST_ETHERTYPE))
    report("AF_PACKET send is dropped", not frames(cap, 0.2, MAC_SB), f"send returns {result}")
    bypass = raw("sb", "a0", TEST_ETHERTYPE)
    bypass.setsockopt(SOL_PACKET, PACKET_QDISC_BYPASS, 1)
    result = send(bypass, frame(MAC_SB, TEST_ETHERTYPE))
    info("AF_PACKET send with PACKET_QDISC_BYPASS", ("gets out" if frames(cap, 0.2, MAC_SB) else "is dropped") + f", send returns {result}")
    rx = raw("sb", "a0", TEST_ETHERTYPE)
    raw("peer", "b0", TEST_ETHERTYPE).send(frame(MAC_PEER, TEST_ETHERTYPE))
    info("AF_PACKET receive behind a closed gate", "sees the frame" if frames(rx, 0.2, MAC_PEER) else "sees nothing")
    lldp_cap, lldp_rx = raw("peer", "b0", LLDP), raw("sb", "a0", LLDP)
    raw("sb", "a0", LLDP).send(frame(MAC_SB, LLDP))
    raw("peer", "b0", LLDP).send(frame(MAC_PEER, LLDP))
    report("LLDP passes both ways", bool(frames(lldp_cap, 0.2, MAC_SB)) and bool(frames(lldp_rx, 0.2, MAC_PEER)))


def test_stacked():
    topo()
    if sh("sb", "ip link add link a0 name a0.5 type vlan id 5", check=False).returncode:
        info("VLAN on a gated interface", "not run, no vlan support here")
    else:
        sh("sb", "ip addr add 198.51.100.1/24 dev a0.5 && ip link set a0.5 up")
        sh("peer", "ip link add link b0 name b0.5 type vlan id 5 && ip addr add 198.51.100.2/24 dev b0.5 && ip link set b0.5 up")
        report("control: VLAN answers without a gate", ping("peer", "198.51.100.1"))
        gate("sb", ["a0"])
        cap = raw("peer", "b0")
        answered = ping("peer", "198.51.100.1")
        seen = frames(cap, 0.2, MAC_SB)
        report("a gate on the parent covers its VLAN", not answered and not seen, f"frames {describe(seen)}")
    topo()
    if sh("sb", "ip link add br0 type bridge", check=False).returncode:
        info("bridge on a gated interface", "not run, no bridge support here")
        return
    sh("sb", f"ip link set br0 address {MAC_SB} && ip addr del 192.0.2.1/24 dev a0 && ip link set a0 master br0")
    sh("sb", "ip addr add 192.0.2.1/24 dev br0 && ip link set br0 up")
    time.sleep(0.1)
    report("control: a bridge answers without a gate", ping("peer", "192.0.2.1"))
    gate("sb", ["a0"])
    cap = raw("peer", "b0")
    frames(cap, 0.05)
    answered = ping("peer", "192.0.2.1")
    seen = frames(cap, 0.2, MAC_SB)
    report("a gate on the port covers its bridge", not answered and not seen, f"frames {describe(seen)}")


def test_device_lifecycle():
    topo()
    gate("sb", ["a0"])
    sh("sb", "ip link del a0")
    sh("sb", "ip link add a0 type veth peer name b0 && ip link set b0 netns peer")
    sh("sb", f"ip link set a0 address {MAC_SB} && ip addr add 192.0.2.1/24 dev a0 && ip link set a0 up")
    sh("peer", f"ip link set b0 address {MAC_PEER} && ip addr add 192.0.2.2/24 dev b0 && ip link set b0 up")
    time.sleep(0.1)
    leak = ping("peer", "192.0.2.1")
    report("a device deleted and made again stays gated", not leak, "it answers: the gate no longer holds it" if leak else "")
    sh("sb", "nft delete table netdev portitor_gate")
    report("control: that device answers once the gate is gone", ping("peer", "192.0.2.1"))
    gate("sb", ["a0"])
    report("loading the gate again closes that device", not ping("peer", "192.0.2.1"))

    # The agent moves interfaces into their instance's namespace.
    topo()
    sh(None, "ip netns del vf", check=False)
    sh(None, "ip netns add vf")
    gate("sb", ["a0"])
    sh("sb", "ip link set a0 netns vf")
    sh("vf", "ip addr add 192.0.2.1/24 dev a0 && ip link set a0 up")
    time.sleep(0.1)
    info("a gated device moved to another namespace, no gate there", "answers" if ping("peer", "192.0.2.1") else "stays silent")
    gate("vf", ["a0"])
    report("a gate loaded in the new namespace holds it", not ping("peer", "192.0.2.1"))
    sh("vf", "ip link set a0 netns sb")
    sh("sb", "ip addr add 192.0.2.1/24 dev a0 && ip link set a0 up")
    time.sleep(0.1)
    leak = ping("peer", "192.0.2.1")
    report("a device moved back to a namespace with a gate is held", not leak, "it answers: the old gate does not hold it" if leak else "")
    p = sh("sb", "nft -f -", check=False, stdin="flush ruleset\n")
    gate("sb", ["a0"])
    report("reloading the gate closes it again", p.returncode == 0 and not ping("peer", "192.0.2.1"))
    topo()
    p = sh("sb", "nft -f -", check=False, stdin=f"{GATE} {{\n  chain in {{\n    type filter hook ingress devices = {{ nosuch }} priority -500; policy drop;\n  }}\n}}\n")
    info("a gate naming a missing device", "accepted" if p.returncode == 0 else f"refused: {p.stderr.strip().splitlines()[0]}")


def test_commit():
    topo()
    gate("sb", ["a0"])
    sh("sb", "nft -f -", stdin="""table inet firewall
delete table inet firewall

table inet firewall {
  chain input { type filter hook input priority 0; policy accept; }
}
""")
    report("reloading inet firewall as a commit does leaves the gate closed", not ping("peer", "192.0.2.1"))
    sh("sb", "nft -f -", stdin="add table netdev other\ndelete table netdev other\n")
    report("the gate survives in the ruleset", "portitor_gate" in sh("sb", "nft list tables").stdout)


def test_speed():
    topo()
    devs = []
    for i in range(16):
        sh("sb", f"ip link add d{i} type dummy && ip link set d{i} up")
        devs.append(f"d{i}")
    gate("sb", devs)
    times = []
    for i in range(40):
        t = time.monotonic()
        setpolicy("sb", devs, "accept" if i % 2 == 0 else "drop")
        times.append((time.monotonic() - t) * 1000)
    info("open or close 16 interfaces, one namespace", f"median {statistics.median(times):.1f} ms, worst {max(times):.1f} ms")
    report("open or close takes well under 100 ms", max(times) < 100)


def garp(ns, dev, mac, ip):
    m, a = bytes.fromhex(mac.replace(":", "")), socket.inet_aton(ip)
    pkt = BROADCAST + m + b"\x08\x06" + struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + m + a + b"\0" * 6 + a
    raw(ns, dev, 0x0806).send(pkt + b"\0" * 18)


def failover(send_garp):
    """Active and standby with one MAC and address on a switch; client pings."""
    for ns in ("act", "sb", "cl", "sw"):
        sh(None, f"ip netns del {ns}", check=False)
        sh(None, f"ip netns add {ns}")
        sh(ns, "ip link set lo up")
    if sh("sw", "ip link add br0 type bridge", check=False).returncode:
        return None
    sh("sw", "ip link set br0 up")
    for ns, dev in (("act", "a0"), ("sb", "a0"), ("cl", "c0")):
        sh("sw", f"ip link add p{ns} type veth peer name {dev}")
        sh("sw", f"ip link set {dev} netns {ns} && ip link set p{ns} master br0 && ip link set p{ns} up")
    for ns in ("act", "sb"):
        sh(ns, "ip link set a0 down" if ns == "sb" else "true")
        sh(ns, f"ip link set a0 address {MAC_SB} && ip addr add 192.0.2.1/24 dev a0")
    gate("act", ["a0"], "accept")
    gate("sb", ["a0"])
    sh("act", "ip link set a0 up")
    sh("sb", "ip link set a0 up")
    sh("cl", "ip addr add 192.0.2.9/24 dev c0 && ip link set c0 up")
    time.sleep(0.3)
    before = ping("cl", "192.0.2.1")
    fdb = sh("sw", f"bridge fdb show br br0 | grep -i {MAC_SB} | grep -v permanent || true").stdout
    count = 500
    pinger = subprocess.Popen(["ip", "netns", "exec", "cl", "ping", "-c", str(count), "-i", "0.01", "-W", "1", "192.0.2.1"], stdout=subprocess.PIPE, text=True)
    time.sleep(1.5)
    t = time.monotonic()
    setpolicy("act", ["a0"], "drop")
    setpolicy("sb", ["a0"], "accept")
    if send_garp:
        garp("sb", "a0", MAC_SB, "192.0.2.1")
    switched = (time.monotonic() - t) * 1000
    out = pinger.communicate(timeout=30)[0]
    stats = next((line for line in out.splitlines() if "received" in line), "")
    sent, got = int(stats.split()[0]), int(stats.split()[3])
    return before, fdb.count("master"), switched, sent - got, sent


def test_failover():
    for send_garp in (True, False):
        r = failover(send_garp)
        if r is None:
            info("failover", "not run, no bridge support here")
            return
        before, ports, switched, lost, sent = r
        name = "with GARP" if send_garp else "without GARP"
        report(f"{name}: one MAC on the switch before takeover, on one port", before and ports == 1, f"fdb entries {ports}")
        info(f"{name}: takeover", f"switched in {switched:.1f} ms, lost {lost} of {sent} pings at 10 ms")
        if send_garp:
            report("with GARP: traffic resumes within 1 s", lost < 100)


def main():
    need_ns()
    for tool in ("ip", "nft", "ping"):
        if not shutil.which(tool):
            sys.exit(f"{tool} not found (try PATH=$PATH:/usr/sbin)")
    subprocess.run(["mount", "--make-rprivate", "/"], check=True)
    subprocess.run(["mount", "-t", "tmpfs", "tmpfs", "/run"], check=True)
    os.makedirs("/run/netns", exist_ok=True)
    print(f"kernel {os.uname().release}, {sh(None, 'nft --version').stdout.strip()}", flush=True)
    for test in (test_ping, test_boot, test_packet_sockets, test_stacked, test_device_lifecycle, test_commit, test_speed, test_failover):
        print(f"--- {test.__name__}", flush=True)
        try:
            test()
        except Exception as e:
            report(f"{test.__name__} crashed", False, str(e))
    print(f"\n{results.count(True)} passed, {results.count(False)} failed")
    sys.exit(1 if False in results else 0)


if __name__ == "__main__":
    main()
