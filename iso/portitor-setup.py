#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 The Portitor contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Setup of a firewall installed from the Portitor ISO (portitor-setup).

Runs on tty1 at boot (portitor-firstboot.service) until it has finished
once. A text UI (Textual, python3-textual) asks for the keyboard layout
(applied at once, so the password is typed with it), the LAN and WAN
interfaces, the LAN address (static or DHCP), a DHCP server on a static
LAN (its range), the WAN address (DHCP, or static with the default
gateway), the DNS servers (by default those the DHCP server on the DHCP WAN,
or LAN, offers), a password and the time zone; before applying, LAN and WAN can be swapped. Then it:

  - writes /etc/resolv.conf (the agent does not manage the firewall's own
    resolver; the one from the installation may be unreachable now),
  - creates the SQLite database and writes /etc/portitor/web.yaml, with a
    self-signed certificate for the GUI on port 443,
  - creates the GUI user admin, and sets the console user's password,
  - sets the agent up on 127.0.0.1 (portitor-web runs on the firewall itself),
  - runs `portitor-web bootstrap`: LAN (static or DHCP, which then takes no
    default route; the default route belongs to the WAN) and WAN (DHCP or
    static), described as LAN and WAN, default route, input rules for
    management (the portitor-mgmt service: SSH and the GUI) and ping from the LAN, a forward rule from the LAN to the WAN,
    masquerade on the WAN, a DHCP server on the LAN if chosen (handing out
    the DNS servers above), and deploys (output has the instance's allow all
    output rule),
  - starts portitor-web and writes the GUI's address to /etc/issue.d (with a
    DHCP LAN, agetty shows its current address).

Every step can be repeated; a failed one is retried with the same answers.

Split setups: the setup first asks what the machine runs.

  both   the above: the firewall with its GUI.
  agent  a firewall managed by portitor-web on another host. The LAN address
         is static; the agent listens on port 8443 and takes calls from
         portitor-web's address (allow_from). Until the first deploy a
         oneshot unit (portitor-setup-lan.service) puts the LAN address on
         the LAN, so portitor-web can reach it. It ends by showing a join
         string: the agent's URL, token and certificate fingerprint and the
         LAN and WAN answers. `sudo portitor-setup --show-join` prints it
         again (plain text, to copy over SSH).
  web    portitor-web only, on a host that manages a firewall elsewhere. Its
         one interface goes in /etc/network/interfaces (DHCP or static), the
         agent is disabled, and the join string from the firewall is pasted
         (now, or later over SSH with `sudo portitor-setup --join`): that runs
         `portitor-web bootstrap --join -`, which deploys the firewall's LAN
         and WAN as above, without the GUI rule.

Run again (`sudo portitor-setup`) after it has finished, it changes the
network: the LAN and WAN interfaces (swapped, too) and addresses, the
LAN's DHCP server (turned on or its range changed; off leaves it as it is),
the default gateway, the DNS servers, the time zone and the keyboard layout, with the last answers
(SETUP_STATE) as defaults; a password is optional there. It leaves the
database, the agent and every other interface alone, runs `portitor-web
bootstrap --reconfigure`, and makes a new GUI certificate when the LAN
address changes.

With /etc/portitor/firstboot.answers (an ISO built with `iso/build.sh
--test`), nothing is asked and no text UI runs: it holds "key: value" lines
for lan (a name or MAC address), address (dhcp for DHCP), wan (a name or MAC
address, optional), wan_address
(empty: DHCP), gateway (on the static WAN, else on the LAN), dhcp_range
(a DHCP server on the static LAN, e.g. 192.168.1.100-192.168.1.199,
optional), dns (space separated), password, hostname (default portitor, may include the domain), timezone and keyboard (an XKB layout, e.g. se). The file is removed when the setup has
finished. role (both, agent or web) picks the split setups; agent reads
web_from (portitor-web's address or network, default the LAN network), web
reads lan and address (its own interface), gateway and join (optional).
"""

from __future__ import annotations

import argparse
import base64
import functools
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import Callable

from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, VerticalScroll
from textual.screen import Screen
from textual.widget import Widget
from textual.widgets import Button, Footer, Header, Input, Label, OptionList, RichLog, Select, Static
from textual.widgets.option_list import Option

DONE = Path("/var/lib/portitor/firstboot.done")
# The last answers (no password): the defaults when the setup runs again.
SETUP_STATE = Path("/var/lib/portitor/setup.json")
ANSWERS = Path("/etc/portitor/firstboot.answers")
LOG = Path("/var/log/portitor-setup.log")
ETC = Path("/etc/portitor")
WEB_YAML = ETC / "web.yaml"
AGENT_YAML = ETC / "agent.yaml"
WEB_CERT = ETC / "web.crt"
WEB_KEY = ETC / "web.key"
WEB_DROPIN = Path("/etc/systemd/system/portitor-web.service.d/firstboot.conf")
ISSUE = Path("/etc/issue.d/portitor.issue")
RESOLV_CONF = Path("/etc/resolv.conf")
HOSTS = Path("/etc/hosts")
KEYBOARD = Path("/etc/default/keyboard")
XKB_RULES = Path("/usr/share/X11/xkb/rules/base.lst")
# The layouts when base.lst is missing.
LAYOUTS = [
    ("us", "English (US)"), ("gb", "English (UK)"), ("de", "German"), ("fr", "French"),
    ("es", "Spanish"), ("it", "Italian"), ("pt", "Portuguese"), ("nl", "Dutch"),
    ("be", "Belgian"), ("ch", "Swiss"), ("se", "Swedish"), ("no", "Norwegian"),
    ("dk", "Danish"), ("fi", "Finnish"), ("pl", "Polish"), ("cz", "Czech"),
]
PUBLIC_DNS = "1.1.1.1 8.8.8.8"
# The login user the installer created; also the agent's console user.
CONSOLE_USER = "portitor"
WEB_GROUP = "portitor"
# portitor-web's service user; it runs every portitor-web command, so the
# database files stay writable for the service.
WEB_USER = "portitor"
WEB_DB_DIR = Path("/var/lib/portitor-web")
AGENT_TOKEN = ETC / "agent.token"
GUI_USER = "admin"
GUI_PORT = 443
AGENT_LISTEN = "127.0.0.1:8443"
AGENT_PORT = 8443
# Agent only: the LAN address until the agent has applied a configuration.
APPLIED = Path("/var/lib/portitor/applied.json")
LAN_UNIT = Path("/etc/systemd/system/portitor-setup-lan.service")
# portitor-web only: the host's own interface.
NET_INTERFACES = Path("/etc/network/interfaces")
JOIN_PREFIX = "portitor-join:"  # web.JoinPrefix
ROLES = [
    ("both", "the firewall, with its GUI (portitor-agent and portitor-web)"),
    ("agent", "a firewall, managed by portitor-web on another host"),
    ("web", "portitor-web only, managing a firewall on another host"),
]
MIN_PASSWORD = 10  # portitor-web's minimum


def _print(msg: str) -> None:
    print(msg, flush=True)


# Where say() writes: stdout, or the text UI's log while it runs the steps.
output: Callable[[str], None] = _print


def say(msg: str = "") -> None:
    output(msg)


def logfile(msg: str) -> None:
    # Root's only, whatever the umask: it logs command output.
    fd = os.open(LOG, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    os.fchmod(fd, 0o600)
    with open(fd, "a", encoding="utf-8") as f:
        f.write(f"{time.strftime('%F %T')} {msg}\n")


def run(argv: list[str], *, stdin: str | None = None, check: bool = True, quiet: bool = False, secret: bool = False) -> subprocess.CompletedProcess[str]:
    """secret: stdout holds a secret; only stderr is logged or shown."""
    logfile("$ " + " ".join(argv))
    proc = subprocess.run(argv, input=stdin, capture_output=True, text=True, check=False)
    out = (proc.stderr if secret else proc.stdout + proc.stderr).strip()
    if out:
        logfile(out)
    if check and proc.returncode != 0:
        shown = argv[3:] if argv[0] == "runuser" else argv
        raise RuntimeError(f"{' '.join(shown[:3])} failed ({proc.returncode}):\n{out}")
    if out and not quiet:
        for line in out.splitlines()[-15:]:
            say(f"    {line}")
    return proc


# ---------------------------------------------------------------------------
# answers: the system's choices and the checks of what is typed
# ---------------------------------------------------------------------------


def read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def nics() -> list[dict[str, str]]:
    """Physical network interfaces (those with a device behind them)."""
    out = []
    for d in sorted(Path("/sys/class/net").iterdir()):
        if not (d / "device").exists():
            continue
        driver = (d / "device" / "driver")
        speed = read(d / "speed")
        out.append({
            "name": d.name,
            "mac": read(d / "address"),
            "carrier": read(d / "carrier") == "1",
            "driver": driver.resolve().name if driver.exists() else "",
            "speed": f"{speed} Mb/s" if speed.isdigit() and int(speed) > 0 else "",
        })
    return out


def links_up() -> None:
    # Links must be up to show whether a cable is plugged in.
    for n in nics():
        run(["ip", "link", "set", n["name"], "up"], check=False, quiet=True)
    time.sleep(2)


def offered_dns(nic: str, timeout: float = 4) -> list[str]:
    """The IPv4 DNS servers a DHCP server on nic offers; empty if none answers.

    Sends a DHCPDISCOVER only, so no lease is taken (nothing configures the
    interfaces before the agent runs)."""
    mac = bytes.fromhex(read(Path("/sys/class/net") / nic / "address").replace(":", ""))
    if len(mac) != 6:
        return []
    run(["ip", "link", "set", nic, "up"], check=False, quiet=True)
    xid = secrets.token_bytes(4)
    # BOOTREQUEST, Ethernet, broadcast flag (no address to unicast the offer to).
    msg = (bytes([1, 1, 6, 0]) + xid + b"\0\0\x80\0" + bytes(16) + mac + bytes(10 + 192)
           + bytes.fromhex("63825363") + bytes([53, 1, 1, 55, 3, 1, 3, 6, 255]))
    deadline = time.monotonic() + timeout
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, nic.encode())
            s.bind(("", 68))
            s.sendto(msg, ("255.255.255.255", 67))
            while (left := deadline - time.monotonic()) > 0:
                s.settimeout(left)
                pkt = s.recv(1500)
                if len(pkt) < 240 or pkt[0] != 2 or pkt[4:8] != xid or pkt[236:240] != msg[236:240]:
                    continue
                opts, i = {}, 240
                while i + 1 < len(pkt) and pkt[i] != 255:
                    if pkt[i] == 0:
                        i += 1
                        continue
                    opts[pkt[i]] = pkt[i + 2:i + 2 + pkt[i + 1]]
                    i += 2 + pkt[i + 1]
                dns = opts.get(6, b"")
                return [str(ipaddress.IPv4Address(dns[j:j + 4])) for j in range(0, len(dns) - 3, 4)][:3]
    except OSError:
        pass
    return []


def check_address(text: str, other: ipaddress.IPv4Interface | None = None) -> ipaddress.IPv4Interface:
    try:
        iface = ipaddress.IPv4Interface(text)
    except ValueError:
        raise ValueError("an IPv4 address with a prefix length, e.g. 192.168.1.1/24") from None
    net = iface.network
    if "/" not in text:
        raise ValueError("add the prefix length, e.g. /24")
    if net.prefixlen < 31 and iface.ip in (net.network_address, net.broadcast_address):
        raise ValueError(f"{iface.ip} is the network or broadcast address of {net}")
    if net.prefixlen > 30:
        raise ValueError("use a prefix length of 30 or less")
    if other and net.overlaps(other.network):
        raise ValueError(f"{net} overlaps the LAN {other.network}")
    return iface


def check_gateway(text: str, addr: ipaddress.IPv4Interface) -> ipaddress.IPv4Address:
    try:
        gw = ipaddress.IPv4Address(text)
    except ValueError:
        raise ValueError("an IPv4 address") from None
    if gw not in addr.network or gw == addr.ip:
        raise ValueError(f"must be another address in {addr.network}")
    return gw


def check_dhcp_range(text: str, addr: ipaddress.IPv4Interface) -> tuple[ipaddress.IPv4Address, ipaddress.IPv4Address]:
    start, sep, end = text.partition("-")
    try:
        if not sep:
            raise ValueError
        r = ipaddress.IPv4Address(start.strip()), ipaddress.IPv4Address(end.strip())
    except ValueError:
        raise ValueError("start-end, e.g. 192.168.1.100-192.168.1.199") from None
    net = addr.network
    for ip in r:
        if ip not in net or (net.prefixlen < 31 and ip in (net.network_address, net.broadcast_address)):
            raise ValueError(f"{ip} is not a host address in {net}")
    if r[0] > r[1]:
        raise ValueError("the start is after the end")
    if r[0] <= addr.ip <= r[1]:
        raise ValueError(f"the range holds the LAN address {addr.ip}")
    return r


def default_dhcp_range(addr: ipaddress.IPv4Interface) -> str:
    """.100-.199 in a /24 or larger, else the upper half; the other half if the LAN address is in it."""
    net, base = addr.network, addr.network.network_address
    if net.prefixlen > 30:
        return ""
    if net.prefixlen <= 24 and not base + 100 <= addr.ip <= base + 199:
        return f"{base + 100}-{base + 199}"
    mid = base + net.num_addresses // 2
    if mid <= addr.ip:
        return f"{base + 1}-{mid - 1}"
    return f"{mid}-{net.broadcast_address - 1}"


def fmt_range(r: tuple | None) -> str:
    return f"{r[0]}-{r[1]}" if r else ""


def parse_dns(answer: str) -> list[str]:
    try:
        servers = [str(ipaddress.ip_address(a)) for a in answer.replace(",", " ").split()]
    except ValueError:
        servers = []
    if not 1 <= len(servers) <= 3:
        raise ValueError("one to three IP addresses, separated by spaces")
    return servers


def check_web_from(text: str) -> str:
    try:
        return str(ipaddress.IPv4Network(text, strict=False))
    except ValueError:
        raise ValueError("an IPv4 address, or a network with its prefix length") from None


def check_timezone(text: str) -> str:
    if re.fullmatch(r"[A-Za-z0-9_+-]+(/[A-Za-z0-9_+-]+)*", text) and Path("/usr/share/zoneinfo", text).is_file():
        return text
    raise ValueError(f"unknown time zone {text}")


def check_hostname(text: str) -> str:
    """A host name (RFC 1123), optionally with its domain: labels of letters,
    digits and hyphens, 1-63 characters, not starting or ending with a hyphen;
    64 characters in all at most (the kernel's limit). Stored in lower case."""
    name = text.strip().rstrip(".").lower()
    label = r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
    if len(name) <= 64 and re.fullmatch(rf"{label}(\.{label})*", name) and not name.isdigit():
        return name
    raise ValueError("letters, digits and hyphens, with dots between the parts of a domain "
                     "(portitor or fw1.example.com); a part can't start or end with a hyphen")


def current_hostname() -> str:
    return socket.getfqdn() if "." in socket.getfqdn() else socket.gethostname()


def current_timezone() -> str:
    return run(["timedatectl", "show", "-p", "Timezone", "--value"], check=False, quiet=True).stdout.strip() or "Etc/UTC"


def timezones() -> list[str]:
    """The time zones timedatectl knows, current() among them."""
    zones = run(["timedatectl", "list-timezones"], check=False, quiet=True).stdout.split()
    return zones or ["Etc/UTC"]


def tz_region(zone: str) -> str:
    """Europe for Europe/Stockholm; Etc for a zone without a region (UTC)."""
    return zone.split("/", 1)[0] if "/" in zone else "Etc"


def xkb_layouts() -> dict[str, str]:
    """The XKB layouts, code: name (the "! layout" section of base.lst)."""
    layouts, section = {}, False
    try:
        lines = XKB_RULES.read_text(encoding="utf-8").splitlines()
    except OSError:
        return dict(LAYOUTS)
    for line in lines:
        if line.startswith("!"):
            section = line.split() == ["!", "layout"]
        elif section and line.strip():
            code, _, name = line.strip().partition(" ")
            layouts[code] = name.strip()
    return layouts or dict(LAYOUTS)


def current_layout() -> str:
    m = re.search(r'^XKBLAYOUT="?([^",\s]*)', read(KEYBOARD), re.M)
    return m[1] if m and m[1] else "us"


def set_keyboard(layout: str) -> None:
    """Writes the layout to /etc/default/keyboard and loads it on the console."""
    text = read(KEYBOARD) or 'XKBMODEL="pc105"\nXKBLAYOUT="us"\nXKBVARIANT=""\nXKBOPTIONS=""\nBACKSPACE="guess"'
    # A variant belongs to the old layout.
    values = {"XKBLAYOUT": layout, "XKBVARIANT": ""}
    lines = []
    for line in text.splitlines():
        key = line.partition("=")[0].strip()
        lines.append(f'{key}="{values.pop(key)}"' if key in values else line)
    lines += [f'{k}="{v}"' for k, v in values.items()]
    write(KEYBOARD, "\n".join(lines) + "\n", 0o644)
    if shutil.which("setupcon"):
        # Fails without a console (unattended); the layout then applies at the next boot.
        run(["setupcon", "-k", "--force"], check=False, quiet=True)


def decode_join(text: str) -> dict:
    """The join string's contents (web.ParseJoin checks them again)."""
    text = "".join(text.split())
    if not text.startswith(JOIN_PREFIX):
        raise ValueError(f"a join string starts with {JOIN_PREFIX}")
    raw = text[len(JOIN_PREFIX):].rstrip("=")
    try:
        d = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
    except ValueError:
        raise ValueError("the join string is damaged; copy it again") from None
    if not isinstance(d, dict) or not all(d.get(k) for k in ("url", "token", "fingerprint", "lan", "address")):
        raise ValueError("the join string is incomplete; copy it again")
    return d


# ---------------------------------------------------------------------------
# steps
# ---------------------------------------------------------------------------


def write(path: Path, text: str, mode: int, group: str = "root") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".new")
    tmp.write_text(text, encoding="utf-8")
    os.chmod(tmp, mode)
    shutil.chown(tmp, "root", group)
    tmp.replace(path)


def web(*args: str) -> list[str]:
    return ["runuser", "-u", WEB_USER, "--", "portitor-web", "-f", str(WEB_YAML), *args]


def step_links(a: dict) -> None:
    # Only the LAN and the WAN stay up; the others are imported as they
    # are, so down.
    for n in nics():
        if n["name"] not in (a["lan"], a["wan"]):
            run(["ip", "link", "set", n["name"], "down"], check=False, quiet=True)


def step_dns(a: dict) -> None:
    if RESOLV_CONF.is_symlink():
        RESOLV_CONF.unlink()
    write(RESOLV_CONF, "# Written by the Portitor first-boot setup.\n"
          + "".join(f"nameserver {d}\n" for d in a["dns"]), 0o644)


def step_keyboard(a: dict) -> None:
    set_keyboard(a["keyboard"])


def step_timezone(a: dict) -> None:
    run(["timedatectl", "set-timezone", a["tz"]])


def step_hostname(a: dict) -> None:
    """The short name in /etc/hostname; /etc/hosts maps 127.0.1.1 to the full
    and the short name, as the Debian installer does."""
    fqdn = a["hostname"]
    short = fqdn.split(".", 1)[0]
    run(["hostnamectl", "set-hostname", short])
    names = f"{fqdn} {short}" if fqdn != short else short
    lines = [ln for ln in read(HOSTS).splitlines() if not ln.startswith("127.0.1.1")]
    i = next((n + 1 for n, ln in enumerate(lines) if ln.startswith("127.0.0.1")), 0)
    lines.insert(i, f"127.0.1.1\t{names}")
    write(HOSTS, "\n".join(lines) + "\n", 0o644)


def step_database(a: dict) -> None:
    run(["install", "-d", "-o", WEB_USER, "-g", WEB_GROUP, "-m", "0700", str(WEB_DB_DIR)])


def step_cert(a: dict) -> None:
    host = a.get("hostname") or socket.gethostname()
    dns = ",".join(f"DNS:{n}" for n in dict.fromkeys([host, host.split(".", 1)[0]]))
    # A DHCP LAN has no fixed address to name.
    san = f"IP:{a['address'].ip},{dns}" if a["address"] else dns
    run([
        "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
        "-nodes", "-days", "3650", "-subj", f"/CN={host}",
        "-addext", f"subjectAltName={san}",
        "-keyout", str(WEB_KEY), "-out", str(WEB_CERT),
    ], quiet=True)
    for f in (WEB_KEY, WEB_CERT):
        os.chmod(f, 0o640)
        shutil.chown(f, "root", WEB_GROUP)


def step_new_cert(a: dict) -> None:
    # The certificate names the LAN address.
    if a["new_cert"]:
        step_cert(a)


def step_web_config(a: dict) -> None:
    step_cert(a)
    write(WEB_YAML, f"""# /etc/portitor/web.yaml - written by the first-boot setup.
# portitor-web runs on the firewall; the ruleset lets the LAN reach it.
bind: ":{GUI_PORT}"
tls_cert: {WEB_CERT}
tls_key: {WEB_KEY}
jwt_secret: "{secrets.token_urlsafe(32)}"

db:
  path: {WEB_DB_DIR}/portitor.db
""", 0o640, WEB_GROUP)
    # Port 443 as the unprivileged service user.
    write(WEB_DROPIN, """[Service]
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
""", 0o644)
    run(["systemctl", "daemon-reload"])
    run(web("migrate"))


def step_users(a: dict) -> None:
    if not a["password"]:
        return
    if a["role"] != "agent":
        run(web("createadmin", GUI_USER), stdin=a["password"] + "\n")
    run(["chpasswd"], stdin=f"{CONSOLE_USER}:{a['password']}\n", quiet=True)


def agent_init(a: dict) -> None:
    """Makes the agent's token and certificate, or keeps them; sets a["fingerprint"]."""
    hosts = [str(a["address"].ip)] if a["role"] == "agent" else ["127.0.0.1", "localhost"]
    # The output holds the agent's token.
    out = run(["portitor-agent", "init", *[x for h in hosts for x in ("--host", h)]], secret=True).stdout
    m = re.search(r"^fingerprint:\s*([0-9a-f]{64})\s*$", out, re.M)
    if not m:
        raise RuntimeError("no fingerprint in the output of portitor-agent init")
    a["fingerprint"] = m[1]


def step_agent(a: dict) -> None:
    agent_init(a)
    step_agent_config(a)


def step_agent_config(a: dict) -> None:
    if a["role"] == "agent":
        # All addresses: the LAN address may change in the GUI, and the
        # agent starts before it configures the interfaces. allow_from (and
        # the anti-lockout rule, the only way in to the port) limit it.
        head = f"# portitor-web runs on another host, at {a['web_from']}.\nlisten: \":{AGENT_PORT}\""
        allow = a["web_from"]
    else:
        head = f"""# portitor-web runs on this host and is the only client of the API.
listen: {AGENT_LISTEN}"""
        allow = "127.0.0.1/32"
    write(AGENT_YAML, f"""# /etc/portitor/agent.yaml - written by the first-boot setup.
{head}
token_file: {ETC}/agent.token
tls_cert: {ETC}/agent.crt
tls_key: {ETC}/agent.key
allow_from:
  - {allow}
console_user: {CONSOLE_USER}
""", 0o600)
    run(["systemctl", "enable", "portitor-agent.service"])
    run(["systemctl", "restart", "portitor-agent.service"])
    # SSH is open from the LAN (the portitor-mgmt service).
    run(["systemctl", "enable", "--now", "ssh.service"])


def step_lan_unit(a: dict) -> None:
    """Agent only: the LAN address until the agent applies the first configuration."""
    lan, addr = a["lan"], a["address"]
    write(LAN_UNIT, f"""# Written by the Portitor first-boot setup (agent only): the LAN address,
# so portitor-web on another host reaches the agent, until the agent has
# applied a configuration. From then on the agent configures the LAN.
[Unit]
Description=Portitor: LAN address until the first deploy
ConditionPathExists=!{APPLIED}
Before=portitor-agent.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/ip link set dev {lan} up
ExecStart=/usr/sbin/ip addr replace {addr} dev {lan}

[Install]
WantedBy=multi-user.target
""", 0o644)
    run(["systemctl", "daemon-reload"])
    run(["systemctl", "enable", LAN_UNIT.name])
    if not APPLIED.exists():
        run(["systemctl", "restart", LAN_UNIT.name])


def join_string(a: dict) -> str:
    """Agent only: what portitor-web needs to manage this firewall."""
    d = {
        "url": f"https://{a['address'].ip}:{AGENT_PORT}",
        "token": AGENT_TOKEN.read_text(encoding="utf-8").strip(),
        "fingerprint": a["fingerprint"],
        "lan": a["lan"],
        "address": str(a["address"]),
    }
    if a["wan"]:
        d["wan"] = a["wan"]
    if a["wan_address"]:
        d["wan_address"] = str(a["wan_address"])
    if a["gateway"]:
        d["gateway"] = str(a["gateway"])
    if a.get("dhcp_range"):
        d["dhcp_range"] = fmt_range(a["dhcp_range"])
        d["dhcp_dns"] = dhcp_dns(a)
    raw = json.dumps(d, separators=(",", ":")).encode()
    return JOIN_PREFIX + base64.urlsafe_b64encode(raw).decode().rstrip("=")


def step_host_network(a: dict) -> None:
    """portitor-web only: no agent configures this host, ifupdown does."""
    nic = a["lan"]
    if a["address"]:
        stanza = f"iface {nic} inet static\n    address {a['address']}\n"
        if a["gateway"]:
            stanza += f"    gateway {a['gateway']}\n"
    else:
        stanza = f"iface {nic} inet dhcp\n"
    # The old configuration (run again), then a clean slate.
    run(["ifdown", "--force", "-a"], check=False, quiet=True)
    for n in nics():
        run(["ip", "addr", "flush", "dev", n["name"]], check=False, quiet=True)
        if n["name"] != nic:
            run(["ip", "link", "set", n["name"], "down"], check=False, quiet=True)
    write(NET_INTERFACES, f"""# Written by the Portitor setup: portitor-web only; no agent runs here.
auto lo
iface lo inet loopback

auto {nic}
{stanza}""", 0o644)
    run(["ifup", nic])


def step_no_agent(a: dict) -> None:
    run(["systemctl", "disable", "--now", "portitor-agent.service"])


def join(a: dict, text: str) -> bool:
    """portitor-web only: deploys the firewall of the join string."""
    say("==> Deploy the firewall's LAN and WAN configuration")
    proc = run(web("bootstrap", "--join", "-"), stdin=text, check=False)
    if proc.returncode == 0:
        say(f"The firewall is managed from here now (agent {decode_join(text)['url']}).")
        return True
    say("!!  portitor-web bootstrap failed (see above)")
    return False


def dhcp_dns(a: dict) -> list[str]:
    """The DNS servers the LAN's DHCP server hands out (DHCPv4: IPv4 only)."""
    return [d for d in a["dns"] if ipaddress.ip_address(d).version == 4]


def step_bootstrap(a: dict) -> None:
    argv = web("bootstrap", "--lan", a["lan"], "--address", str(a["address"] or "dhcp"), "--gui-port", str(GUI_PORT))
    if a.get("dhcp_range"):
        argv += ["--dhcp-range", fmt_range(a["dhcp_range"])]
        if dhcp_dns(a):
            argv += ["--dhcp-dns", ",".join(dhcp_dns(a))]
    if a["wan"]:
        argv += ["--wan", a["wan"]]
    if a["wan_address"]:
        argv += ["--wan-address", str(a["wan_address"])]
    if a["gateway"]:
        argv += ["--gateway", str(a["gateway"])]
    if a.get("reconfigure"):
        # The agent settings stay as they are.
        argv.append("--reconfigure")
        run(argv)
        return
    # The token file is root's; the web user reads it from stdin.
    argv += [
        "--agent-url", f"https://{AGENT_LISTEN}",
        "--agent-token-file", "-",
        "--agent-fingerprint", a["fingerprint"],
    ]
    proc = run(argv, stdin=AGENT_TOKEN.read_text(encoding="utf-8"), check=False)
    if proc.returncode != 0 and "deployed already" not in proc.stdout + proc.stderr:
        raise RuntimeError("portitor-web bootstrap failed (see above)")


def step_web(a: dict) -> None:
    run(["systemctl", "enable", "portitor-web.service"])
    run(["systemctl", "restart", "portitor-web.service"])
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    for _ in range(30):
        try:
            urllib.request.urlopen(f"https://127.0.0.1:{GUI_PORT}/api/version", context=ctx, timeout=2).close()
            return
        except OSError:
            time.sleep(1)
    raise RuntimeError("portitor-web does not answer; see journalctl -u portitor-web")


def dhcp_address(nic: str, wait: int = 30) -> str:
    """The IPv4 address the agent's DHCP client got on nic; empty if none yet."""
    for _ in range(wait):
        out = run(["ip", "-j", "-4", "addr", "show", "dev", nic], check=False, quiet=True).stdout
        try:
            addrs = [x["local"] for link in json.loads(out or "[]") for x in link.get("addr_info", [])]
        except (ValueError, KeyError, TypeError):
            addrs = []
        if addrs:
            return addrs[0]
        time.sleep(1)
    return ""


def step_issue(a: dict) -> None:
    fp = run(["openssl", "x509", "-in", str(WEB_CERT), "-noout", "-fingerprint", "-sha256"], quiet=True).stdout
    fp = fp.strip().split("=", 1)[-1]
    if a["address"]:
        host = issue_host = str(a["address"].ip)
    else:
        # agetty shows the LAN's current address.
        host = dhcp_address(a["lan"]) or f"<the DHCP address of {a['lan']}>"
        issue_host = "\\4{" + a["lan"] + "}"
    a["url"], a["cert_fp"] = f"https://{host}/", fp
    write(ISSUE, f"""Portitor firewall. GUI: https://{issue_host}/ (user {GUI_USER})
Certificate SHA-256: {fp}

""", 0o644)


# The first setup, by role.
STEPS = [
    ("Keyboard layout", step_keyboard),
    ("Interfaces", step_links),
    ("DNS servers", step_dns),
    ("Time zone", step_timezone),
    ("Host name", step_hostname),
    ("Database", step_database),
    ("portitor-web configuration", step_web_config),
    ("Users", step_users),
    ("portitor-agent", step_agent),
    ("Deploy the LAN and WAN configuration", step_bootstrap),
    ("Start portitor-web", step_web),
    ("Login screen", step_issue),
]

AGENT_STEPS = [
    ("Keyboard layout", step_keyboard),
    ("Interfaces", step_links),
    ("DNS servers", step_dns),
    ("Time zone", step_timezone),
    ("Host name", step_hostname),
    ("Users", step_users),
    ("portitor-agent", step_agent),
    ("LAN address until the first deploy", step_lan_unit),
]

WEB_STEPS = [
    ("Keyboard layout", step_keyboard),
    ("Network", step_host_network),
    ("DNS servers", step_dns),
    ("Time zone", step_timezone),
    ("Host name", step_hostname),
    ("Database", step_database),
    ("portitor-web configuration", step_web_config),
    ("Users", step_users),
    ("Disable portitor-agent", step_no_agent),
    ("Start portitor-web", step_web),
    ("Login screen", step_issue),
]

# Run again: the network only.
RECONFIGURE_STEPS = [
    ("Keyboard layout", step_keyboard),
    ("DNS servers", step_dns),
    ("Time zone", step_timezone),
    ("Host name", step_hostname),
    ("GUI certificate", step_new_cert),
    ("Users", step_users),
    ("Deploy the LAN and WAN configuration", step_bootstrap),
    ("Restart portitor-web", step_web),
    ("Login screen", step_issue),
]

# Run again, agent only: the network belongs to portitor-web now.
AGENT_RECONFIGURE_STEPS = [
    ("Keyboard layout", step_keyboard),
    ("DNS servers", step_dns),
    ("Time zone", step_timezone),
    ("Host name", step_hostname),
    ("Users", step_users),
    ("portitor-agent", step_agent),
]

WEB_RECONFIGURE_STEPS = [
    ("Keyboard layout", step_keyboard),
    ("Network", step_host_network),
    ("DNS servers", step_dns),
    ("Time zone", step_timezone),
    ("Host name", step_hostname),
    ("GUI certificate", step_new_cert),
    ("Users", step_users),
    ("Restart portitor-web", step_web),
    ("Login screen", step_issue),
]

FIRST_STEPS = {"both": STEPS, "agent": AGENT_STEPS, "web": WEB_STEPS}
RECONFIGURE = {"both": RECONFIGURE_STEPS, "agent": AGENT_RECONFIGURE_STEPS, "web": WEB_RECONFIGURE_STEPS}


def read_answers() -> dict:
    """The answers file (unattended test installs)."""
    raw = {}
    for line in ANSWERS.read_text(encoding="utf-8").splitlines():
        k, sep, v = line.partition(":")
        if sep and not line.lstrip().startswith("#"):
            raw[k.strip()] = v.strip()

    def nic(key: str) -> str:
        for n in nics():
            if raw.get(key, "").lower() in (n["name"], n["mac"].lower()):
                return n["name"]
        raise RuntimeError(f"{ANSWERS}: no {key} interface {raw.get(key)!r}")

    keyboard = raw.get("keyboard") or current_layout()
    if keyboard not in xkb_layouts():
        raise RuntimeError(f"{ANSWERS}: no keyboard layout {keyboard!r}")
    role = raw.get("role") or "both"
    if role not in dict(ROLES):
        raise RuntimeError(f"{ANSWERS}: no role {role!r}")

    a = {
        "role": role,
        "lan": nic("lan"),
        "address": None if raw["address"].lower() == "dhcp" else ipaddress.IPv4Interface(raw["address"]),
        "wan": nic("wan") if raw.get("wan") and role != "web" else "",
        "wan_address": ipaddress.IPv4Interface(raw["wan_address"]) if raw.get("wan_address") and role != "web" else None,
        "gateway": ipaddress.IPv4Address(raw["gateway"]) if raw.get("gateway") else None,
        "dhcp_range": None,
        "dns": parse_dns(raw.get("dns") or PUBLIC_DNS),
        "password": raw["password"],
        "tz": raw.get("timezone") or "Etc/UTC",
        "hostname": check_hostname(raw.get("hostname") or "portitor"),
        "keyboard": keyboard,
        "web_from": "",
        "join": raw.get("join", ""),
    }
    if role == "agent":
        if not a["address"]:
            raise RuntimeError(f"{ANSWERS}: the agent-only firewall needs a static LAN address")
        a["web_from"] = str(ipaddress.IPv4Network(raw.get("web_from") or a["address"].network, strict=False))
    if raw.get("dhcp_range") and role != "web":
        if not a["address"]:
            raise RuntimeError(f"{ANSWERS}: a DHCP server needs a static LAN address")
        try:
            a["dhcp_range"] = check_dhcp_range(raw["dhcp_range"], a["address"])
        except ValueError as exc:
            raise RuntimeError(f"{ANSWERS}: dhcp_range: {exc}") from None
    if a["join"]:
        decode_join(a["join"])
    return a


def load_state() -> dict:
    """The last answers, as strings; empty if there are none."""
    try:
        state = json.loads(SETUP_STATE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return state if isinstance(state, dict) else {}


def state_of(a: dict) -> dict:
    """The answers as strings, without the password; a DHCP LAN is "dhcp"."""
    state = {k: str(a[k]) if a.get(k) else "" for k in ("role", "lan", "wan", "wan_address", "gateway", "tz", "hostname", "keyboard", "web_from")}
    state["address"] = str(a["address"] or "dhcp")
    state["dns"] = " ".join(a["dns"])
    state["dhcp_range"] = fmt_range(a.get("dhcp_range"))
    return state


def answers_of(state: dict) -> dict:
    """The network answers from state (the agent-only firewall run again)."""
    def iface(k: str) -> ipaddress.IPv4Interface | None:
        v = state.get(k, "")
        return ipaddress.IPv4Interface(v) if v and v != "dhcp" else None
    return {
        "lan": state.get("lan", ""), "address": iface("address"),
        "wan": state.get("wan", ""), "wan_address": iface("wan_address"),
        "gateway": ipaddress.IPv4Address(state["gateway"]) if state.get("gateway") else None,
        "dns": parse_dns(state.get("dns") or PUBLIC_DNS),
    }


def save_state(a: dict) -> None:
    write(SETUP_STATE, json.dumps(state_of(a), indent=2) + "\n", 0o600)


def run_step(a: dict, title: str, fn: Callable[[dict], None]) -> bool:
    say(f"==> {title}")
    try:
        fn(a)
        return True
    except Exception as exc:  # noqa: BLE001 - shown to the operator, who may retry
        logfile(f"FAILED: {exc}")
        say(f"!!  {exc}")
        say(f"    (log: {LOG})")
        return False


def finish(a: dict) -> None:
    """The steps have all run: the setup is done."""
    save_state(a)
    DONE.parent.mkdir(parents=True, exist_ok=True)
    DONE.touch()
    ANSWERS.unlink(missing_ok=True)


def nic_label(name: str) -> str:
    """ens18 (52:54:00:12:34:56)"""
    mac = next((n["mac"] for n in nics() if n["name"] == name), "")
    return f"{name} ({mac})" if mac else name


def summary(a: dict) -> list[str]:
    out = [f"Runs            {a['role']}: {dict(ROLES)[a['role']]}"]
    if a["role"] == "web":
        out += [f"Interface       {nic_label(a['lan'])}",
                f"Address         {a['address'] or 'DHCP'}",
                f"Default gateway {a['gateway'] or 'from DHCP'}"]
    elif a["role"] == "agent" and a.get("reconfigure"):
        out.append(f"portitor-web    {a['web_from']}")
    else:
        out += [f"WAN interface   {nic_label(a['wan'])}",
                f"WAN address     {a['wan_address'] or 'DHCP'}",
                f"Default gateway {a['gateway'] or 'from DHCP'}",
                f"LAN interface   {nic_label(a['lan'])}",
                f"LAN address     {a['address'] or 'DHCP (no default route)'}",
                f"LAN DHCP server {fmt_range(a.get('dhcp_range')) or ('unchanged' if a.get('reconfigure') and a['address'] else 'off')}"]
        if a["role"] == "agent":
            out.append(f"portitor-web    {a['web_from']}")
    out += [f"DNS servers     {' '.join(a['dns'])}",
            f"Host name       {a['hostname']}",
            f"Time zone       {a['tz']}",
            f"Keyboard        {a['keyboard']}"]
    if a.get("reconfigure"):
        out.append(f"Password        {'new' if a['password'] else 'unchanged'}")
    return out


def gui_text(a: dict) -> str:
    return f"""{"Open the GUI from the LAN:" if a["role"] == "both" else "Open the GUI:"}

    {a['url']}    user {GUI_USER}

The browser warns about the self-signed certificate; its SHA-256 fingerprint is
    {a['cert_fp']}
"""


def join_text(a: dict) -> str:
    """Agent only: the join string for portitor-web, and how to use it."""
    return f"""Run sudo portitor-setup on the portitor-web host (installed from the ISO as
"web", or later: sudo portitor-setup --join) and paste this join string:

{join_string(a)}

It holds the agent's token: keep it like a password. Easiest is to copy it over
SSH (ssh {CONSOLE_USER}@{a['address'].ip}, then sudo portitor-setup --show-join). A
portitor-web installed with install.py takes it too:
    sudo runuser -u {WEB_USER} -- portitor-web -f {WEB_YAML} bootstrap --join -
(paste it, Enter, Ctrl-D). By hand, in portitor-web's Settings > Agent:
    Agent URL    https://{a['address'].ip}:{AGENT_PORT}
    Fingerprint  {a['fingerprint']}
    Token        in {AGENT_TOKEN}
but then configure the LAN interface there before the first deploy.
"""


def intro(role: str) -> str:
    """portitor-setup after the first setup: what it changes."""
    if role == "both":
        return ("The first setup has run already. This changes the LAN and WAN interfaces and "
                "addresses, the default gateway, the DNS servers, the time zone and the keyboard "
                "layout, and deploys at once, without the confirm timeout. Other settings are "
                "kept. A session over the old LAN address drops; the console is the safe place "
                "to run this.")
    if role == "agent":
        return ("The first setup has run already. This changes portitor-web's address, the DNS "
                "servers, the time zone, the keyboard layout and the console password. "
                "portitor-web manages the network. sudo portitor-setup --show-join shows the "
                "join string.")
    return ("The first setup has run already. This changes this host's interface and address, "
            "the DNS servers, the time zone, the keyboard layout and the password. A session "
            "over the old address drops. sudo portitor-setup --join manages another firewall.")


# ---------------------------------------------------------------------------
# text UI
# ---------------------------------------------------------------------------


def row(label: str, widget: Widget) -> Horizontal:
    return Horizontal(Label(label, classes="label"), widget, classes="row")


def nic_options() -> list[tuple[str, str]]:
    return [(f"{n['name']:<16} {n['mac']:<18} {'link' if n['carrier'] else 'no link':<8} {n['driver']} {n['speed']}".rstrip(),
             n["name"]) for n in nics()]


def set_nic_options(select: Select, default: str) -> None:
    """Fills select with the interfaces, keeping its choice (or default)."""
    current = default if select.is_blank() else select.value
    options = nic_options()
    select.set_options(options)
    if any(v == current for _, v in options):
        select.value = current


class Page(Screen):
    """A page of the setup: Back and Next, and an error line."""

    BINDINGS = [Binding("escape", "back", "Back")]
    heading = ""
    next_label = "Next"

    def compose(self) -> ComposeResult:
        yield Header(icon=" ")
        with VerticalScroll(id="body"):
            yield Static(self.heading, classes="heading")
            yield from self.body()
            yield Label("", id="error")
            with Horizontal(id="buttons"):
                yield from self.buttons()
        yield Footer()

    def body(self) -> ComposeResult:
        yield from ()

    def buttons(self) -> ComposeResult:
        yield Button("Back", id="back", disabled=len(self.app.screen_stack) <= 2)
        yield Button(self.next_label, id="next", variant="primary")

    @property
    def a(self) -> dict:
        return self.app.a

    @property
    def state(self) -> dict:
        return self.app.state

    def save(self) -> None:
        """Takes the answers into self.a; ValueError says what is wrong."""

    def error(self, msg: str) -> None:
        self.query_one("#error", Label).update(msg)

    def action_back(self) -> None:
        if len(self.app.screen_stack) > 2:
            self.app.pop_screen()

    @on(Button.Pressed, "#back")
    def _back(self) -> None:
        self.action_back()

    @on(Button.Pressed, "#next")
    @on(Input.Submitted)
    def next(self) -> None:
        try:
            self.save()
        except ValueError as exc:
            self.error(str(exc))
            return
        self.error("")
        self.app.next_page()


class KeyboardPage(Page):
    heading = "Keyboard layout"

    def body(self) -> ComposeResult:
        if self.app.reconfigure:
            yield Static(intro(self.state.get("role") or "both"), classes="text")
        yield Static("It applies at once, so the password is typed with it. Type to search.", classes="text")
        yield Input(placeholder="search, e.g. swedish", id="search")
        yield OptionList(id="layouts")

    def on_mount(self) -> None:
        self.known = xkb_layouts()
        # By name, which mostly starts with the language or country.
        self.ordered = sorted(self.known.items(), key=lambda cn: (cn[1].casefold(), cn[0]))
        self.fill("", self.state.get("keyboard") or current_layout())
        self.query_one("#layouts").focus()

    def fill(self, word: str, select: str = "") -> None:
        layouts = self.query_one("#layouts", OptionList)
        layouts.clear_options()
        word = word.lower()
        found = [(c, n) for c, n in self.ordered if word in c or word in n.lower()]
        layouts.add_options([Option(f"{c:<8} {n}", id=c) for c, n in found])
        codes = [c for c, _ in found]
        if codes:
            layouts.highlighted = codes.index(select) if select in codes else 0

    @on(Input.Changed, "#search")
    def _search(self, event: Input.Changed) -> None:
        self.fill(event.value)

    @on(OptionList.OptionSelected)
    def _chosen(self) -> None:
        self.next()

    def save(self) -> None:
        layouts = self.query_one("#layouts", OptionList)
        if layouts.highlighted is None:
            raise ValueError("no layout matches the search")
        code = layouts.get_option_at_index(layouts.highlighted).id
        if code != self.a.get("keyboard"):
            set_keyboard(code)
            self.app.refresh(repaint=True)
        self.a["keyboard"] = code


class RolePage(Page):
    heading = "What this machine runs"

    def body(self) -> ComposeResult:
        yield OptionList(*[Option(f"{r:<6} {t}", id=r) for r, t in ROLES], id="roles")

    def on_mount(self) -> None:
        roles = self.query_one("#roles", OptionList)
        roles.highlighted = [r for r, _ in ROLES].index(self.state.get("role") or "both")
        roles.focus()

    @on(OptionList.OptionSelected)
    def _chosen(self) -> None:
        self.next()

    def save(self) -> None:
        roles = self.query_one("#roles", OptionList)
        self.a["role"] = roles.get_option_at_index(roles.highlighted or 0).id


MODES = [("Static", "static"), ("DHCP", "dhcp")]


class NetworkPage(Page):
    heading = "Network"

    def kind(self) -> str:
        """fw: the firewall's LAN and WAN; host: portitor-web only; agent: run again on an agent-only firewall."""
        role = self.a["role"]
        if role == "web":
            return "host"
        return "agent" if role == "agent" and self.app.reconfigure else "fw"

    def body(self) -> ComposeResult:
        kind, st, role = self.kind(), self.state, self.a["role"]
        static = st.get("address", "") not in ("", "dhcp")
        if kind == "fw":
            yield Static("The WAN interface connects to the Internet, which the firewall needs for updates; "
                         "the LAN interface is where you reach the GUI from. Plug in a cable to see "
                         "which interface it is; Reload updates the link state.", classes="text")
            yield row("WAN interface", Select([], id="wan", prompt="choose the WAN interface"))
            yield row("LAN interface", Select([], id="lan", prompt="choose the LAN interface"))
            yield Button("Reload interfaces", id="reload")
            yield row("WAN IPv4", Select(MODES, id="wan_mode", allow_blank=False,
                                         value="static" if st.get("wan_address") else "dhcp"))
            yield row("WAN address", Input(st.get("wan_address", ""), id="wan_address", placeholder="203.0.113.2/24"))
            yield row("Default gateway", Input(st.get("gateway", ""), id="gateway", placeholder="203.0.113.1"))
            if role != "agent":
                yield row("LAN IPv4", Select(MODES, id="lan_mode", allow_blank=False,
                                             value="dhcp" if st.get("address") == "dhcp" else "static"))
            yield row("LAN address", Input(st.get("address") if static else "192.168.1.1/24", id="address",
                                           placeholder="192.168.1.1/24"))
            yield row("LAN DHCP server", Select([("Off", "off"), ("On", "on")], id="dhcp_mode", allow_blank=False,
                                                value="on" if st.get("dhcp_range") else "off"))
            yield row("DHCP range", Input(st.get("dhcp_range", ""), id="dhcp_range",
                                          placeholder="192.168.1.100-192.168.1.199"))
            yield Static("Hands out addresses on the LAN, with the firewall as gateway and the DNS servers "
                         "below." + (" Off leaves a DHCP server set up in the GUI as it is."
                                     if self.app.reconfigure else ""), classes="hint")
        elif kind == "host":
            yield Static("The interface this host is reached on (the GUI) and reaches the firewall through. "
                         "Plug in a cable to see which interface it is; Reload updates the link state.",
                         classes="text")
            yield row("Interface", Select([], id="lan", prompt="choose the interface"))
            yield Button("Reload interfaces", id="reload")
            yield row("IPv4", Select(MODES, id="lan_mode", allow_blank=False, value="static" if static else "dhcp"))
            yield row("Address", Input(st.get("address", "") if static else "", id="address", placeholder="192.168.1.10/24"))
            yield row("Default gateway", Input(st.get("gateway", ""), id="gateway", placeholder="192.168.1.1"))
        yield row("DNS servers", Input(st.get("dns") or PUBLIC_DNS, id="dns"))
        yield Static("DNS servers " + ("this host uses" if kind == "host" else "the firewall itself uses")
                     + ": during the rest of the installation (packages, Portitor) and afterwards for "
                     + ("updates." if kind == "host" else "updates and IP lists.")
                     + " Filled in from the DHCP server on the DHCP interface, when one answers.", classes="hint")
        if role == "agent":
            yield row("portitor-web from", Input(st.get("web_from", ""), id="web_from", placeholder="the LAN network"))
            yield Static(f"portitor-web calls the agent on port {AGENT_PORT} from this address or network; "
                         "SSH is always open from it too (anti-lockout). Until the first deploy the firewall "
                         "has no routes: portitor-web must be on the LAN for that.", classes="hint")

    def on_mount(self) -> None:
        # The last answers keep their DNS servers.
        self.dns_auto, self.dns_asked = "", "-" if self.state.get("dns") else ""
        self.reload()
        self.modes()

    def dhcp_nic(self) -> str:
        """The interface whose DHCP server suggests the DNS servers: the DHCP WAN, else the DHCP LAN."""
        if self.kind() == "agent":
            return ""
        for wid, mode in (("#wan", "#wan_mode"), ("#lan", "#lan_mode")):
            for select in self.query(wid).results(Select):
                if not select.is_blank() and not self.static(mode):
                    return str(select.value)
        return ""

    def suggest_dns(self) -> None:
        nic = self.dhcp_nic()
        if nic and nic != self.dns_asked and self.dns_asked != "-":
            self.dns_asked = nic
            self.ask_dns(nic)

    @work(thread=True, exclusive=True, group="dns")
    def ask_dns(self, nic: str) -> None:
        if dns := offered_dns(nic):
            self.app.call_from_thread(self.fill_dns, " ".join(dns))

    def fill_dns(self, dns: str) -> None:
        """The DHCP server's DNS servers, unless the field was changed."""
        field = self.query_one("#dns", Input)
        if field.value.strip() in (PUBLIC_DNS, self.dns_auto):
            field.value = self.dns_auto = dns

    @on(Button.Pressed, "#reload")
    def reload(self) -> None:
        for sid, key in (("#lan", "lan"), ("#wan", "wan")):
            for select in self.query(sid).results(Select):
                set_nic_options(select, self.state.get(key, ""))

    @on(Select.Changed)
    def modes(self) -> None:
        for sid, ids in (("#lan_mode", ["#address"] + (["#gateway"] if self.kind() == "host" else [])),
                         ("#wan_mode", ["#wan_address", "#gateway"])):
            for mode in self.query(sid).results(Select):
                for i in ids:
                    self.query_one(i).disabled = mode.value == "dhcp"
        # A DHCP server needs the static LAN.
        for dhcp in self.query("#dhcp_mode").results(Select):
            dhcp.disabled = not self.static("#lan_mode")
            rng = self.query_one("#dhcp_range", Input)
            rng.disabled = dhcp.disabled or dhcp.value == "off"
            if not rng.disabled and not rng.value.strip():
                self.fill_range()
        self.suggest_dns()

    @on(Input.Changed, "#address")
    def fill_range(self) -> None:
        """A range in the LAN, while the one there is not (or empty)."""
        for rng in self.query("#dhcp_range").results(Input):
            try:
                addr = check_address(self.value("#address"))
            except ValueError:
                return
            try:
                check_dhcp_range(rng.value.strip(), addr)
            except ValueError:
                rng.value = default_dhcp_range(addr)

    def value(self, wid: str) -> str:
        return self.query_one(wid, Input).value.strip()

    def nic(self, wid: str, name: str) -> str:
        select = self.query_one(wid, Select)
        if select.is_blank():
            raise ValueError(f"choose the {name}")
        return select.value

    def static(self, wid: str) -> bool:
        modes = self.query(wid).results(Select)
        return all(m.value == "static" for m in modes)

    def field(self, name: str, check: Callable, *args):
        try:
            return check(*args)
        except ValueError as exc:
            raise ValueError(f"{name}: {exc}") from None

    def save(self) -> None:
        a, kind = self.a, self.kind()
        a["dhcp_range"] = None
        if kind == "agent":
            a.update(answers_of(self.state))
        elif kind == "host":
            a["lan"] = self.nic("#lan", "interface")
            a["address"] = self.field("Address", check_address, self.value("#address")) if self.static("#lan_mode") else None
            a["gateway"] = self.field("Default gateway", check_gateway, self.value("#gateway"), a["address"]) if a["address"] else None
            a["wan"], a["wan_address"] = "", None
        else:
            a["wan"] = self.nic("#wan", "WAN interface")
            a["lan"] = self.nic("#lan", "LAN interface")
            if a["lan"] == a["wan"]:
                raise ValueError("the LAN and WAN interfaces must differ (Swap on the last page swaps them)")
            a["address"] = self.field("LAN address", check_address, self.value("#address")) if self.static("#lan_mode") else None
            on = a["address"] and self.query_one("#dhcp_mode", Select).value == "on"
            a["dhcp_range"] = self.field("DHCP range", check_dhcp_range, self.value("#dhcp_range"), a["address"]) if on else None
            a["wan_address"] = (self.field("WAN address", check_address, self.value("#wan_address"), a["address"])
                                if self.static("#wan_mode") else None)
            # DHCP brings the default gateway.
            a["gateway"] = (self.field("Default gateway", check_gateway, self.value("#gateway"), a["wan_address"])
                            if a["wan_address"] else None)
        a["dns"] = self.field("DNS servers", parse_dns, self.value("#dns"))
        a["web_from"] = ""
        if a["role"] == "agent":
            a["web_from"] = self.field("portitor-web from", check_web_from,
                                       self.value("#web_from") or str(a["address"].network))


class AccountPage(Page):
    heading = "Password, host name and time zone"

    def body(self) -> ComposeResult:
        who = (f"the console login {CONSOLE_USER}" if self.a["role"] == "agent"
               else f"the GUI user {GUI_USER} and the console login {CONSOLE_USER}")
        if self.app.reconfigure:
            yield Static(f"A new password for {who}? Leave it empty to keep it.", classes="text")
        else:
            yield Static(f"One password for {who}, {MIN_PASSWORD} characters or more.", classes="text")
        yield row("Password", Input(password=True, id="password"))
        yield row("Again", Input(password=True, id="again"))
        yield row("Host name", Input(self.state.get("hostname") or current_hostname(), id="hostname"))
        yield Static("A name (portitor), or with its domain (fw1.example.com).", classes="hint")
        tz = self.state.get("tz") or current_timezone()
        self.zones = timezones()
        if tz not in self.zones:
            self.zones.append(tz)
        regions = sorted({tz_region(z) for z in self.zones})
        yield row("Region", Select([(r, r) for r in regions], id="region", allow_blank=False, value=tz_region(tz)))
        yield row("Time zone", Select(self.zone_options(tz_region(tz)), id="tz", allow_blank=False, value=tz))
        yield Static("Scheduled tasks use the time zone.", classes="hint")

    def on_mount(self) -> None:
        self.query_one("#password").focus()

    def zone_options(self, region: str) -> list[tuple[str, str]]:
        """The region's zones, named without the region (Stockholm)."""
        return [(z.split("/", 1)[1] if "/" in z else z, z) for z in sorted(self.zones) if tz_region(z) == region]

    @on(Select.Changed, "#region")
    def _region(self, event: Select.Changed) -> None:
        select = self.query_one("#tz", Select)
        current = select.value
        options = self.zone_options(str(event.value))
        select.set_options(options)
        if any(v == current for _, v in options):
            select.value = current

    def save(self) -> None:
        a = self.a
        pw = self.query_one("#password", Input).value
        if pw or not self.app.reconfigure:
            if len(pw) < MIN_PASSWORD:
                raise ValueError(f"Password: at least {MIN_PASSWORD} characters")
            if self.query_one("#again", Input).value != pw:
                raise ValueError("Password: the passwords differ")
        a["password"] = pw
        a["hostname"] = self.field("Host name", check_hostname, self.value("#hostname"))
        a["tz"] = check_timezone(str(self.query_one("#tz", Select).value))
        if self.app.reconfigure:
            a["reconfigure"] = True
            # The certificate names the LAN address and the host name.
            a["new_cert"] = (str(a["address"] or "dhcp") != self.state.get("address")
                             or a["hostname"] != (self.state.get("hostname") or current_hostname()))


class SummaryPage(Page):
    heading = "Apply these settings?"
    next_label = "Apply"

    def body(self) -> ComposeResult:
        yield Static("\n".join(summary(self.a)), id="summary")

    def buttons(self) -> ComposeResult:
        yield Button("Change", id="back")
        if self.a["wan"] and not (self.a["role"] == "agent" and self.a.get("reconfigure")):
            yield Button("Swap LAN and WAN", id="swap")
        yield Button(self.next_label, id="next", variant="primary")

    def on_mount(self) -> None:
        self.query_one("#next").focus()

    @on(Button.Pressed, "#swap")
    def swap(self) -> None:
        # The addresses stay with the LAN and the WAN.
        self.a["lan"], self.a["wan"] = self.a["wan"], self.a["lan"]
        self.query_one("#summary", Static).update("\n".join(summary(self.a)))


class LogPage(Screen):
    """A page with the output of what runs."""

    BINDINGS = [Binding("ctrl+q", "app.quit", "Quit")]

    def log_to_me(self) -> None:
        global output
        log = self.query_one(RichLog)
        app = self.app

        def write(msg: str) -> None:
            try:
                app.call_from_thread(log.write, msg)
            except RuntimeError:  # on the app's own thread
                log.write(msg)
        output = write


class ProgressPage(LogPage):
    """Runs the steps; a failed one can be retried."""

    def compose(self) -> ComposeResult:
        yield Header(icon=" ")
        yield Static("Applying the settings", classes="heading")
        yield RichLog(wrap=True, id="log")
        with Horizontal(id="buttons"):
            yield Button("Retry", id="retry", variant="primary", disabled=True)
            yield Button("Give up", id="giveup", variant="error", disabled=True)
        yield Footer()

    def on_mount(self) -> None:
        self.log_to_me()
        self.steps = RECONFIGURE[self.app.a["role"]] if self.app.reconfigure else FIRST_STEPS[self.app.a["role"]]
        self.run_from(0)

    @work(thread=True, exclusive=True)
    def run_from(self, i: int) -> None:
        a = self.app.a
        for j in range(i, len(self.steps)):
            if not run_step(a, *self.steps[j]):
                self.app.call_from_thread(self.failed, j)
                return
        finish(a)
        self.app.call_from_thread(self.app.steps_done)

    def failed(self, j: int) -> None:
        self.failed_at = j
        for b in self.query(Button):
            b.disabled = False
        self.query_one("#retry").focus()

    @on(Button.Pressed, "#retry")
    def retry(self) -> None:
        for b in self.query(Button):
            b.disabled = True
        self.run_from(self.failed_at)

    @on(Button.Pressed, "#giveup")
    def give_up(self) -> None:
        self.app.exit(return_code=1, message="Nothing more was changed. Run sudo portitor-setup again to retry."
                      if self.app.reconfigure else "The setup runs again at the next boot, or: sudo portitor-setup")


class JoinPage(LogPage):
    """portitor-web only: the join string from the firewall, deployed."""

    def __init__(self, optional: bool) -> None:
        super().__init__()
        self.optional = optional

    def compose(self) -> ComposeResult:
        yield Header(icon=" ")
        yield Static("Manage a firewall", classes="heading")
        yield Static("Paste the join string that the firewall's setup showed (sudo portitor-setup "
                     "--show-join on the firewall shows it again)."
                     + (" Later is fine too: sudo portitor-setup --join." if self.optional else ""), classes="text")
        yield Input(placeholder=JOIN_PREFIX + "...", id="join")
        yield Label("", id="error")
        yield RichLog(wrap=True, id="log")
        with Horizontal(id="buttons"):
            if self.optional:
                yield Button("Later", id="later")
            yield Button("Deploy", id="deploy", variant="primary")
        yield Footer()

    def on_mount(self) -> None:
        self.log_to_me()
        self.query_one("#join").focus()

    @on(Button.Pressed, "#later")
    def later(self) -> None:
        self.app.push_screen(DonePage())

    @on(Button.Pressed, "#deploy")
    @on(Input.Submitted)
    def deploy(self) -> None:
        text = "".join(self.query_one("#join", Input).value.split())
        try:
            d = decode_join(text)
        except ValueError as exc:
            self.query_one("#error", Label).update(str(exc))
            return
        wan = f"WAN {d.get('wan') or '-'} {d.get('wan_address') or ('DHCP' if d.get('wan') else '')}"
        self.query_one("#error", Label).update(f"agent {d['url']}, LAN {d['lan']} {d['address']}, {wan}")
        for b in self.query(Button):
            b.disabled = True
        self.run_join(text)

    @work(thread=True, exclusive=True)
    def run_join(self, text: str) -> None:
        ok = join(self.app.a, text)
        self.app.call_from_thread(self.joined, ok)

    def joined(self, ok: bool) -> None:
        if ok:
            self.app.joined = True
            self.app.push_screen(DonePage())
            return
        self.query_one("#error", Label).update("The deploy failed (see below). Try another join string"
                                               + (", or Later." if self.optional else "."))
        for b in self.query(Button):
            b.disabled = False


class DonePage(Screen):
    BINDINGS = [Binding("ctrl+q", "app.quit", "Quit")]

    def compose(self) -> ComposeResult:
        a = self.app.a
        yield Header(icon=" ")
        yield Static("Done", classes="heading")
        with VerticalScroll(id="body"):
            if a.get("role") == "agent":
                yield Static(join_text(a), classes="text")
            elif self.app.mode == "join":
                yield Static("The firewall is managed from here now.", classes="text")
            else:
                if self.app.joined:
                    yield Static("The firewall is managed from here now.", classes="text")
                yield Static(gui_text(a), classes="text")
        with Horizontal(id="buttons"):
            yield Button("Continue to the login prompt" if self.app.mode == "first" else "Exit",
                         id="exit", variant="primary")
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#exit").focus()

    @on(Button.Pressed, "#exit")
    def done(self) -> None:
        self.app.exit(return_code=0)


# The Linux console's font has none of the block characters of Textual's
# borders: plain lines there.
CONSOLE_CSS = """
Input, OptionList, SelectCurrent, Button, #log { border: solid $panel-lighten-2; }
Input:focus, OptionList:focus, Select:focus > SelectCurrent, Button:focus { border: solid $accent; }
SelectOverlay { border: solid $accent; }
Button { height: 3; }
Button:focus { text-style: bold; }
"""


class SetupApp(App):
    TITLE = "Portitor setup"
    # Ctrl-Q does not reach the app in every terminal (xterm.js); priority
    # so an Input's copy binding does not take it.
    BINDINGS = [Binding("ctrl+c", "quit", "Quit", priority=True)]
    ENABLE_COMMAND_PALETTE = False
    CSS = """
    #body { padding: 0 2; }
    .heading { text-style: bold; padding: 1 2; }
    #body > .heading { padding: 1 0; }
    .text { padding: 0 0 1 0; }
    .hint { color: $text-muted; padding: 0 0 1 22; }
    .row { height: auto; }
    .label { width: 20; padding: 1 1 0 0; }
    .row Input, .row Select { width: 1fr; }
    #error { color: $error; padding: 1 0 0 0; }
    #buttons { height: auto; padding: 1 0; }
    #buttons Button { margin-right: 2; }
    #layouts { height: 1fr; min-height: 10; }
    #log { height: 1fr; border: round $primary; margin: 0 2; }
    #join { margin: 0 2; }
    LogPage #error, LogPage .text { padding: 0 2; }
    """ + (CONSOLE_CSS if os.environ.get("TERM") == "linux" else "")

    def __init__(self, mode: str, state: dict) -> None:
        """mode: first (the first setup), reconfigure (run again) or join (--join)."""
        super().__init__()
        self.mode, self.state = mode, state
        self.reconfigure = mode == "reconfigure"
        self.joined = False
        self.a: dict = {"join": ""}
        if self.reconfigure:
            self.a["role"] = state.get("role") or "both"
            self.pages = [KeyboardPage, NetworkPage, AccountPage, SummaryPage, ProgressPage]
        else:
            self.pages = [KeyboardPage, RolePage, NetworkPage, AccountPage, SummaryPage, ProgressPage]

    def on_mount(self) -> None:
        if self.mode == "join":
            self.a["role"] = "web"
            self.push_screen(JoinPage(optional=False))
        else:
            self.next_page()

    def next_page(self) -> None:
        # The default screen is at the bottom of the stack.
        self.push_screen(self.pages[len(self.screen_stack) - 1]())

    def steps_done(self) -> None:
        if self.mode == "first" and self.a["role"] == "web":
            self.push_screen(JoinPage(optional=True))
        else:
            self.push_screen(DonePage())


def run_tui(mode: str, state: dict) -> int:
    global output
    # Until a page shows the output; the commands log theirs anyway.
    output = logfile
    app = SetupApp(mode, state)
    app.run()
    return app.return_code if app.return_code is not None else 1


def unattended() -> int:
    say("Portitor first-boot setup (unattended, from firstboot.answers)")
    a = read_answers()
    steps = FIRST_STEPS[a["role"]]
    if not all(run_step(a, *s) for s in steps):
        say("The setup runs again at the next boot, or: sudo portitor-setup")
        return 1
    finish(a)
    if a["role"] == "agent":
        say(join_text(a))
    elif a["role"] == "web" and a["join"] and not join(a, a["join"]):
        return 1
    say("Done." + (f" GUI: {a['url']}" if a["role"] != "agent" else ""))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Portitor setup (see the top of this file).")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--join", action="store_true", help="portitor-web only: manage the firewall of a join string")
    group.add_argument("--show-join", action="store_true", help="agent only: print the join string for portitor-web")
    args = parser.parse_args()
    if os.geteuid() != 0:
        if shutil.which("sudo"):
            os.execvp("sudo", ["sudo", sys.executable, os.path.abspath(sys.argv[0]), *sys.argv[1:]])
        say("run as root")
        return 1
    state = load_state()
    if args.join or args.show_join:
        want = "web" if args.join else "agent"
        if not DONE.exists() or (state.get("role") or "both") != want:
            say(f"{'--join' if args.join else '--show-join'} is for a machine set up as \"{want}\"")
            return 1
        if args.show_join:
            # Plain text, to copy over SSH.
            a = {**answers_of(state), "role": "agent"}
            agent_init(a)
            say(join_text(a))
            return 0
        return run_tui("join", state)
    if DONE.exists():
        # The agent owns the links now: an interface it keeps down shows no link.
        return run_tui("reconfigure", state)
    if ANSWERS.exists():
        return unattended()
    links_up()
    return run_tui("first", {})


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
