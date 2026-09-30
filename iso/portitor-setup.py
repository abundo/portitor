#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 The Portitor contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Setup of a firewall installed from the Portitor ISO (portitor-setup).

Runs on tty1 at boot (portitor-firstboot.service) until it has finished
once. It asks for the keyboard layout (applied at once, so the password
is typed with it), the LAN and WAN interfaces, the LAN address (static or
DHCP), the WAN address (DHCP, or static with the default gateway), the DNS
servers, a password and the time zone; before applying, LAN and WAN can be
swapped. Then it:

  - writes /etc/resolv.conf (the agent does not manage the firewall's own
    resolver; the one from the installation may be unreachable now),
  - creates the SQLite database and writes /etc/portitor/web.yaml, with a
    self-signed certificate for the GUI on port 443,
  - creates the GUI user admin, and sets the console user's password,
  - sets the agent up on 127.0.0.1 (portitor-web runs on the firewall itself),
  - runs `portitor-web bootstrap`: LAN (static or DHCP, which then takes no
    default route; the default route belongs to the WAN) and WAN (DHCP or
    static), described as LAN and WAN, default route, input rules for the
    GUI, SSH and ping from the LAN, a forward rule from the LAN to the WAN,
    masquerade on the WAN, and deploys (output has the instance's allow all
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
         LAN and WAN answers. `sudo portitor-setup --show-join` shows it again.
  web    portitor-web only, on a host that manages a firewall elsewhere. Its
         one interface goes in /etc/network/interfaces (DHCP or static), the
         agent is disabled, and the join string from the firewall is pasted
         (now, or later over SSH with `sudo portitor-setup --join`): that runs
         `portitor-web bootstrap --join -`, which deploys the firewall's LAN
         and WAN as above, without the GUI rule.

Run again (`sudo portitor-setup`) after it has finished, it changes the
network: the LAN and WAN interfaces (swapped, too) and addresses, the
default gateway, the DNS servers, the time zone and the keyboard layout, with the last answers
(SETUP_STATE) as defaults; a password is optional there. It leaves the
database, the agent and every other interface alone, runs `portitor-web
bootstrap --reconfigure`, and makes a new GUI certificate when the LAN
address changes.

With /etc/portitor/firstboot.answers (an ISO built with `iso/build.sh
--test`), nothing is asked: it holds "key: value" lines for lan (a name or
MAC address), address (dhcp for DHCP), wan (a name or MAC address,
optional), wan_address
(empty: DHCP), gateway (on the static WAN, else on the LAN), dns (space
separated), password, timezone and keyboard (an XKB layout, e.g. se). The file is removed when the setup has
finished. role (both, agent or web) picks the split setups; agent reads
web_from (portitor-web's address or network, default the LAN network), web
reads lan and address (its own interface), gateway and join (optional).
"""

from __future__ import annotations

import argparse
import base64
import getpass
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
KEYBOARD = Path("/etc/default/keyboard")
XKB_RULES = Path("/usr/share/X11/xkb/rules/base.lst")
# The layouts the setup lists; any other XKB layout can be typed or searched.
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


def say(msg: str = "") -> None:
    print(msg, flush=True)


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
# questions
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


def ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    while True:
        try:
            answer = input(f"{prompt}{suffix}: ").strip()
        except EOFError:
            sys.exit(1)
        if answer or default:
            return answer or default


def ask_nic(role: str, explain: str, taken: str = "", default: str = "") -> str:
    while True:
        found = nics()
        if not found:
            say("No network interfaces found.")
            input("Press Enter to look again.")
            continue
        say()
        say("  #  Interface        MAC                Link     Driver")
        for i, n in enumerate(found, 1):
            link = "up" if n["carrier"] else "no link"
            used = "  (LAN)" if n["name"] == taken else ""
            say(f"  {i}  {n['name']:<16} {n['mac']:<18} {link:<8} {n['driver']} {n['speed']}{used}")
        say()
        say(explain)
        if not any(n["name"] == default for n in found):
            default = ""
        answer = ask(f"{role} interface (1-{len(found)} or name, r reloads)", default)
        if answer.lower() == "r":
            continue
        if answer.isdigit() and 1 <= int(answer) <= len(found):
            answer = found[int(answer) - 1]["name"]
        if not any(n["name"] == answer for n in found):
            say(f"  no interface {answer}")
        elif answer == taken:
            say(f"  {answer} is the LAN interface (s at the end swaps LAN and WAN)")
        else:
            return answer


def links_up() -> None:
    # Links must be up to show whether a cable is plugged in.
    for n in nics():
        run(["ip", "link", "set", n["name"], "up"], check=False, quiet=True)
    time.sleep(2)


def ask_lan(default: str = "") -> str:
    return ask_nic("LAN", "The LAN interface is where you reach the GUI from. Plug in its cable to see\n"
                   "which one it is; r reloads the list.", default=default)


def ask_wan(lan: str, default: str = "") -> str:
    return ask_nic("WAN", "The WAN interface connects to the Internet, which the firewall needs for\n"
                   "updates. Plug in its cable to see which one it is; r reloads the list.", lan, default)


def ask_address(role: str, default: str = "",
                other: ipaddress.IPv4Interface | None = None) -> ipaddress.IPv4Interface:
    while True:
        answer = ask(f"{role} address with prefix length", default)
        try:
            iface = ipaddress.IPv4Interface(answer)
        except ValueError:
            say("  an IPv4 address with a prefix length, e.g. 192.168.1.1/24")
            continue
        net = iface.network
        if "/" not in answer:
            say("  add the prefix length, e.g. /24")
        elif net.prefixlen < 31 and iface.ip in (net.network_address, net.broadcast_address):
            say(f"  {iface.ip} is the network or broadcast address of {net}")
        elif net.prefixlen > 30:
            say("  use a prefix length of 30 or less")
        elif other and net.overlaps(other.network):
            say(f"  {net} overlaps the LAN {other.network}")
        else:
            return iface


def ask_ipv4(role: str, default: str, dhcp: bool,
             other: ipaddress.IPv4Interface | None = None) -> ipaddress.IPv4Interface | None:
    """A static address, or None for DHCP; dhcp is the default mode."""
    while True:
        answer = ask(f"{role} IPv4: dhcp or static", "dhcp" if dhcp else "static").lower()
        if answer == "dhcp":
            return None
        if answer == "static":
            return ask_address(role, default, other=other)
        say("  dhcp or static")


def ask_gateway(addr: ipaddress.IPv4Interface, default: str = "") -> ipaddress.IPv4Address:
    while True:
        answer = ask("Default gateway", default)
        try:
            gw = ipaddress.IPv4Address(answer)
        except ValueError:
            say("  an IPv4 address")
            continue
        if gw not in addr.network or gw == addr.ip:
            say(f"  must be another address in {addr.network}")
            continue
        return gw


def parse_dns(answer: str) -> list[str]:
    servers = [str(ipaddress.ip_address(a)) for a in answer.replace(",", " ").split()]
    if not 1 <= len(servers) <= 3:
        raise ValueError("one to three addresses")
    return servers


def ask_dns(default: str = PUBLIC_DNS, who: str = "the firewall itself uses (updates, IP lists)") -> list[str]:
    say(f"DNS servers {who}.")
    while True:
        answer = ask("DNS servers", default)
        try:
            return parse_dns(answer)
        except ValueError:
            say("  one to three IP addresses, separated by spaces")


def ask_password(optional: bool = False) -> str:
    """With optional, empty keeps the passwords."""
    while True:
        a = getpass.getpass(f"Password ({MIN_PASSWORD}+ characters{', empty keeps it' if optional else ''}): ")
        if optional and not a:
            return ""
        if len(a) < MIN_PASSWORD:
            say(f"  at least {MIN_PASSWORD} characters")
            continue
        if getpass.getpass("Again: ") != a:
            say("  the passwords differ")
            continue
        return a


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


def ask_keyboard(default: str = "") -> str:
    """Asks for the keyboard layout and applies it at once."""
    known = xkb_layouts()
    default = default or current_layout()
    say()
    half = (len(LAYOUTS) + 1) // 2
    for i in range(half):
        row = ""
        for j in (i, i + half):
            if j < len(LAYOUTS):
                code, name = LAYOUTS[j]
                row += f"  {j + 1:>2}  {code:<4} {name:<22}"
        say(row.rstrip())
    say()
    while True:
        answer = ask(f"Keyboard layout (1-{len(LAYOUTS)}, a layout code, or a word to search)", default)
        if answer.isdigit() and 1 <= int(answer) <= len(LAYOUTS):
            answer = LAYOUTS[int(answer) - 1][0]
        if answer in known:
            set_keyboard(answer)
            return answer
        word = answer.lower()
        found = [(c, n) for c, n in known.items() if word in c or word in n.lower()]
        if not found:
            say(f"  no layout matches {answer}")
            continue
        for code, name in found[:20]:
            say(f"  {code:<8} {name}")
        if len(found) > 20:
            say(f"  ... {len(found) - 20} more; search for more of the name")


def ask_role(default: str = "both") -> str:
    say()
    for i, (role, text) in enumerate(ROLES, 1):
        say(f"  {i}  {role:<6} {text}")
    say()
    while True:
        answer = ask(f"This machine runs (1-{len(ROLES)} or a name)", default).lower()
        if answer.isdigit() and 1 <= int(answer) <= len(ROLES):
            answer = ROLES[int(answer) - 1][0]
        if answer in dict(ROLES):
            return answer
        say("  " + ", ".join(r for r, _ in ROLES))


def ask_web_from(lan: ipaddress.IPv4Interface, default: str = "") -> str:
    say("portitor-web calls the agent on port {} from this address or network; SSH is".format(AGENT_PORT))
    say("always open from it too (anti-lockout). Until the first deploy the firewall has")
    say(f"no routes: portitor-web must be on the LAN, {lan.network}, for that.")
    while True:
        answer = ask("portitor-web's address or network", default or str(lan.network))
        try:
            return str(ipaddress.IPv4Network(answer, strict=False))
        except ValueError:
            say("  an IPv4 address, or a network with its prefix length")


def ask_host(state: dict) -> dict:
    """portitor-web only: the host's one interface, its address and DNS."""
    nic = ask_nic("Network", "The interface this host is reached on (the GUI) and reaches the firewall\n"
                  "through. Plug in its cable to see which one it is; r reloads the list.", default=state.get("lan", ""))
    say()
    default = state.get("address", "")
    address = ask_ipv4("Host", "" if default in ("", "dhcp") else default, default in ("", "dhcp"))
    gateway = ask_gateway(address, state.get("gateway", "")) if address else None
    say()
    dns = ask_dns(state.get("dns") or PUBLIC_DNS, "this host uses")
    return {"lan": nic, "address": address, "wan": "", "wan_address": None, "gateway": gateway, "dns": dns}


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


def ask_join(optional: bool) -> str:
    """The join string from the firewall; empty (with optional) for later."""
    say("Paste the join string that the firewall's setup showed (sudo portitor-setup")
    say("--show-join on the firewall shows it again).")
    while True:
        try:
            answer = "".join(input("Join string" + (" (empty: later, sudo portitor-setup --join)" if optional else "") + ": ").split())
        except EOFError:
            sys.exit(1)
        if not answer and optional:
            return ""
        try:
            d = decode_join(answer)
        except ValueError as exc:
            say(f"  {exc}")
            continue
        say(f"  agent {d['url']}, LAN {d['lan']} {d['address']}, WAN {d.get('wan') or '-'} {d.get('wan_address') or ('DHCP' if d.get('wan') else '')}")
        return answer


def ask_timezone() -> str:
    current = run(["timedatectl", "show", "-p", "Timezone", "--value"], check=False, quiet=True).stdout.strip() or "Etc/UTC"
    while True:
        answer = ask("Time zone (e.g. Europe/Stockholm; scheduled tasks use it)", current)
        if re.fullmatch(r"[A-Za-z0-9_+-]+(/[A-Za-z0-9_+-]+)*", answer) and Path("/usr/share/zoneinfo", answer).is_file():
            return answer
        say(f"  unknown time zone {answer}")


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


def step_database(a: dict) -> None:
    run(["install", "-d", "-o", WEB_USER, "-g", WEB_GROUP, "-m", "0700", str(WEB_DB_DIR)])


def step_cert(a: dict) -> None:
    host = socket.gethostname()
    # A DHCP LAN has no fixed address to name.
    san = f"IP:{a['address'].ip},DNS:{host}" if a["address"] else f"DNS:{host}"
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


def step_bootstrap(a: dict) -> None:
    argv = web("bootstrap", "--lan", a["lan"], "--address", str(a["address"] or "dhcp"), "--gui-port", str(GUI_PORT))
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
    ("Users", step_users),
    ("portitor-agent", step_agent),
    ("LAN address until the first deploy", step_lan_unit),
]

WEB_STEPS = [
    ("Keyboard layout", step_keyboard),
    ("Network", step_host_network),
    ("DNS servers", step_dns),
    ("Time zone", step_timezone),
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
    ("Users", step_users),
    ("portitor-agent", step_agent),
]

WEB_RECONFIGURE_STEPS = [
    ("Keyboard layout", step_keyboard),
    ("Network", step_host_network),
    ("DNS servers", step_dns),
    ("Time zone", step_timezone),
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
        "dns": parse_dns(raw.get("dns") or PUBLIC_DNS),
        "password": raw["password"],
        "tz": raw.get("timezone") or "Etc/UTC",
        "keyboard": keyboard,
        "web_from": "",
        "join": raw.get("join", ""),
    }
    if role == "agent":
        if not a["address"]:
            raise RuntimeError(f"{ANSWERS}: the agent-only firewall needs a static LAN address")
        a["web_from"] = str(ipaddress.IPv4Network(raw.get("web_from") or a["address"].network, strict=False))
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
    state = {k: str(a[k]) if a.get(k) else "" for k in ("role", "lan", "wan", "wan_address", "gateway", "tz", "keyboard", "web_from")}
    state["address"] = str(a["address"] or "dhcp")
    state["dns"] = " ".join(a["dns"])
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


def run_steps(a: dict, interactive: bool, steps: list) -> bool:
    i = 0
    while i < len(steps):
        title, fn = steps[i]
        say(f"==> {title}")
        try:
            fn(a)
            i += 1
        except Exception as exc:  # noqa: BLE001 - shown to the operator, then retried
            logfile(f"FAILED: {exc}")
            say(f"!!  {exc}")
            say(f"    (log: {LOG})")
            if not interactive or ask("Retry this step? (y: retry, n: leave to a shell login)", "y").lower() not in ("y", "yes"):
                if a.get("reconfigure"):
                    say("Nothing more was changed. Run sudo portitor-setup again to retry.")
                else:
                    say("The setup runs again at the next boot, or: sudo portitor-setup")
                return False
    save_state(a)
    DONE.parent.mkdir(parents=True, exist_ok=True)
    DONE.touch()
    ANSWERS.unlink(missing_ok=True)
    return True


def ask_network(state: dict, static_lan: bool = False) -> dict:
    """The network questions, with the defaults from state. static_lan: the
    agent-only firewall, which portitor-web must find at a fixed address."""
    lan = ask_lan(state.get("lan", ""))
    wan = ask_wan(lan, state.get("wan", ""))
    say()
    lan_default = state.get("address", "")
    lan_default = "192.168.1.1/24" if lan_default in ("", "dhcp") else lan_default
    if static_lan:
        address = ask_address("LAN", lan_default)
    else:
        address = ask_ipv4("LAN", lan_default, state.get("address") == "dhcp")
    wan_address = ask_ipv4("WAN", state.get("wan_address", ""), not state.get("wan_address"), other=address)
    # DHCP brings the default gateway.
    gateway = ask_gateway(wan_address, state.get("gateway", "")) if wan_address else None
    say()
    dns = ask_dns(state.get("dns") or PUBLIC_DNS)
    return {"lan": lan, "address": address, "wan": wan, "wan_address": wan_address, "gateway": gateway, "dns": dns}


def ask_all(state: dict, role: str, reconfigure: bool) -> dict:
    """The questions for role, with the defaults from state."""
    # First: the password is typed with it.
    keyboard = ask_keyboard(state.get("keyboard", ""))
    if role == "web":
        a = ask_host(state)
    elif role == "agent" and reconfigure:
        # portitor-web configures the firewall's network now.
        a = answers_of(state)
        say()
        a["dns"] = ask_dns(state.get("dns") or PUBLIC_DNS)
    else:
        a = ask_network(state, static_lan=role == "agent")
    a["role"], a["keyboard"], a["join"] = role, keyboard, ""
    a["web_from"] = ask_web_from(a["address"], state.get("web_from", "")) if role == "agent" else ""
    say()
    who = f"the console login {CONSOLE_USER}" if role == "agent" else f"the GUI user {GUI_USER} and the console login {CONSOLE_USER}"
    if reconfigure:
        say(f"A new password for {who}?")
    else:
        say(f"One password for {who}.")
    a["password"] = ask_password(optional=reconfigure)
    a["tz"] = ask_timezone()
    if reconfigure:
        a["reconfigure"] = True
        a["new_cert"] = str(a["address"] or "dhcp") != state.get("address")
    return a


def summary(a: dict) -> None:
    say()
    say(f"  Runs            {a['role']}: {dict(ROLES)[a['role']]}")
    if a["role"] == "web":
        say(f"  Interface       {a['lan']}")
        say(f"  Address         {a['address'] or 'DHCP'}")
        say(f"  Default gateway {a['gateway'] or 'from DHCP'}")
    elif a["role"] == "agent" and a.get("reconfigure"):
        say(f"  portitor-web    {a['web_from']}")
    else:
        say(f"  LAN interface   {a['lan']}")
        say(f"  LAN address     {a['address'] or 'DHCP (no default route)'}")
        say(f"  WAN interface   {a['wan']}")
        say(f"  WAN address     {a['wan_address'] or 'DHCP'}")
        say(f"  Default gateway {a['gateway'] or 'from DHCP'}")
        if a["role"] == "agent":
            say(f"  portitor-web    {a['web_from']}")
    say(f"  DNS servers     {' '.join(a['dns'])}")
    say(f"  Time zone       {a['tz']}")
    say(f"  Keyboard        {a['keyboard']}")
    if a.get("reconfigure"):
        say(f"  Password        {'new' if a['password'] else 'unchanged'}")


def confirm(a: dict) -> bool:
    """Shows the answers; s swaps the LAN and WAN interfaces. False: ask again."""
    swap = a["wan"] and not (a["role"] == "agent" and a.get("reconfigure"))
    while True:
        summary(a)
        answer = ask("Apply? (y: yes, n: change the answers" + (", s: swap LAN and WAN)" if swap else ")"), "y").lower()
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no"):
            return False
        if swap and answer in ("s", "swap"):
            a["lan"], a["wan"] = a["wan"], a["lan"]


def show_gui(a: dict) -> None:
    say()
    say("Open the GUI from the LAN:" if a["role"] == "both" else "Open the GUI:")
    say()
    say(f"    {a['url']}    user {GUI_USER}")
    say()
    say("The browser warns about the self-signed certificate; its SHA-256 fingerprint is")
    say(f"    {a['cert_fp']}")
    say()


def show_join(a: dict) -> None:
    """Agent only: the join string for portitor-web."""
    text = join_string(a)
    say()
    say("Run sudo portitor-setup on the portitor-web host (installed from the ISO as")
    say("\"web\", or later: sudo portitor-setup --join) and paste this join string:")
    say()
    say(text)
    say()
    say("It holds the agent's token: keep it like a password. Easiest is to copy it over")
    say(f"SSH (ssh {CONSOLE_USER}@{a['address'].ip}, then sudo portitor-setup --show-join). A")
    say("portitor-web installed with install.py takes it too:")
    say(f"    sudo runuser -u {WEB_USER} -- portitor-web -f {WEB_YAML} bootstrap --join -")
    say("(paste it, Enter, Ctrl-D). By hand, in portitor-web's Settings > Agent:")
    say(f"    Agent URL    https://{a['address'].ip}:{AGENT_PORT}")
    say(f"    Fingerprint  {a['fingerprint']}")
    say(f"    Token        in {AGENT_TOKEN}")
    say("but then configure the LAN interface there before the first deploy.")
    say()


def ask_join_and_deploy(a: dict, optional: bool) -> bool:
    """portitor-web only: asks for the join string until the firewall is deployed."""
    while True:
        text = a.pop("join", "") or ask_join(optional)
        if not text:
            return True
        if join(a, text):
            return True
        if ask("Try another join string? (y: yes, n: later, sudo portitor-setup --join)", "y").lower() not in ("y", "yes"):
            return False


def reconfigure() -> int:
    """portitor-setup after the first setup: change the network."""
    state = load_state()
    role = state.get("role") or "both"
    say()
    say("Portitor setup: change the settings")
    say("===================================")
    say("The first setup has run already.")
    if role == "both":
        say("This changes the LAN and WAN interfaces and")
        say("addresses, the default gateway, the DNS servers, the time zone and the keyboard")
        say("layout, and deploys at once, without the confirm timeout. Other settings are")
        say("kept. A session over the old LAN address drops; the console is the safe place")
        say("to run this.")
    elif role == "agent":
        say("This changes portitor-web's address, the DNS servers, the time")
        say("zone, the keyboard layout and the console password. portitor-web manages the")
        say("network. sudo portitor-setup --show-join shows the join string.")
    else:
        say("This changes this host's interface and address, the DNS")
        say("servers, the time zone, the keyboard layout and the password. A session over")
        say("the old address drops. sudo portitor-setup --join manages another firewall.")
    # The agent owns the links now: an interface it keeps down shows no link.
    while True:
        a = ask_all(state, role, reconfigure=True)
        if confirm(a):
            break
        state = state_of(a)
    if not run_steps(a, interactive=True, steps=RECONFIGURE[role]):
        return 1
    say()
    say("Done.")
    if role != "agent":
        show_gui(a)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Portitor setup (see the top of this file).")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--join", action="store_true", help="portitor-web only: manage the firewall of a join string")
    group.add_argument("--show-join", action="store_true", help="agent only: show the join string for portitor-web")
    args = parser.parse_args()
    if os.geteuid() != 0:
        if shutil.which("sudo"):
            os.execvp("sudo", ["sudo", sys.executable, os.path.abspath(sys.argv[0]), *sys.argv[1:]])
        say("run as root")
        return 1
    if args.join or args.show_join:
        state = load_state()
        want = "web" if args.join else "agent"
        if not DONE.exists() or (state.get("role") or "both") != want:
            say(f"{'--join' if args.join else '--show-join'} is for a machine set up as \"{want}\"")
            return 1
        if args.show_join:
            a = {**answers_of(state), "role": "agent"}
            agent_init(a)
            show_join(a)
            return 0
        return 0 if ask_join_and_deploy({}, optional=False) else 1
    if DONE.exists():
        return reconfigure()
    if ANSWERS.exists():
        say("Portitor first-boot setup (unattended, from firstboot.answers)")
        a = read_answers()
        if not run_steps(a, interactive=False, steps=FIRST_STEPS[a["role"]]):
            return 1
        if a["role"] == "agent":
            show_join(a)
        elif a["role"] == "web" and a["join"] and not join(a, a["join"]):
            return 1
        say("Done." + (f" GUI: {a['url']}" if a["role"] != "agent" else ""))
        return 0
    say()
    say("Portitor first-boot setup")
    say("=========================")
    links_up()
    state: dict = {}
    while True:
        role = ask_role(state.get("role") or "both")
        a = ask_all(state, role, reconfigure=False)
        if confirm(a):
            break
        state = state_of(a)

    if not run_steps(a, interactive=True, steps=FIRST_STEPS[role]):
        return 1
    if role == "web":
        say()
        ask_join_and_deploy(a, optional=True)
    say()
    say("Done.")
    if role == "agent":
        show_join(a)
    else:
        show_gui(a)
    say("Press Enter for the login prompt.")
    try:
        input()
    except EOFError:
        pass
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
