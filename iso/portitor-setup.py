#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 The Portitor contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Setup of a firewall installed from the Portitor ISO (portitor-setup).

Runs on tty1 at boot (portitor-firstboot.service) until it has finished
once. It asks for the LAN and WAN interfaces, the LAN address (static or
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
    default route), WAN (DHCP or static), default route, rules for the GUI
    and ping from the LAN, and deploys,
  - starts portitor-web and writes the GUI's address to /etc/issue.d (with a
    DHCP LAN, agetty shows its current address).

Every step can be repeated; a failed one is retried with the same answers.

Run again (`sudo portitor-setup`) after it has finished, it changes the
network: the LAN and WAN interfaces (swapped, too) and addresses, the
default gateway, the DNS servers and the time zone, with the last answers
(SETUP_STATE) as defaults; a password is optional there. It leaves the
database, the agent and every other interface alone, runs `portitor-web
bootstrap --reconfigure`, and makes a new GUI certificate when the LAN
address changes.

With /etc/portitor/firstboot.answers (an ISO built with `iso/build.sh
--test`), nothing is asked: it holds "key: value" lines for lan (a name or
MAC address), address (dhcp for DHCP), wan (a name or MAC address,
optional), wan_address
(empty: DHCP), gateway (on the static WAN, else on the LAN), dns (space
separated), password and timezone. The file is removed when the setup has
finished.
"""

from __future__ import annotations

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
MIN_PASSWORD = 10  # portitor-web's minimum


def say(msg: str = "") -> None:
    print(msg, flush=True)


def logfile(msg: str) -> None:
    with LOG.open("a", encoding="utf-8") as f:
        f.write(f"{time.strftime('%F %T')} {msg}\n")


def run(argv: list[str], *, stdin: str | None = None, check: bool = True, quiet: bool = False) -> subprocess.CompletedProcess[str]:
    logfile("$ " + " ".join(argv))
    proc = subprocess.run(argv, input=stdin, capture_output=True, text=True, check=False)
    out = (proc.stdout + proc.stderr).strip()
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


def ask_dns(default: str = PUBLIC_DNS) -> list[str]:
    say("DNS servers the firewall itself uses (updates, IP lists).")
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
    run(web("createadmin", GUI_USER), stdin=a["password"] + "\n")
    run(["chpasswd"], stdin=f"{CONSOLE_USER}:{a['password']}\n", quiet=True)


def step_agent(a: dict) -> None:
    out = run(["portitor-agent", "init", "--host", "127.0.0.1", "--host", "localhost"], quiet=True).stdout
    m = re.search(r"^fingerprint:\s*([0-9a-f]{64})\s*$", out, re.M)
    if not m:
        raise RuntimeError(f"no fingerprint in the output of portitor-agent init:\n{out}")
    a["fingerprint"] = m[1]
    write(AGENT_YAML, f"""# /etc/portitor/agent.yaml - written by the first-boot setup.
# portitor-web runs on this host and is the only client of the API.
listen: {AGENT_LISTEN}
token_file: {ETC}/agent.token
tls_cert: {ETC}/agent.crt
tls_key: {ETC}/agent.key
allow_from:
  - 127.0.0.1/32
console_user: {CONSOLE_USER}
""", 0o600)
    run(["systemctl", "enable", "portitor-agent.service"])
    run(["systemctl", "restart", "portitor-agent.service"])


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
        "--agent-token-file", "/dev/stdin",
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


# The first setup.
STEPS = [
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

# Run again: the network only.
RECONFIGURE_STEPS = [
    ("DNS servers", step_dns),
    ("Time zone", step_timezone),
    ("GUI certificate", step_new_cert),
    ("Users", step_users),
    ("Deploy the LAN and WAN configuration", step_bootstrap),
    ("Restart portitor-web", step_web),
    ("Login screen", step_issue),
]


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

    return {
        "lan": nic("lan"),
        "address": None if raw["address"].lower() == "dhcp" else ipaddress.IPv4Interface(raw["address"]),
        "wan": nic("wan") if raw.get("wan") else "",
        "wan_address": ipaddress.IPv4Interface(raw["wan_address"]) if raw.get("wan_address") else None,
        "gateway": ipaddress.IPv4Address(raw["gateway"]) if raw.get("gateway") else None,
        "dns": parse_dns(raw.get("dns") or PUBLIC_DNS),
        "password": raw["password"],
        "tz": raw.get("timezone") or "Etc/UTC",
    }


def load_state() -> dict:
    """The last answers, as strings; empty if there are none."""
    try:
        state = json.loads(SETUP_STATE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return state if isinstance(state, dict) else {}


def state_of(a: dict) -> dict:
    """The answers as strings, without the password; a DHCP LAN is "dhcp"."""
    state = {k: str(a[k]) if a[k] else "" for k in ("lan", "wan", "wan_address", "gateway", "tz")}
    state["address"] = str(a["address"] or "dhcp")
    state["dns"] = " ".join(a["dns"])
    return state


def save_state(a: dict) -> None:
    write(SETUP_STATE, json.dumps(state_of(a), indent=2) + "\n", 0o600)


def run_steps(a: dict, interactive: bool, steps: list = STEPS) -> bool:
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


def ask_network(state: dict) -> dict:
    """The network questions, with the defaults from state."""
    lan = ask_lan(state.get("lan", ""))
    wan = ask_wan(lan, state.get("wan", ""))
    say()
    lan_default = state.get("address", "")
    address = ask_ipv4("LAN", "192.168.1.1/24" if lan_default in ("", "dhcp") else lan_default, lan_default == "dhcp")
    wan_address = ask_ipv4("WAN", state.get("wan_address", ""), not state.get("wan_address"), other=address)
    # DHCP brings the default gateway.
    gateway = ask_gateway(wan_address, state.get("gateway", "")) if wan_address else None
    say()
    dns = ask_dns(state.get("dns") or PUBLIC_DNS)
    return {"lan": lan, "address": address, "wan": wan, "wan_address": wan_address, "gateway": gateway, "dns": dns}


def summary(a: dict) -> None:
    say()
    say(f"  LAN interface   {a['lan']}")
    say(f"  LAN address     {a['address'] or 'DHCP (no default route)'}")
    say(f"  WAN interface   {a['wan']}")
    say(f"  WAN address     {a['wan_address'] or 'DHCP'}")
    say(f"  Default gateway {a['gateway'] or 'from DHCP'}")
    say(f"  DNS servers     {' '.join(a['dns'])}")
    say(f"  Time zone       {a['tz']}")
    if a.get("reconfigure"):
        say(f"  Password        {'new' if a['password'] else 'unchanged'}")


def confirm(a: dict) -> bool:
    """Shows the answers; s swaps the LAN and WAN interfaces. False: ask again."""
    while True:
        summary(a)
        answer = ask("Apply? (y: yes, n: change the answers, s: swap LAN and WAN)", "y").lower()
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no"):
            return False
        if answer in ("s", "swap"):
            a["lan"], a["wan"] = a["wan"], a["lan"]


def show_gui(a: dict) -> None:
    say()
    say("Open the GUI from the LAN:")
    say()
    say(f"    {a['url']}    user {GUI_USER}")
    say()
    say("The browser warns about the self-signed certificate; its SHA-256 fingerprint is")
    say(f"    {a['cert_fp']}")
    say()


def reconfigure() -> int:
    """portitor-setup after the first setup: change the network."""
    state = load_state()
    say()
    say("Portitor setup: change the network")
    say("==================================")
    say("The first setup has run already. This changes the LAN and WAN interfaces and")
    say("addresses, the default gateway, the DNS servers and the time zone, and deploys")
    say("at once, without the confirm timeout. Other settings are kept. A session over")
    say("the old LAN address drops; the console is the safe place to run this.")
    # The agent owns the links now: an interface it keeps down shows no link.
    while True:
        a = ask_network(state)
        a["tz"] = ask_timezone()
        say()
        say(f"A new password for the GUI user {GUI_USER} and the console login {CONSOLE_USER}?")
        a["password"] = ask_password(optional=True)
        a["reconfigure"] = True
        a["new_cert"] = str(a["address"] or "dhcp") != state.get("address")
        if confirm(a):
            break
        state = state_of(a)
    if not run_steps(a, interactive=True, steps=RECONFIGURE_STEPS):
        return 1
    say()
    say("Done.")
    show_gui(a)
    return 0


def main() -> int:
    if os.geteuid() != 0:
        if shutil.which("sudo"):
            os.execvp("sudo", ["sudo", sys.executable, os.path.abspath(sys.argv[0]), *sys.argv[1:]])
        say("run as root")
        return 1
    if DONE.exists():
        return reconfigure()
    if ANSWERS.exists():
        say("Portitor first-boot setup (unattended, from firstboot.answers)")
        a = read_answers()
        if not run_steps(a, interactive=False):
            return 1
        say(f"Done. GUI: {a['url']}")
        return 0
    say()
    say("Portitor first-boot setup")
    say("=========================")
    links_up()
    state: dict = {}
    while True:
        a = ask_network(state)
        say()
        say(f"One password for the GUI user {GUI_USER} and the console login {CONSOLE_USER}.")
        a["password"] = ask_password()
        a["tz"] = ask_timezone()
        if confirm(a):
            break
        state = state_of(a)

    if not run_steps(a, interactive=True):
        return 1
    say()
    say("Done.")
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
