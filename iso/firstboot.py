#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 The Portitor contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""First-boot setup of a firewall installed from the Portitor ISO.

Runs on tty1 (portitor-firstboot.service) until it has finished once. It
asks for the LAN interface, its address and the default gateway, the DNS
servers, a password and the time zone, then:

  - writes /etc/resolv.conf (the agent does not manage the firewall's own
    resolver; the one from the installation may be unreachable now),
  - creates the SQLite database and writes /etc/portitor/web.yaml, with a
    self-signed certificate for the GUI on port 443,
  - creates the GUI user admin, and sets the console user's password,
  - sets the agent up on 127.0.0.1 (portitor-web runs on the firewall itself),
  - runs `portitor-web bootstrap`: LAN address, default route, rules for the
    GUI and ping from the LAN, and deploys,
  - starts portitor-web and writes the GUI's address to /etc/issue.d.

Every step can be repeated; a failed one is retried with the same answers.

With /etc/portitor/firstboot.answers (an ISO built with `iso/build.sh
--test`), nothing is asked: it holds "key: value" lines for lan (a name or
MAC address), address, gateway, dns (space separated), password and
timezone. The file is removed
when the setup has finished.
"""

from __future__ import annotations

import getpass
import ipaddress
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
ANSWERS = Path("/etc/portitor/firstboot.answers")
LOG = Path("/var/log/portitor-firstboot.log")
ETC = Path("/etc/portitor")
WEB_YAML = ETC / "web.yaml"
AGENT_YAML = ETC / "agent.yaml"
WEB_CERT = ETC / "web.crt"
WEB_KEY = ETC / "web.key"
WEB_DROPIN = Path("/etc/systemd/system/portitor-web.service.d/firstboot.conf")
ISSUE = Path("/etc/issue.d/portitor.issue")
RESOLV_CONF = Path("/etc/resolv.conf")
PUBLIC_DNS = "9.9.9.9 1.1.1.1"
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


def ask_lan() -> str:
    # Links must be up to show whether a cable is plugged in.
    for n in nics():
        run(["ip", "link", "set", n["name"], "up"], check=False, quiet=True)
    time.sleep(2)
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
            say(f"  {i}  {n['name']:<16} {n['mac']:<18} {link:<8} {n['driver']} {n['speed']}")
        say()
        say("The LAN interface is where you reach the GUI from. Plug in its cable to see")
        say("which one it is; r reloads the list.")
        answer = ask(f"LAN interface (1-{len(found)} or name, r reloads)")
        if answer.lower() == "r":
            continue
        if answer.isdigit() and 1 <= int(answer) <= len(found):
            return found[int(answer) - 1]["name"]
        if any(n["name"] == answer for n in found):
            return answer
        say(f"  no interface {answer}")


def ask_address() -> ipaddress.IPv4Interface:
    while True:
        answer = ask("LAN address with prefix length", "192.168.1.1/24")
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
        else:
            return iface


def ask_gateway(addr: ipaddress.IPv4Interface) -> ipaddress.IPv4Address | None:
    say("The default gateway is optional: leave it empty when the WAN interface will")
    say("get it by DHCP (configure the WAN in the GUI).")
    while True:
        answer = input("Default gateway (empty: none): ").strip()
        if not answer:
            return None
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


def ask_dns(gateway: ipaddress.IPv4Address | None) -> list[str]:
    say("DNS servers the firewall itself uses (updates, IP lists).")
    while True:
        answer = ask("DNS servers", str(gateway) if gateway else PUBLIC_DNS)
        try:
            return parse_dns(answer)
        except ValueError:
            say("  one to three IP addresses, separated by spaces")


def ask_password() -> str:
    while True:
        a = getpass.getpass(f"Password ({MIN_PASSWORD}+ characters): ")
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
    # Only the LAN stays up; the others are imported as they are, so down.
    for n in nics():
        if n["name"] != a["lan"]:
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


def step_web_config(a: dict) -> None:
    host = socket.gethostname()
    run([
        "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
        "-nodes", "-days", "3650", "-subj", f"/CN={host}",
        "-addext", f"subjectAltName=IP:{a['address'].ip},DNS:{host}",
        "-keyout", str(WEB_KEY), "-out", str(WEB_CERT),
    ], quiet=True)
    for f in (WEB_KEY, WEB_CERT):
        os.chmod(f, 0o640)
        shutil.chown(f, "root", WEB_GROUP)
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
    # The token file is root's; the web user reads it from stdin.
    argv = web(
        "bootstrap",
        "--agent-url", f"https://{AGENT_LISTEN}",
        "--agent-token-file", "/dev/stdin",
        "--agent-fingerprint", a["fingerprint"],
        "--lan", a["lan"], "--address", str(a["address"]), "--gui-port", str(GUI_PORT),
    )
    if a["gateway"]:
        argv += ["--gateway", str(a["gateway"])]
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


def step_issue(a: dict) -> None:
    fp = run(["openssl", "x509", "-in", str(WEB_CERT), "-noout", "-fingerprint", "-sha256"], quiet=True).stdout
    fp = fp.strip().split("=", 1)[-1]
    a["url"], a["cert_fp"] = f"https://{a['address'].ip}/", fp
    write(ISSUE, f"""Portitor firewall. GUI: {a['url']} (user {GUI_USER})
Certificate SHA-256: {fp}

""", 0o644)


STEPS = [
    ("Interfaces", step_links),
    ("DNS servers", step_dns),
    ("Time zone", step_timezone),
    ("Database", step_database),
    ("portitor-web configuration", step_web_config),
    ("Users", step_users),
    ("portitor-agent", step_agent),
    ("Deploy the LAN configuration", step_bootstrap),
    ("Start portitor-web", step_web),
    ("Login screen", step_issue),
]


def read_answers() -> dict:
    """The answers file (unattended test installs)."""
    raw = {}
    for line in ANSWERS.read_text(encoding="utf-8").splitlines():
        k, sep, v = line.partition(":")
        if sep and not line.lstrip().startswith("#"):
            raw[k.strip()] = v.strip()
    for n in nics():
        if raw.get("lan", "").lower() in (n["name"], n["mac"].lower()):
            lan = n["name"]
            break
    else:
        raise RuntimeError(f"{ANSWERS}: no interface {raw.get('lan')!r}")
    return {
        "lan": lan,
        "address": ipaddress.IPv4Interface(raw["address"]),
        "gateway": ipaddress.IPv4Address(raw["gateway"]) if raw.get("gateway") else None,
        "dns": parse_dns(raw.get("dns") or PUBLIC_DNS),
        "password": raw["password"],
        "tz": raw.get("timezone") or "Etc/UTC",
    }


def run_steps(a: dict, interactive: bool) -> bool:
    i = 0
    while i < len(STEPS):
        title, fn = STEPS[i]
        say(f"==> {title}")
        try:
            fn(a)
            i += 1
        except Exception as exc:  # noqa: BLE001 - shown to the operator, then retried
            logfile(f"FAILED: {exc}")
            say(f"!!  {exc}")
            say(f"    (log: {LOG})")
            if not interactive or ask("Retry this step? (y: retry, n: leave to a shell login)", "y").lower() not in ("y", "yes"):
                say("The setup runs again at the next boot, or: sudo /usr/lib/portitor/firstboot.py --force")
                return False
    DONE.parent.mkdir(parents=True, exist_ok=True)
    DONE.touch()
    ANSWERS.unlink(missing_ok=True)
    return True


def main() -> int:
    if os.geteuid() != 0:
        say("run as root")
        return 1
    if DONE.exists() and "--force" not in sys.argv:
        say(f"The first-boot setup has run already ({DONE}); --force runs it again.")
        return 0
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
    lan = ask_lan()
    address = ask_address()
    gateway = ask_gateway(address)
    dns = ask_dns(gateway)
    say()
    say(f"One password for the GUI user {GUI_USER} and the console login {CONSOLE_USER}.")
    password = ask_password()
    tz = ask_timezone()
    say()
    say(f"  LAN interface   {lan}")
    say(f"  LAN address     {address}")
    say(f"  Default gateway {gateway or '(none)'}")
    say(f"  DNS servers     {' '.join(dns)}")
    say(f"  Time zone       {tz}")
    if ask("Apply? (y/n)", "y").lower() not in ("y", "yes"):
        return main()

    a = {"lan": lan, "address": address, "gateway": gateway, "dns": dns, "password": password, "tz": tz}
    if not run_steps(a, interactive=True):
        return 1
    say()
    say("Done. Open the GUI from the LAN:")
    say()
    say(f"    {a['url']}    user {GUI_USER}")
    say()
    say("The browser warns about the self-signed certificate; its SHA-256 fingerprint is")
    say(f"    {a['cert_fp']}")
    say()
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
