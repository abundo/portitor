#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 The Portitor contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Install or update Portitor: on a firewall portitor-agent and
portitor-config (its configuration, GUI and API), and portitor-web, the
portal to the firewalls' GUIs, on this host or another (over SSH).

Binaries go to /usr/bin, systemd units to /etc/systemd/system, example
configs to /etc/portitor (only when missing; config.yaml gets a generated
jwt_secret). If an installed unit differs from this release, the installer
shows a diff and asks before overwriting (--yes overwrites).

An update restarts portitor-agent (its per-instance units follow), stops
portitor-config, runs `portitor-config migrate` and restarts it, and
restarts portitor-web. The firewall is updated first: the agent rejects
document fields it does not know, so it must never be older than
portitor-config. On a first install, when a config was just created, the
database is created but nothing is started; the installer prints the
remaining steps.

A host that ran portitor-web with its database (before portitor-web became
the portal) gets that database as portitor-config's, and portitor-web
there serves it as its firewall: the same GUI, at the same address. A
portitor-web on a host of its own gives its database to the firewall it
deployed to (found in the database, updated with it, over SSH), and serves
that one.

What gets installed:
  (default)       whatever is installed on this host. When that includes
                  portitor-web, also the firewalls it serves (the hosts of
                  the URLs under firewalls: in web.yaml, and their HA
                  peers).
  --web [HOST]    portitor-web on HOST (default this host), over SSH like
                  --agent (plus the firewalls, as above)
  --agent [HOST]  portitor-agent and portitor-config on HOST (default this
                  host), over SSH as
                  --ssh-user (default portitor, which needs passwordless
                  sudo; the installer prints how to set that up), or root.
                  Repeat it, or separate hosts by commas, for several. Agents
                  are updated one at a time, an HA pair's secondary first,
                  each waiting until the one before hears its HA peer again,
                  so one host of the pair keeps forwarding.
  --no-agent      never the agent

Where from:
  ./install.py                GitHub release. TUI on a TTY, or --list /
                              --install TAG. The selected release's own
                              install.py does the install (so its steps match
                              its binaries) unless this copy has a higher
                              INSTALLER_VERSION. A standalone copy offers to
                              update itself from the latest release first.
                              Downloads are SHA-256 verified.
  ./install.py --source       This source tree: `make release` (CGO off), then
                              install build/. Cross-builds the agent when the
                              firewall has another architecture.
  ./install.py --local PATH   A release archive (.tar.gz) or an extracted release
                              directory, without GitHub (the installer ISO uses
                              this).

The agent host also gets a copy of this installer as
/usr/lib/portitor/install.py: the agent runs it for updates started from the
GUI (`--list --json`, `--install TAG --yes`).
"""

from __future__ import annotations

import argparse
import curses
import difflib
import hashlib
import json
import os
import re
import secrets
import shlex
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Sequence

# Bump when the installer itself changes, so a release's copy can tell
# whether it is newer than the one running.
INSTALLER_VERSION = 10
INSTALLER_FILENAME = "install.py"
# Where the agent host keeps a copy, for updates from the GUI.
INSTALLER_DEST = "/usr/lib/portitor/install.py"

REPO_DIR = Path(__file__).resolve().parent
REPO_DEFAULT = "abundo/portitor"
USER_AGENT = "portitor-install.py"
ARCHIVE_OS = "linux"

BIN_DIR = "/usr/bin"
WEB_BIN = f"{BIN_DIR}/portitor-web"
AGENT_BIN = f"{BIN_DIR}/portitor-agent"
# The portitor command (show lldp neighbours, ...) is the agent run by this name.
CLI_LINK = f"{BIN_DIR}/portitor"
ETC_DIR = "/etc/portitor"
WEB_CONFIG = f"{ETC_DIR}/web.yaml"
AGENT_CONFIG = f"{ETC_DIR}/agent.yaml"
SYSTEMD_DIR = "/etc/systemd/system"
WEB_USER = "portitor"
# portitor-web's database before it became the portal: moved to
# portitor-config on the same host.
OLD_WEB_DB_DIR = "/var/lib/portitor-web"
# portitor-config: portitor-web run as portitor-config on the firewall,
# its configuration, GUI and API. It touches the database only as
# WEB_USER, so the files SQLite creates stay writable for the service.
CONFIG_LINK = f"{BIN_DIR}/portitor-config"
CONFIG_FILE = f"{ETC_DIR}/config.yaml"
CONFIG_DB_DIR = "/var/lib/portitor-config"
CONFIG_UNIT = "portitor-config.service"
CONFIG_CERT = f"{ETC_DIR}/config.crt"
CONFIG_KEY = f"{ETC_DIR}/config.key"
# The agent's last applied document (its default state_dir).
AGENT_APPLIED = "/var/lib/portitor/applied.json"
# portitor-config's address on its own host, which portitor-web there uses.
CONFIG_LOCAL_URL = "https://127.0.0.1:8444"
SSH_USER_DEFAULT = "portitor"
WEB_UNIT = "portitor-web.service"
AGENT_UNIT = "portitor-agent.service"
# The per-instance units are started by the agent, never enabled.
AGENT_UNITS = (
    AGENT_UNIT,
    "portitor-named@.service",
    "portitor-kea4@.service",
    "portitor-kea6@.service",
    "portitor-radvd@.service",
    "portitor-frr@.service",
    "portitor-chrony@.service",
    "portitor-snmpd@.service",
    "portitor-conntrackd@.service",
)
# The Debian packages the agent runs (iso/preseed.cfg has the same). An
# update installs the ones missing (a release can need a new one, as 0.4.0
# needs FRR), with the distribution units listed masked first, as
# iso/target.sh masks them: the agent unmasks the ones it uses, so a new
# package's daemon never starts with the distribution's default config.
AGENT_PACKAGES = {
    "nftables": (),
    "iproute2": (),
    "wireguard-tools": (),
    "bind9": ("named.service",),
    "bind9-utils": (),
    "bind9-dnsutils": (),
    "kea-dhcp4-server": ("kea-dhcp4-server.service",),
    "kea-dhcp6-server": ("kea-dhcp6-server.service",),
    "radvd": ("radvd.service",),
    "frr": ("frr.service",),
    "frr-pythontools": (),
    "tcpdump": (),
    "tshark": (),
    "mtr-tiny": (),
    # Tools → iperf3; its own server unit is never used.
    "iperf3": ("iperf3.service",),
    # NTP. Not masked: it replaces systemd-timesyncd and keeps the host's
    # clock with Debian's config until the default virtual firewall has NTP.
    "chrony": (),
    # SNMP; the default virtual firewall's runs under snmpd.service.
    "snmpd": ("snmpd.service",),
    # Connection sync of HA pairs; the default virtual firewall's runs under
    # conntrackd.service.
    "conntrackd": ("conntrackd.service",),
    # NAT64; DKMS builds the kernel module with the kernel headers
    # (agent_packages adds them for the architecture).
    "jool-dkms": (),
    "jool-tools": (),
}
# BIND 9 stable from ISC's Debian repository
# (https://kb.isc.org/docs/isc-packages-for-bind-9), newer than the
# distribution's; iso/preseed.cfg adds it too. Signed by the deb.sury.org key
# in deploy/apt/isc-bind.asc (15058500A0235D97F5D10063B188E2B695BD4743).
ISC_BIND_REPO = "https://bind.debian.net/bind"
ISC_BIND_SUITES = ("bullseye", "bookworm", "trixie", "jammy", "noble", "resolute")
ISC_BIND_KEYRING = "/usr/share/keyrings/isc-bind.asc"
ISC_BIND_LIST = "/etc/apt/sources.list.d/isc-bind.list"
# Debian/Ubuntu confine named and Kea with AppArmor; our rules
# (deploy/apparmor/<profile>) go in each profile's local include, between
# markers so the admin's own lines are kept.
APPARMOR_DIR = "/etc/apparmor.d"
APPARMOR_BEGIN = "# BEGIN portitor (managed by install.py)"
APPARMOR_END = "# END portitor"
LOCAL_NAMES = {"localhost", "127.0.0.1", "::1", ""}
# Where install.py once put Wiregasm, which portitor-web now embeds; removed on
# install.
OLD_WIREGASM_DIR = "/usr/share/portitor/wiregasm"

SELF_UPDATED_ENV = "PORTITOR_INSTALL_SELF_UPDATED"
# Set in the selected release's installer, run by this one: the release is
# already chosen, confirmed, downloaded and extracted (to RELEASE_WORK_ENV).
PINNED_ENV = "PORTITOR_INSTALL_PINNED"
RELEASE_WORK_ENV = "PORTITOR_RELEASE_WORK"


class InstallError(Exception):
    """Fatal, already-formatted error for the CLI."""


# stderr with --list --json, so stdout holds only the JSON.
log_stream = sys.stdout


def log(msg: str = "") -> None:
    print(msg, file=log_stream, flush=True)


def warn(msg: str) -> None:
    log(f"!!  {msg}")


# ---------------------------------------------------------------------------
# versions
# ---------------------------------------------------------------------------


def strip_v(tag: str) -> str:
    tag = tag.strip()
    return tag[1:] if tag[:1] in ("v", "V") else tag


def same_stamp(a: str, b: str) -> bool:
    """Git tags are v1.2.3; GoReleaser stamps the binaries with 1.2.3."""
    return bool(strip_v(a)) and strip_v(a) == strip_v(b)


def parse_version(tag: str) -> tuple[int, int, int] | None:
    m = re.match(r"v?(\d+)\.(\d+)\.(\d+)", tag.strip())
    return (int(m[1]), int(m[2]), int(m[3])) if m else None


def is_dev_build(stamp: str) -> bool:
    """A `git describe` stamp past a tag (v1.2.3-4-gabc), dirty, or no tag."""
    s = strip_v(stamp)
    return parse_version(s) is None or "-g" in s or s.endswith("-dirty")


def version_newer(tag: str, installed: str) -> bool:
    rel, cur = parse_version(tag), parse_version(installed)
    if rel is None:
        return False
    return cur is None or rel > cur


def versions_equal(tag: str, installed: str) -> bool:
    return same_stamp(tag, installed) and not is_dev_build(installed)


def same_base(tag: str, installed: str) -> bool:
    rel = parse_version(tag)
    return rel is not None and rel == parse_version(installed)


def version_of_output(text: str) -> str | None:
    """`portitor-web --version` prints "portitor-web version <stamp>"."""
    m = re.search(r"\bversion\s+(\S+)", text)
    return m[1] if m else None


def format_date(iso: str) -> str:
    try:
        return datetime.fromisoformat(iso.replace("Z", "+00:00")).date().isoformat()
    except ValueError:
        return iso[:10] or "-"


def goarch(machine: str) -> str:
    machine = machine.strip()
    return {"x86_64": "amd64", "aarch64": "arm64"}.get(machine, machine)


def local_arch() -> str:
    return goarch(os.uname().machine)


# ---------------------------------------------------------------------------
# hosts: every system change goes through Host, locally (sudo) or over SSH
# ---------------------------------------------------------------------------


def need_sudo() -> bool:
    return os.geteuid() != 0


def ensure_sudo(plan: "Plan", dry_run: bool) -> None:
    """Asks for the sudo password up front, when a host is this one."""
    if dry_run or not need_sudo() or not any(h.local for h in plan.hosts()):
        return
    log("==> Requesting sudo access")
    if subprocess.run(["sudo", "-v"], check=False).returncode != 0:
        raise InstallError("root (or sudo) is required")


def is_local_address(host: str) -> bool:
    """True for localhost and for any address assigned to this machine."""
    if host in LOCAL_NAMES:
        return True
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_DGRAM)
    except OSError:
        return False
    for family, _, _, _, addr in infos:
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as s:
                s.bind((addr[0], 0))
                return True
        except OSError:
            continue
    return False


class Host:
    """Runs shell snippets as root on this host or over SSH.

    Mutating calls only print in dry-run; reads always run.
    """

    def __init__(self, name: str, ssh_user: str, dry_run: bool):
        self.name = name
        self.local = is_local_address(name)
        self.ssh_user = ssh_user
        self.dry_run = dry_run

    def __str__(self) -> str:
        return "this host" if self.local else self.name

    def argv(self, script: str, root: bool) -> list[str]:
        if self.local:
            return (["sudo"] if root and need_sudo() else []) + ["sh", "-c", script]
        remote = "sh -c " + shlex.quote(script)
        if self.ssh_user != "root":
            remote = "sudo -n " + remote
        return [
            "ssh",
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=10",
            f"{self.ssh_user}@{self.name}",
            remote,
        ]

    def run(
        self,
        script: str,
        *,
        desc: str | None = None,
        check: bool = True,
        mutate: bool = True,
        capture: bool = False,
        stdin_file: Path | None = None,
        root: bool | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """root defaults to mutate: a read that needs root passes root=True."""
        where = "" if self.local else f"{self.name}: "
        if mutate:
            if self.dry_run:
                log(f"    [dry-run] {where}{desc or script}")
                return subprocess.CompletedProcess(script, 0, "", "")
            log(f"    $ {where}{desc or script}")
        with (stdin_file.open("rb") if stdin_file else open(os.devnull, "rb")) as stdin:
            proc = subprocess.run(
                self.argv(script, root=mutate if root is None else root),
                stdin=stdin,
                capture_output=capture,
                text=True,
                check=False,
                timeout=None if mutate else 30,
            )
        if check and proc.returncode != 0:
            detail = (proc.stderr or "").strip() if capture else ""
            raise InstallError(
                f"{where}command failed ({proc.returncode}): {desc or script}"
                + (f"\n{detail}" if detail else "")
            )
        return proc

    def read(self, path: str, root: bool = False) -> str | None:
        proc = self.run(f"cat {shlex.quote(path)}", check=False, mutate=False, capture=True, root=root)
        return proc.stdout if proc.returncode == 0 else None

    def run_to_file(self, script: str, dest: Path, desc: str) -> None:
        """Runs script as root, its output (binary) written to the local file
        dest. Only prints in dry-run."""
        where = "" if self.local else f"{self.name}: "
        if self.dry_run:
            log(f"    [dry-run] {where}{desc}")
            return
        log(f"    $ {where}{desc}")
        with dest.open("wb") as out:
            proc = subprocess.run(self.argv(script, root=True), stdin=subprocess.DEVNULL, stdout=out,
                                  stderr=subprocess.PIPE, check=False)
        if proc.returncode != 0:
            detail = proc.stderr.decode(errors="replace").strip()
            raise InstallError(f"{where}command failed ({proc.returncode}): {desc}" + (f"\n{detail}" if detail else ""))

    def exists(self, path: str) -> bool:
        return self.run(f"test -e {shlex.quote(path)}", check=False, mutate=False).returncode == 0

    def arch(self) -> str:
        return goarch(self.run("uname -m", mutate=False, capture=True).stdout)

    def version(self, binary: str) -> str | None:
        proc = self.run(f"{shlex.quote(binary)} --version", check=False, mutate=False, capture=True)
        return version_of_output(proc.stdout + proc.stderr) if proc.returncode == 0 else None

    def put(self, src: Path, dest: str, mode: str, group: str = "root", name: str = "") -> None:
        """Install src as dest atomically (a running binary is replaced, not rewritten)."""
        d = shlex.quote(dest)
        script = (
            't=$(mktemp) && cat >"$t" && '
            f'install -D -m {mode} -o root -g {group} "$t" {d}.new && mv -f {d}.new {d}; '
            'rc=$?; rm -f "$t"; exit $rc'
        )
        self.run(script, desc=f"install -m {mode} {name or src.name} {dest}", stdin_file=src)

    def put_text(self, text: str, dest: str, mode: str, group: str = "root") -> None:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as tmp:
            tmp.write(text)
        try:
            self.put(Path(tmp.name), dest, mode, group, name=Path(dest).name)
        finally:
            os.unlink(tmp.name)

    def systemctl(self, *args: str, check: bool = True) -> None:
        self.run("systemctl " + " ".join(shlex.quote(a) for a in args), check=check)


# ---------------------------------------------------------------------------
# systemd units
# ---------------------------------------------------------------------------


def normalize_unit(text: str) -> str:
    lines = [line.rstrip() for line in text.replace("\r\n", "\n").split("\n")]
    return "\n".join(lines).strip() + "\n"


def confirm_overwrite(unit: str, host: Host, diff: str, assume_yes: bool) -> bool:
    log(f"==> {unit} on {host} differs from this release:")
    for line in diff.splitlines() or ["(whitespace only)"]:
        log(f"    {line}")
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        warn(f"leaving {unit} on {host} unchanged (no TTY; pass --yes to overwrite)")
        return False
    try:
        return input(f"Overwrite {unit} on {host}? [y/N] ").strip().lower() in {"y", "yes"}
    except EOFError:
        return False


def install_unit(host: Host, src: Path, assume_yes: bool) -> str:
    """Install or update one unit. Returns installed, updated, unchanged or kept."""
    if not src.is_file():
        raise InstallError(f"missing systemd unit {src}")
    unit = src.name
    dest = f"{SYSTEMD_DIR}/{unit}"
    packaged = src.read_text(encoding="utf-8")
    installed = host.read(dest)
    if installed is None:
        host.put(src, dest, "0644")
        return "installed"
    if normalize_unit(installed) == normalize_unit(packaged):
        return "unchanged"
    diff = "\n".join(
        difflib.unified_diff(
            installed.splitlines(),
            packaged.splitlines(),
            fromfile=f"installed {unit}",
            tofile=f"packaged {unit}",
            lineterm="",
        )
    )
    if not confirm_overwrite(unit, host, diff, assume_yes or host.dry_run):
        log(f"    keeping the installed {unit}")
        return "kept"
    host.put(src, dest, "0644")
    return "updated"


# ---------------------------------------------------------------------------
# install steps
# ---------------------------------------------------------------------------


@dataclass
class Plan:
    web: Host | None
    agents: list[Host]
    # Why the agents go in this order (HA pairs), for describe.
    agent_order_note: str = ""
    # Agents in an HA pair before the install, by name: after a restart
    # the agent's socket may not answer yet, so it is not asked again.
    ha_agents: set[str] = field(default_factory=set)
    # The agent (by name) that portitor-web's database on web, from before
    # it became the portal, moves to, and the address web reached it at.
    db_to: str = ""
    db_address: str = ""

    def hosts(self) -> list[Host]:
        return ([self.web] if self.web else []) + self.agents

    def describe(self) -> list[str]:
        out = [f"portitor-agent and portitor-config on {a}" for a in self.agents]
        if self.agent_order_note:
            out.append(self.agent_order_note)
        if self.web:
            out.append(f"portitor-web on {self.web}")
        if self.db_to:
            out.append(f"portitor-web's database moves from {self.web} to portitor-config on {self.db_to}")
        return out


def verify_version(host: Host, binary: str, expected: str) -> None:
    if host.dry_run:
        return
    got = host.version(binary)
    if not got or not same_stamp(got, expected):
        raise InstallError(f"{host}: {binary} reports {got or 'no version'}, expected {expected}")
    log(f"    {host}: {Path(binary).name} {got}")


def install_agent(host: Host, binary: Path, deploy: Path, version: str, assume_yes: bool) -> None:
    log(f"==> Installing portitor-agent {version} on {host}")
    new_config = not host.exists(AGENT_CONFIG)
    if new_config:
        host.put(deploy / "agent.yaml", AGENT_CONFIG, "0600")
    host.put(binary, AGENT_BIN, "0755")
    host.run(f"ln -sfn portitor-agent {shlex.quote(CLI_LINK)}", desc=f"ln -s portitor-agent {CLI_LINK}")
    host.put(Path(__file__).resolve(), INSTALLER_DEST, "0755", name=INSTALLER_FILENAME)
    actions = {u: install_unit(host, deploy / "systemd" / u, assume_yes) for u in AGENT_UNITS}
    move_kea_leases(host)
    move_bind_dirs(host)
    host.systemctl("daemon-reload")
    install_apparmor(host, deploy)
    if new_config:
        on = "" if host.local else f" (on {host.name})"
        log(f"==> portitor-agent is installed but not started. Next steps{on}:")
        log("    install nftables, iproute2, wireguard-tools, bind9, kea-dhcp4-server,")
        log("      kea-dhcp6-server, radvd, frr, frr-pythontools, tcpdump, tshark, mtr-tiny and iperf3 (or your distribution's equivalents)")
        log("    portitor-agent init --host <management address>   # token + fingerprint for the GUI")
        log(f"    $EDITOR {AGENT_CONFIG}                     # listen, allow_from, bind_user")
        log("    the default virtual firewall (the host) runs the distribution's named, Kea, radvd and FRR:")
        log("      the agent writes their standard config files (keeping the originals as *.portitor-orig)")
        log("      and enables the ones it uses; disable the others if you don't run them yourself")
        log("    remove the firewall's interfaces from netplan, NetworkManager or systemd-networkd")
        log("      (a second DHCP client on the WAN keeps the agent from getting a lease)")
        log(f"    systemctl enable --now {AGENT_UNIT}")
        return
    install_packages(host, deploy)
    if actions[AGENT_UNIT] == "installed":
        host.systemctl("enable", AGENT_UNIT)
    host.systemctl("restart", AGENT_UNIT)
    if not host.dry_run and not agent_answers(host):
        warn(f"{AGENT_UNIT} does not answer on {host}; see journalctl -u {AGENT_UNIT}")
    verify_version(host, AGENT_BIN, version)


def agent_answers(host: Host, timeout: float = 20) -> bool:
    """Whether the restarted agent answers on its socket within timeout.
    A unit that is active for a moment may still be failing at start and
    restarting (no token, a listen address it can't bind): that one never
    answers."""
    deadline = time.monotonic() + timeout
    while True:
        if host.run(f"{CLI_LINK} show ha >/dev/null 2>&1", check=False, mutate=False, root=True).returncode == 0:
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(1)


def add_bind_repo(host: Host, deploy: Path) -> bool:
    """Add ISC's BIND repository if the release has one; True if it was added."""
    proc = host.run('. /etc/os-release && echo "$VERSION_CODENAME"', check=False, mutate=False, capture=True)
    suite = proc.stdout.strip()
    if proc.returncode or suite not in ISC_BIND_SUITES:
        return False
    # The ISO's installer adds it to sources.list (apt-setup/local0).
    if not host.run(
        "grep -rEqs 'bind\\.debian\\.net/bind/?( |$)' /etc/apt/sources.list /etc/apt/sources.list.d",
        check=False, mutate=False,
    ).returncode:
        return False
    log(f"==> Adding ISC's BIND repository on {host}")
    host.put(deploy / "apt" / "isc-bind.asc", ISC_BIND_KEYRING, "0644")
    host.put_text(f"deb [signed-by={ISC_BIND_KEYRING}] {ISC_BIND_REPO} {suite} main\n", ISC_BIND_LIST, "0644")
    return True


def agent_packages(host: Host) -> dict[str, tuple[str, ...]]:
    """AGENT_PACKAGES with the kernel headers for jool-dkms: the metapackage
    that follows the kernel, Debian's for the architecture or Ubuntu's."""
    for headers in (f"linux-headers-{host.arch()}", "linux-headers-generic"):
        if host.run(f"apt-cache show {headers} >/dev/null 2>&1", check=False, mutate=False).returncode == 0:
            return {**AGENT_PACKAGES, headers: ()}
    return dict(AGENT_PACKAGES)


def install_packages(host: Host, deploy: Path) -> None:
    """Install the agent's packages that are missing, on a host with apt.

    BIND comes from ISC's repository; when that is added, the installed
    bind9 packages are upgraded from it.
    """
    if host.run("command -v apt-get dpkg-query", check=False, mutate=False).returncode:
        return
    packages = agent_packages(host)
    names = " ".join(packages)
    proc = host.run(
        f"dpkg-query -W -f '${{Package}} ${{db:Status-Status}}\\n' {names} 2>/dev/null",
        check=False, mutate=False, capture=True,
    )
    have = {f[0] for f in (l.split() for l in proc.stdout.splitlines()) if len(f) == 2 and f[1] == "installed"}
    missing = [p for p in packages if p not in have]
    upgrade = [p for p in packages if p.startswith("bind9") and p in have] if add_bind_repo(host, deploy) else []
    if not missing and not upgrade:
        return
    if missing:
        log(f"==> Installing packages on {host}: {' '.join(missing)}")
    if upgrade:
        log(f"==> Upgrading BIND from ISC's repository on {host}: {' '.join(upgrade)}")
    units = [u for p in missing for u in packages[p]]
    if units:
        host.systemctl("mask", *units)
    host.run("apt-get update -q", check=False)
    pkgs = " ".join(missing + upgrade)
    host.run(
        "DEBIAN_FRONTEND=noninteractive apt-get install -y -q " + pkgs,
        desc=f"apt-get install {pkgs}",
    )


def move_kea_leases(host: Host) -> None:
    """Move lease files from before the per-instance Kea directories.

    The units mount /var/lib/kea/<instance> over /var/lib/kea, so a unit
    can't do this itself. A running Kea keeps writing to the renamed file;
    the restart that follows opens it at its new path. The DHCPv6 server
    id (DUID) goes along, so clients see the same server.
    """
    host.run(
        "cd /var/lib/kea 2>/dev/null || exit 0\n"
        "for f in kea-leases[46]-*.csv*; do\n"
        '  [ -e "$f" ] || continue\n'
        '  n=${f#kea-leases?-}; n=${n%%.csv*}\n'
        '  mkdir -p -m 0750 "$n" && mv -n "$f" "$n/"\n'
        "done\n"
        "if [ -e kea-dhcp6-serverid ]; then\n"
        '  for d in */; do [ -d "$d" ] && cp -pn kea-dhcp6-serverid "$d"; done\n'
        "fi\n"
        "true",
        desc="move Kea lease files to /var/lib/kea/<instance>",
    )


def move_bind_dirs(host: Host) -> None:
    """Move BIND's files from before the per-instance BIND directories.

    named's working directory (DNSSEC keys, managed keys) moves from
    /var/lib/portitor/instances/<instance>/bind to /var/cache/bind/<instance>,
    and the zone files (with their signed versions and journals) from .../zones
    to /var/lib/bind/<instance>. The next apply writes named.conf with the new
    paths and dnsmgr2 rewrites its include.
    """
    host.run(
        "cd /var/lib/portitor/instances 2>/dev/null || exit 0\n"
        "for d in */; do\n"
        '  n=${d%/}\n'
        '  for m in "bind /var/cache/bind" "zones /var/lib/bind"; do\n'
        '    set -- $m\n'
        '    [ -d "$n/$1" ] || continue\n'
        '    install -d -m 0750 "$2/$n"\n'
        '    chown --reference="$n/$1" "$2/$n"\n'
        '    find "$n/$1" -mindepth 1 -maxdepth 1 -exec mv -n -t "$2/$n" {} +\n'
        '    rmdir "$n/$1" 2>/dev/null\n'
        "  done\n"
        "done\n"
        "true",
        desc="move BIND files to /var/cache/bind/<instance> and /var/lib/bind/<instance>",
    )


def replace_marked_block(text: str, begin: str, end: str, block: str) -> str:
    """text with the lines from begin to end replaced by block (appended if absent)."""
    lines = text.splitlines()
    try:
        i = lines.index(begin)
        j = lines.index(end, i)
    except ValueError:
        i = j = -1
    if i >= 0:
        del lines[i : j + 1]
    else:
        while lines and not lines[-1].strip():
            lines.pop()
        if lines:
            lines.append("")
        i = len(lines)
    lines[i:i] = [begin, *block.strip("\n").splitlines(), end]
    return "\n".join(lines) + "\n"


def install_apparmor(host: Host, deploy: Path) -> None:
    """Let named and Kea (portitor-named@, -kea4@, -kea6@) use Portitor's paths.

    Without this, they fail on Debian/Ubuntu with "permission denied" on
    their config, PID or lock files. Written whenever /etc/apparmor.d exists,
    so a package installed later loads the rules with its profile.
    """
    src_dir = deploy / "apparmor"
    if not src_dir.is_dir() or not host.exists(APPARMOR_DIR):
        return
    # Not in a chroot (the installer ISO) or without AppArmor in the kernel.
    active = host.exists("/sys/kernel/security/apparmor/profiles")
    for src in sorted(src_dir.iterdir()):
        local = f"{APPARMOR_DIR}/local/{src.name}"
        current = host.read(local) or ""
        text = replace_marked_block(current, APPARMOR_BEGIN, APPARMOR_END, src.read_text(encoding="utf-8"))
        if text == current:
            continue
        host.put_text(text, local, "0644")
        profile = f"{APPARMOR_DIR}/{src.name}"
        if active and host.exists(profile):
            host.run(f"apparmor_parser -r {shlex.quote(profile)}", check=False)


def install_web(
    host: Host, binary: Path, deploy: Path, version: str, assume_yes: bool,
    moved_to: Host | None = None, moved_address: str = "",
) -> None:
    """portitor-web, the portal: no database, the firewalls in web.yaml.
    moved_to is the firewall its old database went to (at moved_address)."""
    log(f"==> Installing portitor-web {version} on {host}")
    ensure_user(host)
    new_config = not host.exists(WEB_CONFIG)
    if new_config:
        host.put(deploy / "web.yaml", WEB_CONFIG, "0640", group=WEB_USER)
    host.put(binary, WEB_BIN, "0755")
    if host.exists(OLD_WIREGASM_DIR):
        host.run(f"rm -rf {OLD_WIREGASM_DIR}")
    action = install_unit(host, deploy / "systemd" / WEB_UNIT, assume_yes)
    host.systemctl("daemon-reload")
    if moved_to:
        link_remote_config(host, moved_to, moved_address)
    # portitor-config on this host is its firewall, unless it lists others.
    elif host.exists(CONFIG_FILE):
        link_local_config(host)
    if new_config:
        log("==> portitor-web is installed but not started. Next steps:")
        log(f"    list the firewalls under firewalls: in {WEB_CONFIG}: on each,")
        log("      url https://<firewall>:8444 and fingerprint (portitor-config fingerprint there),")
        log(f"      and this host's address under trusted_proxies: in its {CONFIG_FILE}")
        log(f"    systemctl enable --now {WEB_UNIT}")
        return
    if action == "installed":
        host.systemctl("enable", WEB_UNIT)
    host.systemctl("restart", WEB_UNIT)
    verify_version(host, WEB_BIN, version)


def ensure_user(host: Host) -> None:
    host.run(
        f"getent group {WEB_USER} >/dev/null || groupadd --system {WEB_USER}; "
        f"getent passwd {WEB_USER} >/dev/null || useradd --system -g {WEB_USER} "
        f"--no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin {WEB_USER}",
        desc=f"create system user {WEB_USER} unless it exists",
    )


def portal_name(host: Host) -> str:
    """The name portitor-web gives the firewall on its own host."""
    proc = host.run("hostname -s", check=False, mutate=False, capture=True)
    # A firewall's name: letters, digits, '-', '_' and '.', starting with a
    # letter or digit, at most 63 characters.
    name = re.sub(r"[^a-zA-Z0-9_.-]+", "-", (proc.stdout or "").strip()).lstrip("-_.")
    return name[:63] or "firewall"


def link_local_config(host: Host) -> None:
    """portitor-web serves portitor-config on the same host, when its
    web.yaml lists no firewall: it adds that one, and portitor-config trusts
    portitor-web's X-Forwarded-For (127.0.0.1)."""
    web = host.read(WEB_CONFIG) or ""
    if re.search(r"^\s*-\s*name:", web, re.M) or host.dry_run:
        return
    proc = host.run(f"runuser -u {WEB_USER} -- {CONFIG_LINK} -f {CONFIG_FILE} fingerprint",
                    check=False, mutate=False, capture=True, root=True)
    fp = (proc.stdout or "").strip()
    if proc.returncode != 0 or not re.fullmatch(r"[0-9a-f]{64}", fp):
        warn(f"portitor-config fingerprint failed on {host}; list it under firewalls: in {WEB_CONFIG} yourself")
        return
    name = portal_name(host)
    add_portal_firewall(host, web, name, CONFIG_LOCAL_URL, fp, "This host's portitor-config")
    log(f"    portitor-web serves this host's portitor-config as firewall {name}")
    if add_trusted_proxy(host, "127.0.0.1", "portitor-web on this host"):
        host.systemctl("try-restart", CONFIG_UNIT, check=False)


def link_remote_config(web: Host, fw: Host, address: str) -> None:
    """portitor-web on web serves portitor-config on fw, which its old
    database moved to: fw is listed in web.yaml at address, and fw's
    portitor-config trusts web's X-Forwarded-For."""
    if web.dry_run:
        log(f"    [dry-run] list {fw} under firewalls: in {WEB_CONFIG}, and {web} in its trusted_proxies")
        return
    proc = fw.run(f"runuser -u {WEB_USER} -- {CONFIG_LINK} -f {CONFIG_FILE} fingerprint",
                  check=False, mutate=False, capture=True, root=True)
    fp = (proc.stdout or "").strip()
    if proc.returncode != 0 or not re.fullmatch(r"[0-9a-f]{64}", fp):
        warn(f"portitor-config fingerprint failed on {fw}; list it under firewalls: in {WEB_CONFIG} on {web} yourself")
        return
    port = config_port(fw)
    url_host = f"[{address}]" if ":" in address else address
    name = portal_name(fw)
    add_portal_firewall(web, web.read(WEB_CONFIG, root=True) or "", name, f"https://{url_host}:{port}", fp,
                        "The firewall portitor-web's database moved to")
    log(f"    portitor-web serves {fw}'s portitor-config as firewall {name}")
    # The address web reaches fw from, which fw sees in the connections.
    script = ("import socket, sys; a = socket.getaddrinfo(sys.argv[1], int(sys.argv[2]), type=socket.SOCK_DGRAM)[0]; "
              "s = socket.socket(a[0], socket.SOCK_DGRAM); s.connect(a[4]); print(s.getsockname()[0])")
    proc = web.run(f"python3 -I -c {shlex.quote(script)} {shlex.quote(address)} {port}",
                   check=False, mutate=False, capture=True)
    src = (proc.stdout or "").strip().split("%")[0]
    if proc.returncode != 0 or not src:
        warn(f"cannot tell {web}'s address towards {address}; add it under trusted_proxies: in {CONFIG_FILE} on {fw}")
        return
    if add_trusted_proxy(fw, src, "portitor-web"):
        fw.systemctl("try-restart", CONFIG_UNIT, check=False)


def add_portal_firewall(host: Host, web: str, name: str, url: str, fp: str, note: str) -> None:
    """Writes web.yaml (text web) on host with this one firewall listed."""
    block = f"firewalls:\n  - name: {name}\n    url: {url}\n    fingerprint: {fp}\n"
    if re.search(r"^firewalls:.*$", web, re.M):
        web = re.sub(r"^firewalls:.*\n?", block, web, count=1, flags=re.M)
    else:
        web = web.rstrip("\n") + f"\n\n# {note} (install.py).\n" + block
    host.put_text(web, WEB_CONFIG, "0640", group=WEB_USER)


def add_trusted_proxy(host: Host, addr: str, note: str) -> bool:
    """Adds addr to trusted_proxies in host's config.yaml; True when it
    changed. A list in block style is left to the admin."""
    cfg = host.read(CONFIG_FILE, root=True) or ""
    m = re.search(r"^trusted_proxies:[ \t]*(\[([^\]\n]*)\])?[ \t]*(#.*)?$", cfg, re.M)
    if m and m.group(1) is None:
        warn(f"add {addr} under trusted_proxies: in {CONFIG_FILE} on {host} yourself")
        return False
    items = [i.strip().strip("\"'") for i in m.group(2).split(",")] if m else []
    items = [i for i in items if i]
    if addr in items:
        return False
    line = f"trusted_proxies: [{', '.join(items + [addr])}]"
    if m:
        cfg = cfg[:m.start()] + line + cfg[m.end():]
    else:
        cfg = cfg.rstrip("\n") + f"\n# {note} (install.py).\n{line}\n"
    host.put_text(cfg, CONFIG_FILE, "0640", group=WEB_USER)
    log(f"    portitor-config on {host} trusts {addr} (trusted_proxies)")
    return True


def config_port(host: Host) -> int:
    """portitor-config's port on host (bind in config.yaml)."""
    cfg = host.read(CONFIG_FILE, root=True) or ""
    m = re.search(r"^bind:\s*[\"']?[^\s\"'#]*:(\d+)", cfg, re.M)
    return int(m.group(1)) if m else 8444


def local_agent_url(host: Host) -> str:
    """Where portitor-config reaches the agent on its host: the agent's
    listen address in agent.yaml, loopback when it listens on all."""
    text = host.read(AGENT_CONFIG, root=True) or ""
    m = re.search(r"^listen:\s*[\"']?([^\s\"'#]+)", text, re.M)
    addr, _, port = (m.group(1) if m else ":8443").rpartition(":")
    addr = addr.strip("[]")
    if addr in ("", "0.0.0.0", "::"):
        addr = "127.0.0.1"
    return f"https://{f'[{addr}]' if ':' in addr else addr}:{port or 8443}"


def set_agent_url(host: Host) -> None:
    """Sets agent_url in config.yaml when the agent does not listen on
    loopback, unless the admin has set it."""
    cfg = host.read(CONFIG_FILE, root=True)
    if cfg is None or re.search(r"^agent_url:", cfg, re.M) or host.dry_run:
        return
    url = local_agent_url(host)
    if url == "https://127.0.0.1:8443":
        return
    line = f"agent_url: {url}"
    if re.search(r"^#\s*agent_url:.*$", cfg, re.M):
        cfg = re.sub(r"^#\s*agent_url:.*$", line, cfg, count=1, flags=re.M)
    else:
        cfg = cfg.rstrip("\n") + f"\n# This host's agent (install.py, from its listen).\n{line}\n"
    host.put_text(cfg, CONFIG_FILE, "0640", group=WEB_USER)
    log(f"    portitor-config reaches its agent at {url}")


def install(
    plan: Plan, roots: dict[str, Path], archs: dict[str, str], deploy: Path, version: str, assume_yes: bool,
    config: bool = False,
) -> None:
    """roots: arch -> directory with the binaries. deploy: units and example
    configs. config is the old --config: portitor-config goes with every
    agent now."""
    # The firewalls first: the agent rejects fields it does not know, so it
    # must never be older than portitor-config, which deploys to it.
    # One at a time, an HA pair's secondary first (make_plan's order): each
    # agent restarts fenced unless it hears its peer, so the next waits
    # until the restarted one does, and one host of the pair keeps forwarding.
    moved_to = next((a for a in plan.agents if a.name == plan.db_to), None)
    for agent in plan.agents:
        root = roots[archs[agent_key(agent)]]
        install_agent(agent, root / "portitor-agent", deploy, version, assume_yes)
        install_config(agent, root / "portitor-web", deploy, version, assume_yes,
                       db_from=plan.web if agent is moved_to else None)
        if agent.name in plan.ha_agents:
            wait_for_ha_peer(agent)
    if plan.web:
        install_web(plan.web, roots[archs["web"]] / "portitor-web", deploy, version, assume_yes,
                    moved_to=moved_to, moved_address=plan.db_address)
    log("==> Done")


def install_config(
    host: Host, binary: Path, deploy: Path, version: str, assume_yes: bool, db_from: Host | None = None,
) -> None:
    """portitor-config on the firewall: the portitor-web binary run as
    portitor-config, with its own config, certificate, database and unit,
    set to deploy to the local agent. A host that ran portitor-web with its
    database gets that database, and so does the firewall a portitor-web
    elsewhere (db_from) deployed to. A new one is not started: it needs an
    admin."""
    log(f"==> Installing portitor-config {version} on {host}")
    ensure_user(host)
    new_config = not host.exists(CONFIG_FILE)
    if new_config:
        example = (deploy / "config.yaml").read_text(encoding="utf-8")
        secret = secrets.token_urlsafe(32)
        host.put_text(example.replace("jwt_secret: CHANGE-ME", f'jwt_secret: "{secret}"'), CONFIG_FILE, "0640", group=WEB_USER)
    if not host.exists(CONFIG_CERT):
        host.run(
            f"openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 7300 "
            f"-subj /CN=portitor-config -keyout {CONFIG_KEY} -out {CONFIG_CERT} 2>/dev/null && "
            f"chgrp {WEB_USER} {CONFIG_KEY} {CONFIG_CERT} && chmod 0640 {CONFIG_KEY} && chmod 0644 {CONFIG_CERT}",
            desc="make portitor-config's certificate",
        )
    host.run(f"install -d -o {WEB_USER} -g {WEB_USER} -m 0700 {CONFIG_DB_DIR}")
    host.run(f"systemctl stop {CONFIG_UNIT} 2>/dev/null || true", desc=f"systemctl stop {CONFIG_UNIT}")
    moved = move_remote_database(db_from, host) if db_from else move_web_database(host)
    set_agent_url(host)
    host.put(binary, WEB_BIN, "0755")
    host.run(f"ln -sfn portitor-web {shlex.quote(CONFIG_LINK)}", desc=f"ln -s portitor-web {CONFIG_LINK}")
    action = install_unit(host, deploy / "systemd" / CONFIG_UNIT, assume_yes)
    host.systemctl("daemon-reload")
    run_config = f"runuser -u {WEB_USER} -- {CONFIG_LINK} -f {CONFIG_FILE}"
    host.run(f"{run_config} migrate", desc="portitor-config migrate")
    if new_config and not moved and host.exists(f"{ETC_DIR}/agent.token"):
        # Its own agent, the token read as root and handed over.
        host.run(
            f"fp=$(openssl x509 -in {ETC_DIR}/agent.crt -noout -fingerprint -sha256 | cut -d= -f2 | tr -d :); "
            f"cat {ETC_DIR}/agent.token | {run_config} set-agent --url https://127.0.0.1:8443 "
            f"--token-file - --fingerprint \"$fp\"",
            desc="portitor-config set-agent (the local agent)",
        )
    if new_config and not moved and configured_elsewhere(host):
        log("==> portitor-config is installed but not started: this firewall's configuration is")
        log("    in a portitor-web elsewhere. Update that one with install.py on its host, which moves")
        log("    its database here. Don't create an admin here: a commit from this empty database")
        log("    would replace the firewall's configuration.")
        return
    if new_config and not moved:
        log("==> portitor-config is installed but not started. Next steps:")
        if not host.exists(f"{ETC_DIR}/agent.token"):
            log(f"    portitor-agent init, then: cat {ETC_DIR}/agent.token | sudo -u {WEB_USER} portitor-config set-agent --token-file - --fingerprint <its fingerprint>")
        log(f"    sudo -u {WEB_USER} portitor-config createadmin admin")
        log(f"    systemctl enable --now {CONFIG_UNIT}")
        log(f"    for portitor-web: URL https://<this host>:8444, fingerprint: sudo -u {WEB_USER} portitor-config fingerprint")
        return
    if action == "installed" or moved:
        host.systemctl("enable", CONFIG_UNIT)
    host.systemctl("restart", CONFIG_UNIT)
    verify_version(host, WEB_BIN, version)


def move_web_database(host: Host) -> bool:
    """Moves portitor-web's database, from before it became the portal, to
    portitor-config on the same host, when portitor-config has none yet and
    portitor-web was enabled (a disabled one's database is a leftover)."""
    old, new = f"{OLD_WEB_DB_DIR}/portitor.db", f"{CONFIG_DB_DIR}/portitor.db"
    if not host.exists(old) or host.exists(new):
        return False
    enabled = host.run(f"systemctl is-enabled --quiet {WEB_UNIT}", check=False, mutate=False, capture=True)
    if enabled.returncode != 0:
        return False
    log(f"==> Moving portitor-web's database to portitor-config on {host}")
    host.run(f"systemctl stop {WEB_UNIT} 2>/dev/null || true", desc=f"systemctl stop {WEB_UNIT}")
    host.run(
        f"for f in portitor.db portitor.db-wal portitor.db-shm; do "
        f"[ -e {OLD_WEB_DB_DIR}/$f ] && install -o {WEB_USER} -g {WEB_USER} -m 0600 {OLD_WEB_DB_DIR}/$f {CONFIG_DB_DIR}/$f; done; "
        f"[ -d {OLD_WEB_DB_DIR}/deployed ] && cp -a {OLD_WEB_DB_DIR}/deployed {CONFIG_DB_DIR}/ && chown -R {WEB_USER}:{WEB_USER} {CONFIG_DB_DIR}/deployed; "
        f"mv {old} {old}.moved-to-portitor-config",
        desc=f"copy {OLD_WEB_DB_DIR} to {CONFIG_DB_DIR}",
    )
    return True


# Reads the firewalls of portitor-web's database from before it became the
# portal, of any schema since there was one: their agent URLs, and whether
# each is an HA secondary. Run as python3 -I -c with the database's path.
OLD_DB_FIREWALLS = """
import json, sqlite3, sys
db = sqlite3.connect("file:" + sys.argv[1] + "?mode=ro", uri=True)
rows = []
for q in ("SELECT agent_url, ha_primary_id IS NOT NULL FROM firewalls ORDER BY id",
          "SELECT agent_url, 0 FROM firewalls ORDER BY id",
          "SELECT agent_url, 0 FROM settings WHERE id = 1"):
    try:
        rows = db.execute(q).fetchall()
        break
    except sqlite3.OperationalError:
        pass
print(json.dumps([{"url": u or "", "secondary": bool(s)} for u, s in rows]))
"""
# Copies a database with SQLite's backup API (its WAL included): source,
# then destination.
DB_BACKUP = ('import sqlite3, sys; d = sqlite3.connect(sys.argv[2]); '
             'sqlite3.connect("file:" + sys.argv[1] + "?mode=ro", uri=True).backup(d); d.close()')
DB_USERS = 'import sqlite3, sys; print(sqlite3.connect("file:" + sys.argv[1] + "?mode=ro", uri=True).execute("SELECT count(*) FROM users").fetchone()[0])'


def old_web_database(web: Host) -> tuple[list[str], str] | None:
    """portitor-web's database on web from before it became the portal,
    when it must move to a firewall elsewhere: the hosts of its agent URLs,
    and the address of the one it moves to (the HA primary), "" when it has
    no agent URL. None when there is nothing to move: no database, moved
    already, web.yaml lists firewalls, portitor-web was disabled (a
    leftover), or the agent runs on web itself (move_web_database's case;
    the ISO's portitor-web alone has the agent installed but disabled)."""
    old = f"{OLD_WEB_DB_DIR}/portitor.db"
    if not web.exists(old):
        return None
    if agent_enabled(web):
        return None
    if re.search(r"^\s*-\s*name:", web.read(WEB_CONFIG, root=True) or "", re.M):
        return None
    if web.run(f"systemctl is-enabled --quiet {WEB_UNIT}", check=False, mutate=False).returncode != 0:
        return None
    proc = web.run(f"python3 -I -c {shlex.quote(OLD_DB_FIREWALLS)} {shlex.quote(old)}",
                   check=False, mutate=False, capture=True, root=True)
    try:
        rows = json.loads(proc.stdout) if proc.returncode == 0 else None
    except ValueError:
        rows = None
    if rows is None:
        raise InstallError(f"{web}: cannot read the firewalls in {old}: {(proc.stderr or proc.stdout).strip()}")
    hosts: list[str] = []
    primaries: list[str] = []
    for r in rows:
        host = urllib.parse.urlsplit(r["url"]).hostname or ""
        if not host:
            continue
        if host in LOCAL_NAMES:
            return None
        if host not in hosts:
            hosts.append(host)
        if not r["secondary"]:
            primaries.append(host)
    if len(primaries) > 1:
        raise InstallError(
            f"portitor-web's database on {web} deploys to several firewalls ({', '.join(primaries)}); "
            "each firewall now has its own portitor-config. Export each virtual firewall as a bundle "
            "and import it on its firewall, then list the firewalls in web.yaml."
        )
    return hosts, primaries[0] if primaries else ""


def agent_enabled(host: Host) -> bool:
    """True when host runs the agent: the ISO's portitor-web alone has it
    installed but disabled."""
    return host.run(f"systemctl is-enabled --quiet {AGENT_UNIT}", check=False, mutate=False).returncode == 0


def configured_elsewhere(host: Host) -> bool:
    """True when the agent on host has applied a configuration that its
    portitor-config has no database for: a portitor-web elsewhere has it."""
    return host.exists(AGENT_APPLIED)


def move_remote_database(web: Host, fw: Host) -> bool:
    """Moves portitor-web's database on web, from before it became the
    portal, to portitor-config on fw, the firewall it deployed to. One
    there already is set aside only when it has no users (a new one, from
    an update of the firewall alone)."""
    old, new = f"{OLD_WEB_DB_DIR}/portitor.db", f"{CONFIG_DB_DIR}/portitor.db"
    log(f"==> Moving portitor-web's database on {web} to portitor-config on {fw}")
    if fw.exists(new) and not fw.dry_run:
        proc = fw.run(f"python3 -I -c {shlex.quote(DB_USERS)} {new}", check=False, mutate=False, capture=True, root=True)
        if proc.returncode != 0 or proc.stdout.strip() != "0":
            raise InstallError(
                f"{fw} has a portitor-config database with users ({new}); move it aside there "
                f"to move {web}'s {old} in its place, or copy that one over yourself"
            )
        fw.run(f"for f in portitor.db portitor.db-wal portitor.db-shm; do "
               f"[ ! -e {CONFIG_DB_DIR}/$f ] || mv {CONFIG_DB_DIR}/$f {CONFIG_DB_DIR}/$f.unused; done",
               desc=f"set the new, empty {new} aside (.unused)")
    web.run(f"systemctl stop {WEB_UNIT} 2>/dev/null || true", desc=f"systemctl stop {WEB_UNIT} on {web}")
    pack = (
        f"t=$(mktemp -d) && python3 -I -c {shlex.quote(DB_BACKUP)} {old} $t/portitor.db && "
        f"{{ [ ! -d {OLD_WEB_DB_DIR}/deployed ] || cp -a {OLD_WEB_DB_DIR}/deployed $t/; }} && "
        f"cd $t && tar -czf - *; rc=$?; cd /; rm -rf \"$t\"; exit $rc"
    )
    with tempfile.TemporaryDirectory(prefix="portitor-db-") as tmp:
        archive = Path(tmp) / "database.tar.gz"
        web.run_to_file(pack, archive, f"copy {old} and {OLD_WEB_DB_DIR}/deployed")
        fw.run(
            f"tar -C {CONFIG_DB_DIR} --no-same-owner -xzf - && chown -R {WEB_USER}:{WEB_USER} {CONFIG_DB_DIR} && "
            f"chmod 0600 {new}",
            desc=f"unpack it in {CONFIG_DB_DIR}", stdin_file=archive,
        )
    web.run(f"mv {old} {old}.moved-to-portitor-config", desc=f"mv {old} {old}.moved-to-portitor-config")
    return True


# ---------------------------------------------------------------------------
# what to install where
# ---------------------------------------------------------------------------


def agent_hosts_from_settings(web: Host) -> list[str]:
    """The firewalls portitor-web on web serves: the hosts of the URLs under
    firewalls: in web.yaml, and the HA peers their portitor-configs deploy
    to (`portitor-config agent-url --all` there). One on localhost is the web
    host itself."""
    text = web.read(WEB_CONFIG) if web.exists(WEB_CONFIG) else None
    if not text:
        return []
    hosts: list[str] = []

    def add(url: str, via: Host | None) -> None:
        host = urllib.parse.urlsplit(url).hostname
        if not host:
            raise InstallError(f"cannot find a host in the URL {url!r}; pass --agent HOST")
        if host in LOCAL_NAMES:
            host = via.name if via and not via.local else ("localhost" if web.local else web.name)
        if host not in hosts:
            hosts.append(host)

    for url in re.findall(r"^\s*url:\s*[\"']?([^\s\"']+)", text, re.M):
        add(url, web)
    # Their HA peers, which their portitor-configs know; one that can't be
    # asked (no SSH yet, an older release) is left to --agent.
    for name in list(hosts):
        fw = web if name in (web.name, "localhost") else Host(name, web.ssh_user, web.dry_run)
        proc = fw.run(f"test -x {CONFIG_LINK} && runuser -u {WEB_USER} -- {CONFIG_LINK} -f {CONFIG_FILE} agent-url --all",
                      check=False, mutate=False, capture=True, root=True)
        for url in (proc.stdout or "").split() if proc.returncode == 0 else []:
            add(url, fw)
    return hosts


def ha_status(host: Host) -> dict:
    """The agent's HA status (`portitor show ha --json`); empty when it
    is not in a pair, not running, or too old to tell."""
    if host.dry_run or not host.exists(CLI_LINK):
        return {}
    proc = host.run(f"{CLI_LINK} --json show ha", check=False, mutate=False, capture=True, root=True)
    if proc.returncode != 0:
        return {}
    try:
        st = json.loads(proc.stdout)
    except ValueError:
        return {}
    return st if isinstance(st, dict) and st.get("node") else {}


def order_agents(agents: list[Host]) -> tuple[list[Host], str, set[str]]:
    """HA secondaries first, then the rest, each in the given order; a
    note on it when there is a pair; and the agents in a pair."""
    nodes = {a.name: ha_status(a).get("node", "") for a in agents}
    ordered = sorted(agents, key=lambda a: nodes[a.name] != "secondary")
    paired = {n for n, node in nodes.items() if node}
    if not paired:
        return ordered, "", paired
    return ordered, "one agent at a time, HA secondaries first", paired


def wait_for_ha_peer(host: Host, timeout: float = 60) -> None:
    """Waits until a restarted agent in an HA pair hears its peer, so the
    pair's other host can go next. Warns when it doesn't in time."""
    if host.dry_run:
        return
    log(f"==> Waiting for portitor-agent on {host} to hear its HA peer")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        st = ha_status(host)
        if st.get("peer_alive"):
            return
        time.sleep(2)
    warn(f"portitor-agent on {host} does not hear its HA peer after {timeout:.0f} s; "
         f"see `portitor show ha` there")


def make_plan(args: argparse.Namespace) -> Plan:
    web_host: str | None = args.web
    agent_hosts: list[str] = [h for arg in args.agent or [] for h in arg.split(",") if h]
    if args.agent and not agent_hosts:
        raise InstallError("--agent: no host")
    if web_host is None and not agent_hosts:
        # The binary is portitor-config's too: portitor-web is installed
        # where its web.yaml is.
        if Path(WEB_CONFIG).exists():
            web_host = "localhost"
        elif Path(AGENT_BIN).exists():
            agent_hosts = ["localhost"]
        if web_host is None and not agent_hosts:
            raise InstallError(
                "Portitor is not installed on this host. For a first install pass "
                "--web [HOST] and/or --agent [HOST]."
            )
    web = Host(web_host, args.ssh_user, args.dry_run) if web_host is not None else None
    if web:
        check_ssh(web)
    # A portitor-web from before the portal, on its own host: its database
    # moves to the firewall it deployed to, so the firewall goes too.
    old_db = old_web_database(web) if web else None
    db_to = db_address = ""
    if old_db:
        if args.no_agent:
            raise InstallError(
                f"portitor-web's database on {web} moves to its firewall's portitor-config: "
                "update them together (without --no-agent)"
            )
        old_hosts, db_address = old_db
        if not agent_hosts:
            agent_hosts = list(old_hosts)
            log(f"==> portitor-web's firewalls (in its database): {', '.join(agent_hosts)}")
        if not db_address and len(agent_hosts) == 1:
            db_address = agent_hosts[0]
        if not db_address:
            raise InstallError(
                f"portitor-web's database on {web} has no agent URL; pass the firewall it belongs to as --agent HOST"
            )
        db_to = db_address
        if db_to not in agent_hosts:
            agent_hosts.append(db_to)
    if web and not agent_hosts and not args.no_agent:
        agent_hosts = agent_hosts_from_settings(web)
        if agent_hosts:
            log(f"==> portitor-web's firewalls: {', '.join(agent_hosts)}")
        else:
            log(f"==> No firewalls in {WEB_CONFIG}; not updating a firewall")
    if args.no_agent:
        agent_hosts = []
    elif web and not agent_hosts and agent_enabled(web):
        agent_hosts = [web.name]
    if not web and not agent_hosts:
        raise InstallError("nothing to install")
    agents: list[Host] = []
    for name in agent_hosts:
        agent = Host(name, args.ssh_user, args.dry_run)
        # The same machine by two names (localhost and its address) once.
        if any(a.name == agent.name or (a.local and agent.local) for a in agents):
            continue
        check_ssh(agent)
        agents.append(agent)
    agents, note, paired = order_agents(agents)
    return Plan(web=web, agents=agents, agent_order_note=note, ha_agents=paired, db_to=db_to, db_address=db_address)


def ssh_setup_help(host: str, user: str) -> str:
    """How to let the installer in: key-based SSH, and for a user other
    than root, passwordless sudo (`sudo -n`, no TTY)."""
    if user == "root":
        return "\n".join([
            f"Allow key-based SSH as root on {host} (PermitRootLogin prohibit-password),",
            "or use the default --ssh-user portitor with sudo.",
            f"Check from here:  ssh root@{host} true",
        ])
    q = shlex.quote(user)
    return "\n".join([
        f"Set up the {user} user on {host}, as root there:",
        f"  useradd --create-home --shell /bin/sh {q}   # a real shell: SSH runs commands through it",
        f"  install -d -m 700 -o {q} -g {q} ~{user}/.ssh",
        f"  # add this host's public key (e.g. ~/.ssh/id_ed25519.pub) to ~{user}/.ssh/authorized_keys,",
        f"  # owned by {user}, mode 600",
        f"  echo '{user} ALL=(root) NOPASSWD: ALL' >/etc/sudoers.d/{user}",
        f"  chmod 0440 /etc/sudoers.d/{user}",
        f"  visudo -cf /etc/sudoers.d/{user}",
        "  # sudo must not require a TTY: remove any 'Defaults requiretty' line",
        f"Check from here (must print nothing and exit 0):  ssh {user}@{host} sudo -n true",
        "Or pass --ssh-user root, or another user with passwordless sudo.",
    ])


def check_ssh(host: Host) -> None:
    """Fail early, with how to set it up, when host is remote and unreachable as root."""
    if host.local:
        return
    proc = host.run("true", check=False, mutate=False, capture=True, root=True)
    if proc.returncode != 0:
        raise InstallError(
            f"cannot reach {host.name} over SSH as {host.ssh_user} "
            f"with {'root' if host.ssh_user == 'root' else 'passwordless sudo'}: "
            f"{(proc.stderr or '').strip()}\n\n"
            + ssh_setup_help(host.name, host.ssh_user)
        )


def agent_key(host: Host, first: bool = False) -> str:
    """An agent's key in plan_archs and installed_versions: "agent" for
    the first (the keys `--list --json` has always had), else "agent HOST"."""
    return "agent" if first else f"agent {host.name}"


def plan_archs(plan: Plan) -> dict[str, str]:
    """Architecture of each host: "web" and agent_key(agent)."""
    archs = {"web": plan.web.arch() if plan.web and not plan.web.local else local_arch()}
    for a in plan.agents:
        archs[agent_key(a)] = local_arch() if a.local else a.arch()
    return archs


def needed_archs(plan: Plan, archs: dict[str, str]) -> dict[str, set[str]]:
    """Architecture -> the binaries the hosts of it need."""
    out: dict[str, set[str]] = {}
    if plan.web:
        out.setdefault(archs["web"], set()).add("portitor-web")
    for a in plan.agents:
        out.setdefault(archs[agent_key(a)], set()).add("portitor-agent")
    return out


def installed_versions(plan: Plan) -> dict[str, str]:
    out = {}
    if plan.web:
        out["web"] = plan.web.version(WEB_BIN) or "not installed"
    for i, a in enumerate(plan.agents):
        out[agent_key(a, first=i == 0)] = a.version(AGENT_BIN) or "not installed"
    return out


def primary_version(installed: dict[str, str]) -> str:
    return installed.get("web") or installed.get("agent") or "not installed"


def summary_lines(plan: Plan, installed: dict[str, str]) -> list[str]:
    lines = []
    for i, a in enumerate(plan.agents):
        lines.append(f"agent  {installed.get(agent_key(a, first=i == 0), '?'):<22} {a}")
    if plan.web:
        lines.append(f"web    {installed.get('web', '?'):<22} {plan.web}")
    return lines


# ---------------------------------------------------------------------------
# GitHub releases
# ---------------------------------------------------------------------------


class StripAuthOnRedirect(urllib.request.HTTPRedirectHandler):
    """Asset downloads redirect to a signed URL that rejects Authorization."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and urllib.parse.urlsplit(req.full_url).netloc != urllib.parse.urlsplit(new.full_url).netloc:
            for key in list(new.headers):
                if key.lower() == "authorization":
                    del new.headers[key]
        return new


def github_token() -> str | None:
    for key in ("GITHUB_TOKEN", "GH_TOKEN"):
        if os.environ.get(key, "").strip():
            return os.environ[key].strip()
    if shutil.which("gh"):
        try:
            out = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, check=False, timeout=10)
            return out.stdout.strip() or None
        except (OSError, subprocess.TimeoutExpired):
            pass
    return None


@dataclass
class Asset:
    name: str
    size: int
    url: str
    api_url: str


@dataclass
class Release:
    tag: str
    published_at: str
    prerelease: bool
    assets: list[Asset] = field(default_factory=list)
    # Why the release must not be installed: a "Broken: <reason>" line in its
    # GitHub release notes, which can be added after publishing.
    broken: str = ""

    def archive(self, arch: str) -> Asset | None:
        suffix = f"_{ARCHIVE_OS}_{arch}.tar.gz"
        return next((a for a in self.assets if a.name.endswith(suffix)), None)

    def checksums(self) -> Asset | None:
        return next((a for a in self.assets if a.name.endswith("_checksums.txt")), None)


def broken_reason(body: str) -> str:
    m = re.search(r"^\W*broken\W*:\s*(.*)$", body, re.IGNORECASE | re.MULTILINE)
    return (m[1].strip(" *_") or "marked broken") if m else ""


class GithubClient:
    def __init__(self, repo: str, token: str | None):
        self.repo = repo
        self.token = token
        self.opener = urllib.request.build_opener(StripAuthOnRedirect)

    def _headers(self, accept: str) -> dict[str, str]:
        h = {"Accept": accept, "User-Agent": USER_AGENT, "X-GitHub-Api-Version": "2022-11-28"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    def _open(self, url: str, accept: str):
        req = urllib.request.Request(url, headers=self._headers(accept))
        try:
            return self.opener.open(req, timeout=60)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                raise InstallError(
                    f"{url}: not found. If {self.repo} is private, set GITHUB_TOKEN or run `gh auth login`."
                ) from exc
            raise InstallError(f"GitHub request failed ({exc.code}): {url}") from exc
        except urllib.error.URLError as exc:
            raise InstallError(f"GitHub request failed: {exc.reason}") from exc

    def list_releases(self, limit: int) -> list[Release]:
        releases: list[Release] = []
        url: str | None = f"https://api.github.com/repos/{self.repo}/releases?per_page=100"
        while url and len(releases) < limit:
            with self._open(url, "application/vnd.github+json") as resp:
                page = json.loads(resp.read())
                link = resp.headers.get("Link", "")
            for item in page:
                if item.get("draft"):
                    continue
                releases.append(
                    Release(
                        tag=item.get("tag_name") or "",
                        published_at=item.get("published_at") or "",
                        prerelease=bool(item.get("prerelease")),
                        broken=broken_reason(item.get("body") or ""),
                        assets=[
                            Asset(a["name"], int(a.get("size") or 0), a.get("browser_download_url") or "", a.get("url") or "")
                            for a in item.get("assets") or []
                        ],
                    )
                )
            m = re.search(r'<([^>]+)>;\s*rel="next"', link)
            url = m[1] if m else None
        return releases[:limit]

    def download(self, asset: Asset, dest: Path) -> None:
        # A private repo's assets are only reachable through the API URL.
        url = asset.api_url if self.token and asset.api_url else asset.url
        tmp = dest.with_name(dest.name + ".partial")
        with self._open(url, "application/octet-stream") as resp, tmp.open("wb") as out:
            shutil.copyfileobj(resp, out, 1 << 20)
        tmp.replace(dest)


def cache_dir() -> Path:
    base = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    d = base / "portitor-releases"
    d.mkdir(parents=True, exist_ok=True)
    return d


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def download_checksums(client: GithubClient, rel: Release) -> dict[str, str]:
    asset = rel.checksums()
    if asset is None:
        raise InstallError(f"release {rel.tag} has no checksums file")
    path = cache_dir() / asset.name
    client.download(asset, path)
    out = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        parts = line.split()
        if len(parts) == 2:
            out[parts[1].lstrip("*")] = parts[0].lower()
    return out


def download_archive(client: GithubClient, rel: Release, arch: str, checksums: dict[str, str]) -> Path:
    asset = rel.archive(arch)
    if asset is None:
        raise InstallError(f"release {rel.tag} has no {ARCHIVE_OS}/{arch} archive")
    expected = checksums.get(asset.name)
    if not expected:
        raise InstallError(f"release {rel.tag}'s checksums have no entry for {asset.name}")
    path = cache_dir() / asset.name
    if path.is_file() and sha256_file(path) == expected:
        log(f"==> Using cached {asset.name}")
    else:
        log(f"==> Downloading {asset.name} ({asset.size / 1048576:.1f} MiB)")
        client.download(asset, path)
    got = sha256_file(path)
    if got != expected:
        path.unlink(missing_ok=True)
        raise InstallError(f"checksum mismatch for {asset.name}: expected {expected}, got {got}")
    log(f"    sha256 ok ({got[:12]}…)")
    return path


def is_release_root(path: Path) -> bool:
    files = ("portitor-web", "portitor-agent", "deploy/agent.yaml", "deploy/web.yaml")
    return all((path / f).is_file() for f in files)


def extract_archive(archive: Path, dest: Path) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    base = str(dest.resolve())
    with tarfile.open(archive, "r:gz") as tar:
        for m in tar.getmembers():
            target = os.path.normpath(os.path.join(base, m.name))
            if not (m.isfile() or m.isdir()) or os.path.commonpath([target, base]) != base:
                raise InstallError(f"refusing archive member {m.name!r} in {archive.name}")
        if hasattr(tarfile, "data_filter"):
            tar.extractall(dest, filter="data")
        else:
            tar.extractall(dest)
    if is_release_root(dest):
        return dest
    subs = [p for p in dest.iterdir() if p.is_dir() and is_release_root(p)]
    if len(subs) == 1:
        return subs[0]
    raise InstallError(f"{archive.name} does not contain portitor-web, portitor-agent and deploy/{{agent,web}}.yaml")


def prepare_roots(client: GithubClient, rel: Release, archs: set[str], work: Path) -> dict[str, Path]:
    checksums = download_checksums(client, rel)
    return {arch: extract_archive(download_archive(client, rel, arch, checksums), work / arch) for arch in sorted(archs)}


def roots_from_work(work: Path) -> dict[str, Path]:
    roots = {}
    for p in work.iterdir():
        if is_release_root(p):
            roots[p.name] = p
        else:
            subs = [s for s in p.iterdir() if s.is_dir() and is_release_root(s)]
            if len(subs) == 1:
                roots[p.name] = subs[0]
    return roots


def latest_stable(releases: list[Release], include_pre: bool = False) -> Release | None:
    return next((r for r in releases if (include_pre or not r.prerelease) and not r.broken), None)


def pick_release(releases: list[Release], spec: str, include_pre: bool) -> Release:
    if spec in {"latest", "stable"}:
        rel = latest_stable(releases, include_pre)
        if rel is None:
            raise InstallError("no stable release found (pass --pre to include prereleases)")
        return rel
    for rel in releases:
        if strip_v(spec) == strip_v(rel.tag):
            return rel
    raise InstallError(f"release {spec} not found (try --list)")


# ---------------------------------------------------------------------------
# release selection
# ---------------------------------------------------------------------------


def release_status(rel: Release, installed: str, latest_tag: str | None) -> str:
    bits = []
    if rel.tag == latest_tag:
        bits.append("latest")
    if versions_equal(rel.tag, installed):
        bits.append("current")
    elif same_base(rel.tag, installed) and is_dev_build(installed):
        bits.append("local")
    elif version_newer(rel.tag, installed):
        bits.append("newer")
    elif parse_version(installed):
        bits.append("older")
    if rel.prerelease:
        bits.append("pre")
    if rel.broken:
        bits.append(f"BROKEN: {rel.broken}")
    return "  ".join(bits)


def missing_archs(rel: Release, archs: set[str]) -> list[str]:
    return [a for a in sorted(archs) if rel.archive(a) is None]


def print_release_table(releases: list[Release], plan: Plan, installed: dict[str, str], archs: set[str]) -> None:
    latest = latest_stable(releases)
    cur = primary_version(installed)
    for line in summary_lines(plan, installed):
        log(f"Installed : {line}")
    log(f"Latest    : {latest.tag if latest else '(none)'}")
    log()
    header = f"{'#':>3} {'TAG':<16} {'DATE':<12} NOTES"
    log(header)
    log("-" * len(header))
    for i, rel in enumerate(releases):
        notes = release_status(rel, cur, latest.tag if latest else None)
        missing = missing_archs(rel, archs)
        if missing:
            notes += f"  (no {'/'.join(missing)} archive)"
        log(f"{i + 1:>3} {rel.tag:<16} {format_date(rel.published_at):<12} {notes}")


def print_release_json(releases: list[Release], installed: dict[str, str], archs: set[str], include_pre: bool) -> None:
    """--list --json, for the agent (the GUI's update page)."""
    latest = latest_stable(releases)
    cur = primary_version(installed)
    out = {
        "installed": installed,
        "latest": latest.tag if latest else "",
        "releases": [
            {
                "tag": rel.tag,
                "date": format_date(rel.published_at),
                "prerelease": rel.prerelease,
                "notes": release_status(rel, cur, latest.tag if latest else None),
                "newer": version_newer(rel.tag, cur) and (include_pre or not rel.prerelease) and not rel.broken,
                "broken": rel.broken,
                "installable": not missing_archs(rel, archs),
            }
            for rel in releases
        ],
    }
    print(json.dumps(out, indent=2))


def numbered_select(releases: list[Release], plan: Plan, installed: dict[str, str], archs: set[str]) -> Release | None:
    print_release_table(releases, plan, installed, archs)
    log()
    log("Enter a number (1 is newest), a tag, or q to quit.")
    while True:
        try:
            raw = input("Select: ").strip()
        except EOFError:
            return None
        if raw.lower() in {"", "q", "quit"}:
            return None
        if raw.isdigit() and 1 <= int(raw) <= len(releases):
            return releases[int(raw) - 1]
        try:
            return pick_release(releases, raw, include_pre=True)
        except InstallError:
            log("  unknown selection")


def confirm_text(rel: Release, plan: Plan, installed: dict[str, str], assume_yes: bool) -> bool:
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        raise InstallError("refusing to install without a TTY; pass --yes")
    log()
    log(f"Install {rel.tag} ({format_date(rel.published_at)})")
    if rel.broken:
        log(f"  WARNING: {rel.tag} is marked broken: {rel.broken}")
    for line in summary_lines(plan, installed):
        log(f"  {line}")
    try:
        return input("Proceed? [y/N] ").strip().lower() in {"y", "yes"}
    except EOFError:
        return False


def curses_select(releases: list[Release], plan: Plan, installed: dict[str, str], archs: set[str]) -> Release | None:
    cur = primary_version(installed)
    latest = latest_stable(releases)
    latest_tag = latest.tag if latest else None

    def pair(n: int) -> int:
        return curses.color_pair(n) if curses.has_colors() else 0

    def add(win, y: int, x: int, text: str, attr: int = 0) -> None:
        h, w = win.getmaxyx()
        if 0 <= y < h and x < w:
            try:
                win.addnstr(y, x, text, max(0, w - x - 1), attr)
            except curses.error:
                pass

    def confirm(stdscr, rel: Release) -> bool:
        h, w = stdscr.getmaxyx()
        lines = [f"Install {rel.tag}  ({format_date(rel.published_at)})", ""]
        lines += summary_lines(plan, installed)
        lines += ["", "Enter confirm    Esc cancel"]
        box_w = min(w - 2, max(len(s) for s in lines) + 4)
        box_h = len(lines) + 2
        try:
            win = stdscr.derwin(box_h, box_w, max(0, (h - box_h) // 2), max(0, (w - box_w) // 2))
        except curses.error:
            return True
        win.clear()
        win.box()
        for i, line in enumerate(lines):
            add(win, i + 1, 2, line[: box_w - 3], curses.A_BOLD if i == 0 else 0)
        win.refresh()
        while True:
            key = win.getch()
            if key in (curses.KEY_ENTER, 10, 13, ord("y"), ord("Y")):
                return True
            if key in (27, ord("n"), ord("N"), ord("q"), ord("Q")):
                return False

    def draw(stdscr) -> Release | None:
        curses.curs_set(0)
        curses.use_default_colors()
        if curses.has_colors():
            for n, fg, bg in ((1, curses.COLOR_CYAN, -1), (2, curses.COLOR_GREEN, -1), (3, curses.COLOR_YELLOW, -1),
                              (4, curses.COLOR_MAGENTA, -1), (5, curses.COLOR_BLACK, curses.COLOR_CYAN),
                              (6, curses.COLOR_RED, -1)):
                curses.init_pair(n, fg, bg)
        newer = sum(1 for r in releases if version_newer(r.tag, cur) and not r.prerelease and not r.broken)
        idx = next((i for i, r in enumerate(releases)
                    if version_newer(r.tag, cur) and not r.prerelease and not r.broken), None)
        if idx is None:
            idx = next((i for i, r in enumerate(releases) if versions_equal(r.tag, cur)), 0)
        offset = 0
        while True:
            stdscr.erase()
            h, w = stdscr.getmaxyx()
            add(stdscr, 0, 0, " Portitor installer ".center(max(w - 1, 0)), curses.A_BOLD | pair(1))
            y = 1
            for line in summary_lines(plan, installed):
                add(stdscr, y, 0, "  " + line)
                y += 1
            if newer:
                add(stdscr, y, 0, f"  {newer} newer release(s). Select one to install.", pair(3))
            elif latest_tag and versions_equal(latest_tag, cur):
                add(stdscr, y, 0, "  Up to date. Select a release to reinstall or roll back.", pair(2))
            else:
                add(stdscr, y, 0, "  Select a release to install.", pair(2))
            add(stdscr, y + 2, 0, f"  {'TAG':<16} {'DATE':<12} NOTES", curses.A_UNDERLINE)
            top = y + 3
            rows = max(1, h - top - 2)
            offset = min(max(offset, idx - rows + 1), idx)
            for row, rel in enumerate(releases[offset : offset + rows]):
                i = offset + row
                missing = missing_archs(rel, archs)
                line = f"  {rel.tag:<16} {format_date(rel.published_at):<12} {release_status(rel, cur, latest_tag)}"
                attr = 0
                if missing:
                    line += f"  (no {'/'.join(missing)} archive)"
                    attr = pair(6)
                elif versions_equal(rel.tag, cur):
                    attr = pair(2)
                elif version_newer(rel.tag, cur):
                    attr = pair(3)
                if rel.prerelease and not missing:
                    attr = pair(4)
                if rel.broken:
                    attr = pair(6)
                if i == idx:
                    attr = (pair(5) or curses.A_REVERSE) | curses.A_BOLD
                    line = ">" + line[1:]
                add(stdscr, top + row, 0, line, attr)
            add(stdscr, h - 1, 0, "  ↑/↓ move   Enter install   q quit", curses.A_DIM)
            stdscr.refresh()
            key = stdscr.getch()
            if key in (ord("q"), ord("Q"), 27):
                return None
            if key in (curses.KEY_UP, ord("k")):
                idx = max(0, idx - 1)
            elif key in (curses.KEY_DOWN, ord("j")):
                idx = min(len(releases) - 1, idx + 1)
            elif key == curses.KEY_PPAGE:
                idx = max(0, idx - rows)
            elif key == curses.KEY_NPAGE:
                idx = min(len(releases) - 1, idx + rows)
            elif key in (curses.KEY_HOME, ord("g")):
                idx = 0
            elif key in (curses.KEY_END, ord("G")):
                idx = len(releases) - 1
            elif key in (curses.KEY_ENTER, 10, 13):
                if missing_archs(releases[idx], archs):
                    curses.flash()
                elif confirm(stdscr, releases[idx]):
                    return releases[idx]

    return curses.wrapper(draw)


# ---------------------------------------------------------------------------
# the installer's own version: self-update and the release's copy
# ---------------------------------------------------------------------------


def installer_version_of(data: bytes) -> int:
    m = re.search(rb"^INSTALLER_VERSION\s*=\s*(\d+)\s*$", data, re.M)
    return int(m[1]) if m else 0


def looks_like_installer(data: bytes) -> bool:
    try:
        text = data.decode("utf-8")
        compile(text, INSTALLER_FILENAME, "exec")
    except (UnicodeDecodeError, SyntaxError):
        return False
    return "def main(" in text and "portitor" in text


def maybe_self_update(args: argparse.Namespace) -> None:
    """Replace this copy with the latest release's install.py if that is newer.

    Taken from the checksum-verified release archive, never from a branch:
    unreleased code may call commands the chosen release's binaries lack.
    Skipped in a git checkout, where the tree is the source of truth.
    """
    if args.skip_self_update or os.environ.get(SELF_UPDATED_ENV) or os.environ.get(PINNED_ENV):
        return
    if (REPO_DIR / ".git").exists() and not args.self_update:
        return
    client = GithubClient(args.repo, github_token())
    try:
        rel = latest_stable(client.list_releases(args.limit), args.pre)
        if rel is None:
            return
        with tempfile.TemporaryDirectory(prefix="portitor-self-") as tmp:
            checksums = download_checksums(client, rel)
            root = extract_archive(download_archive(client, rel, local_arch(), checksums), Path(tmp))
            remote = (root / INSTALLER_FILENAME).read_bytes()
    except (InstallError, OSError, ValueError) as exc:
        if args.self_update:
            raise
        warn(f"could not check the latest release for a newer {INSTALLER_FILENAME}: {exc}")
        return
    path = Path(__file__).resolve()
    local = path.read_bytes()
    if not looks_like_installer(remote) or installer_version_of(remote) <= installer_version_of(local):
        if args.self_update:
            log(f"==> {INSTALLER_FILENAME} is up to date (version {installer_version_of(local)})")
        return
    log(f"==> {rel.tag} has a newer {INSTALLER_FILENAME} "
        f"(version {installer_version_of(remote)}, this copy {installer_version_of(local)})")
    if args.dry_run:
        return
    if not (args.yes or args.self_update):
        if not sys.stdin.isatty():
            log("    re-run on a TTY, or pass --self-update")
            return
        if input("Update this installer and re-run? [Y/n] ").strip().lower() not in {"", "y", "yes"}:
            return
    fd, tmp = tempfile.mkstemp(prefix=".install.py.", dir=path.parent)
    with os.fdopen(fd, "wb") as f:
        f.write(remote)
    os.chmod(tmp, path.stat().st_mode)
    os.replace(tmp, path)
    log(f"==> Updated {path}")
    if args.self_update and not args.list and args.install is None:
        return
    env = dict(os.environ, **{SELF_UPDATED_ENV: "1"})
    os.execve(sys.executable, [sys.executable, str(path), *sys.argv[1:]], env)


def run_release_installer(rel: Release, root: Path, work: Path) -> int | None:
    """Run the release's own install.py unless this copy is newer.

    Returns its exit code, or None to install with this copy.
    """
    if os.environ.get(PINNED_ENV):
        return None
    bundled = root / INSTALLER_FILENAME
    payload = bundled.read_bytes() if bundled.is_file() else b""
    current = Path(__file__).resolve().read_bytes()
    if not looks_like_installer(payload) or payload == current:
        return None
    if installer_version_of(current) > installer_version_of(payload):
        log(f"==> This {INSTALLER_FILENAME} is newer than {rel.tag}'s; installing with this copy")
        return None
    log(f"==> Running {rel.tag}'s {INSTALLER_FILENAME}")
    argv, skip = [], False
    for a in sys.argv[1:]:
        if skip:
            skip = False
        elif a == "--install":
            skip = True
        elif not a.startswith("--install=") and a != "--self-update":
            argv.append(a)
    env = dict(os.environ, **{PINNED_ENV: "1", SELF_UPDATED_ENV: "1", RELEASE_WORK_ENV: str(work)})
    return subprocess.run([sys.executable, str(bundled), *argv, "--install", rel.tag], env=env, check=False).returncode


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main_release(args: argparse.Namespace) -> int:
    plan = make_plan(args)
    archs = plan_archs(plan)
    needed = set(needed_archs(plan, archs))
    installed = installed_versions(plan)
    cur = primary_version(installed)

    token = github_token()
    client = GithubClient(args.repo, token)
    log(f"==> Fetching releases from {args.repo}" + ("" if token else " (no GitHub token)"))
    releases = client.list_releases(args.limit)
    if args.list and args.json:
        print_release_json(releases, installed, needed, args.pre)
        return 0
    if not releases:
        raise InstallError(f"{args.repo} has no releases")
    newer = [r for r in releases if version_newer(r.tag, cur) and (args.pre or not r.prerelease) and not r.broken]

    if args.list:
        print_release_table(releases, plan, installed, needed)
        if newer:
            log(f"\n{len(newer)} newer release(s) than {cur}.")
            return 2
        return 0

    if args.install:
        rel = pick_release(releases, args.install, args.pre)
        if not os.environ.get(PINNED_ENV):
            print_release_table(releases, plan, installed, needed)
            if not confirm_text(rel, plan, installed, args.yes or args.dry_run):
                log("Aborted.")
                return 1
    elif sys.stdin.isatty() and sys.stdout.isatty():
        try:
            rel = curses_select(releases, plan, installed, needed)
        except curses.error:
            rel = numbered_select(releases, plan, installed, needed)
            if rel and not confirm_text(rel, plan, installed, False):
                rel = None
        if rel is None:
            log("Aborted.")
            return 1
    else:
        print_release_table(releases, plan, installed, needed)
        log()
        log("Newer releases available; pass --install TAG." if newer else "Up to date.")
        return 2 if newer else 0

    if missing := missing_archs(rel, needed):
        raise InstallError(f"{rel.tag} has no archive for {', '.join(missing)}")
    if rel.broken:
        warn(f"{rel.tag} is marked broken: {rel.broken}")
    log(f"==> Installing {rel.tag}: " + ", ".join(plan.describe()))
    ensure_sudo(plan, args.dry_run)

    inherited = os.environ.get(RELEASE_WORK_ENV) if os.environ.get(PINNED_ENV) else None
    work = Path(inherited) if inherited else Path(tempfile.mkdtemp(prefix="portitor-rel-"))
    try:
        roots = roots_from_work(work) if inherited else prepare_roots(client, rel, needed, work)
        if missing := sorted(needed - roots.keys()):
            raise InstallError(f"no extracted {', '.join(missing)} archive in {work}")
        any_root = next(iter(roots.values()))
        rc = run_release_installer(rel, any_root, work)
        if rc is not None:
            return rc
        install(plan, roots, archs, any_root / "deploy", rel.tag, args.yes, args.config)
    finally:
        if not inherited:
            shutil.rmtree(work, ignore_errors=True)
    return 0


def git_describe() -> str:
    try:
        proc = subprocess.run(
            ["git", "describe", "--tags", "--always", "--dirty"],
            cwd=REPO_DIR, capture_output=True, text=True, check=False,
        )
    except OSError:
        return "dev"
    return proc.stdout.strip() or "dev"


def build(argv: list[str], env: dict[str, str], dry_run: bool) -> None:
    printable = " ".join(f"{k}={v}" for k, v in env.items()) + " " + shlex.join(argv)
    if dry_run:
        log(f"    [dry-run] {printable}")
        return
    log(f"    $ {printable}")
    if subprocess.run(argv, cwd=REPO_DIR, env=dict(os.environ, **env), check=False).returncode:
        raise InstallError(f"build failed: {printable}")


def main_source(args: argparse.Namespace) -> int:
    plan = make_plan(args)
    archs = plan_archs(plan)
    build_dir = REPO_DIR / "build"
    log(f"==> Source install of {git_describe()}: " + ", ".join(plan.describe()))

    # CGO off: the firewall may run an older libc than this machine.
    if args.skip_build:
        log(f"==> Using the existing {build_dir}")
    else:
        log("==> Building (make release)")
        build(["make", "release"], {"CGO_ENABLED": "0"}, args.dry_run)
    roots = {local_arch(): build_dir}
    # What each architecture needs: the local one always gets both (make release).
    needs = needed_archs(plan, archs)
    needs[local_arch()] = {"portitor-web", "portitor-agent"}
    for arch, names in needs.items():
        if arch == local_arch():
            continue
        cross = build_dir / f"{ARCHIVE_OS}_{arch}"
        log(f"==> Building {', '.join(sorted(names))} for {arch}")
        if not args.skip_build:
            # release builds the frontend into portitor-web, as for this host.
            target = "release" if "portitor-web" in names else "portitor-agent"
            build(["make", target, f"BUILD_DIR={cross.relative_to(REPO_DIR)}"],
                  {"CGO_ENABLED": "0", "GOOS": ARCHIVE_OS, "GOARCH": arch}, args.dry_run)
        roots[arch] = cross
    for arch, root in roots.items():
        for name in sorted(needs[arch]):
            if not (root / name).is_file():
                if args.dry_run:
                    log(f"==> Dry run: {root / name} is not built yet, so nothing more to show")
                    return 0
                raise InstallError(f"{root / name} is missing; run without --skip-build")
    # Stamped into the binary; with a dry run or --skip-build, that is build/'s.
    proc = subprocess.run([str(build_dir / "portitor-web"), "--version"], capture_output=True, text=True, check=False)
    version = version_of_output(proc.stdout) or git_describe()

    ensure_sudo(plan, args.dry_run)
    install(plan, roots, archs, REPO_DIR / "deploy", version, args.yes, args.config)
    return 0


def main_local(args: argparse.Namespace) -> int:
    plan = make_plan(args)
    archs = plan_archs(plan)
    path = Path(args.local).resolve()
    work = None
    try:
        if path.is_dir():
            if not is_release_root(path):
                raise InstallError(f"{path} does not contain portitor-web, portitor-agent and deploy/{{agent,web}}.yaml")
            root = path
        elif path.is_file():
            work = Path(tempfile.mkdtemp(prefix="portitor-local-"))
            root = extract_archive(path, work)
        else:
            raise InstallError(f"{path}: no such file or directory")
        # The binaries must run here to report their version.
        for kind, arch in archs.items():
            if arch != local_arch():
                raise InstallError(f"--local installs {local_arch()} only; the {kind} host is {arch}")
        proc = subprocess.run([str(root / "portitor-agent"), "--version"], capture_output=True, text=True, check=False)
        version = version_of_output(proc.stdout)
        if proc.returncode != 0 or not version:
            raise InstallError(f"cannot run {root / 'portitor-agent'} --version (not an {local_arch()} build?)")
        log(f"==> Local install of {version} from {path}: " + ", ".join(plan.describe()))
        ensure_sudo(plan, args.dry_run)
        install(plan, {local_arch(): root}, archs, root / "deploy", version, args.yes, args.config)
    finally:
        if work:
            shutil.rmtree(work, ignore_errors=True)
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Install or update portitor-web and portitor-agent.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ./install.py                          pick a release (TUI), update what is installed
  ./install.py --list                   show releases; exit 2 if one is newer
  ./install.py --install latest --yes   unattended update
  ./install.py --install v1.2.0 --web --agent fw.example.net
  ./install.py --source --dry-run       from this tree, show what would change
  ./install.py --source --agent 192.168.1.1   this tree's agent onto the firewall only
  ./install.py --source --web gui.example.net --agent fw.example.net   this tree onto both
  ./install.py --install latest --agent fw1,fw2   both hosts of an HA pair, secondary first
  ./install.py --local portitor_1.2.0_linux_amd64.tar.gz --web --agent

Environment:
  GITHUB_TOKEN / GH_TOKEN   token for a private repo (else `gh auth token`)
  SSH_USER                  default for --ssh-user (else portitor)
""",
    )
    what = p.add_argument_group("what to install (default: what is installed on this host)")
    what.add_argument("--web", nargs="?", const="localhost", metavar="HOST",
                      help="portitor-web on HOST (default this host)")
    what.add_argument("--agent", nargs="?", const="localhost", action="append", metavar="HOST[,HOST...]",
                      help="portitor-agent on HOST (default this host); repeat it, or separate hosts "
                           "by commas, for several (one at a time, HA secondaries first)")
    what.add_argument("--no-agent", action="store_true", help="never install or update the agent")
    what.add_argument("--config", action="store_true",
                      help=argparse.SUPPRESS)  # portitor-config goes with every agent now
    what.add_argument("--ssh-user", default=os.environ.get("SSH_USER", SSH_USER_DEFAULT),
                      help="SSH user for a remote host: root, or a user with passwordless sudo "
                           f"(default {SSH_USER_DEFAULT})")
    src = p.add_argument_group("where from")
    src.add_argument("--source", action="store_true", help="build and install this source tree")
    src.add_argument("--skip-build", action="store_true", help="with --source, use build/ as it is")
    src.add_argument("--local", metavar="PATH", help="install a release archive or extracted release directory")
    src.add_argument("--list", action="store_true", help="print GitHub releases and exit")
    src.add_argument("--json", action="store_true", help="with --list, print JSON (always exit 0)")
    src.add_argument("--install", metavar="TAG", help="release tag to install, or 'latest'")
    src.add_argument("--pre", action="store_true", help="let 'latest' pick a prerelease")
    src.add_argument("--repo", default=os.environ.get("GITHUB_REPO", REPO_DEFAULT), help=f"default {REPO_DEFAULT}")
    src.add_argument("--limit", type=int, default=50, help="releases to fetch (default 50)")
    src.add_argument("--self-update", action="store_true",
                     help="update this script from the latest release, then continue with --list/--install or exit")
    src.add_argument("--skip-self-update", action="store_true", help="do not look for a newer install.py")
    p.add_argument("--yes", "-y", action="store_true", help="no prompts; overwrite changed systemd units")
    p.add_argument("--dry-run", action="store_true", help="show what would change, change nothing")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    global log_stream
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.json:
        log_stream = sys.stderr
    if args.no_agent and args.agent is not None:
        raise InstallError("--agent and --no-agent exclude each other")
    if args.skip_build and not args.source:
        raise InstallError("--skip-build needs --source")
    if args.source and args.local:
        raise InstallError("--source and --local exclude each other")
    if (args.source or args.local) and (args.list or args.install or args.self_update):
        raise InstallError("--source and --local cannot be combined with --list, --install or --self-update")
    if args.json and not args.list:
        raise InstallError("--json needs --list")
    if args.self_update and args.skip_self_update:
        raise InstallError("--self-update and --skip-self-update exclude each other")
    if args.source:
        return main_source(args)
    if args.local:
        return main_local(args)
    maybe_self_update(args)
    if args.self_update and not args.list and args.install is None:
        return 0
    return main_release(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        sys.exit(130)
    except InstallError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)
