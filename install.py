#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 The Portitor contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Install or update Portitor: on a firewall portitor-agent and
portitor-config (its configuration, GUI and API), and portitor-manager, the
manager of the firewalls (portitor-web before 1.1.0), on this host or
another (over SSH).

Binaries go to /usr/bin, systemd units to /etc/systemd/system, example
configs to /etc/portitor (only when missing; config.yaml gets a generated
jwt_secret). If an installed unit differs from this release, the installer
shows a diff and asks before overwriting (--yes overwrites).

An update restarts portitor-agent (its per-instance units follow), stops
portitor-config, runs `portitor-config migrate` (which checks that it can
read its data directory) and restarts it, and restarts portitor-manager. The
firewall is updated first: the agent rejects document fields it does not
know, so it must never be older than portitor-config. On a first install,
when a config was just created, the data directory is made but nothing is
started; the installer prints the remaining steps.

Before anything is replaced, the release's portitor-config reads a copy of
each firewall's data directory (`migrate`); one it can't read (an older
release than the data's) is refused with nothing changed. Each host then
keeps its installed release in /var/lib/portitor-previous (binaries, units,
/etc/portitor and the data directories of the services updated there, copied
while they are stopped). After the restarts the agent must answer and
portitor-config and portitor-manager listen; when a step or a check fails, the
host is put back to its previous release (its data directory too, from before
the migration) and the update stops: the hosts before it stay updated. Debian
packages installed by the update stay.

An installation older than 1.0.0 is refused before anything is replaced:
update it to 1.0.0 first, which moves what its database held into files.

What gets installed:
  (default)       whatever is installed on this host. When that includes
                  portitor-manager, also the firewalls it serves (the hosts
                  of the firewalls in its configuration, portitor-manager
                  list-firewalls, and their cluster peers).
  --manager [HOST]  portitor-manager on HOST (default this host), over SSH
                  like --agent (plus the firewalls, as above); --web is the
                  same, until 1.2.0
  --agent [HOST]  portitor-agent and portitor-config on HOST (default this
                  host), over SSH as
                  --ssh-user (default portitor, which needs passwordless
                  sudo; the installer prints how to set that up), or root.
                  Repeat it, or separate hosts by commas, for several. Agents
                  are updated one at a time, a cluster's secondary first,
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
INSTALLER_VERSION = 15
INSTALLER_FILENAME = "install.py"
# Where the agent host keeps a copy, for updates from the GUI.
INSTALLER_DEST = "/usr/lib/portitor/install.py"

REPO_DIR = Path(__file__).resolve().parent
REPO_DEFAULT = "abundo/portitor"
USER_AGENT = "portitor-install.py"
ARCHIVE_OS = "linux"

BIN_DIR = "/usr/bin"
# The one binary: portitor-manager, and portitor-config by that name (a
# symlink). portitor-web, its name before 1.1.0, stays a symlink to it until
# 1.2.0.
WEB_BIN = f"{BIN_DIR}/portitor-manager"
OLD_WEB_BIN = f"{BIN_DIR}/portitor-web"
AGENT_BIN = f"{BIN_DIR}/portitor-agent"
# The portitor command (show lldp neighbours, ...) is the agent run by this name.
CLI_LINK = f"{BIN_DIR}/portitor"
# Its bash completion (cobra's "portitor completion bash"), written on every
# install and update so it follows the release's commands; the bash-completion
# package loads it.
CLI_COMPLETION = "/usr/share/bash-completion/completions/portitor"
COMPLETION_DIR = str(Path(CLI_COMPLETION).parent)
ETC_DIR = "/etc/portitor"
WEB_CONFIG = f"{ETC_DIR}/manager.yaml"
WEB_DATA_DIR = "/var/lib/portitor-manager"
# portitor-manager's before 1.1.0 (portitor-web), moved by migrate_manager.
OLD_WEB_CONFIG = f"{ETC_DIR}/web.yaml"
OLD_WEB_DATA_DIR = "/var/lib/portitor-web"
OLD_WEB_UNIT = "portitor-web.service"
AGENT_CONFIG = f"{ETC_DIR}/agent.yaml"
SYSTEMD_DIR = "/etc/systemd/system"
WEB_USER = "portitor"
# portitor-config: portitor-manager run as portitor-config on the firewall,
# its configuration, GUI and API. It touches its data directory only as
# WEB_USER, so the files it writes stay writable for the service.
CONFIG_LINK = f"{BIN_DIR}/portitor-config"
CONFIG_FILE = f"{ETC_DIR}/config.yaml"
CONFIG_DB_DIR = "/var/lib/portitor-config"
CONFIG_UNIT = "portitor-config.service"
CONFIG_CERT = f"{ETC_DIR}/config.crt"
CONFIG_KEY = f"{ETC_DIR}/config.key"
# The agent's last applied document (its default state_dir).
AGENT_APPLIED = "/var/lib/portitor/applied.json"
SSH_USER_DEFAULT = "portitor"
# Portitor's DHCP servers run as this user (portitor-dhcpd@.service).
DHCP_USER = "portitor-dhcp"
WEB_UNIT = "portitor-manager.service"
AGENT_UNIT = "portitor-agent.service"
# The boot-time policy (render.Early): enabled with the agent, never started
# on a running host; the agent's first apply at the next boot removes it.
EARLY_UNIT = "portitor-early.service"
# The per-instance units are started by the agent, never enabled.
AGENT_UNITS = (
    AGENT_UNIT,
    EARLY_UNIT,
    "portitor-named@.service",
    "portitor-dhcpd@.service",
    "portitor-frr@.service",
    "portitor-chrony@.service",
    "portitor-snmpd@.service",
    "portitor-conntrackd@.service",
    "portitor-openvpn-udp@.service",
    "portitor-openvpn-tcp@.service",
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
    # Syslog servers: rsyslog sends them the journal, and runs only for that.
    "rsyslog": ("rsyslog.service",),
    # OpenVPN; the default virtual firewall's runs under the template
    # openvpn-server@, which starts nothing by itself.
    "openvpn": (),
    # NAT64; DKMS builds the kernel module with the kernel headers
    # (agent_packages adds them for the architecture).
    "jool-dkms": (),
    "jool-tools": (),
    # Loads the portitor command's completion (CLI_COMPLETION).
    "bash-completion": (),
}
# BIND 9 stable from ISC's Debian repository
# (https://kb.isc.org/docs/isc-packages-for-bind-9), newer than the
# distribution's; iso/preseed.cfg adds it too. Signed by the deb.sury.org key
# in deploy/apt/isc-bind.asc (15058500A0235D97F5D10063B188E2B695BD4743).
ISC_BIND_REPO = "https://bind.debian.net/bind"
ISC_BIND_SUITES = ("bullseye", "bookworm", "trixie", "jammy", "noble", "resolute")
ISC_BIND_KEYRING = "/usr/share/keyrings/isc-bind.asc"
ISC_BIND_LIST = "/etc/apt/sources.list.d/isc-bind.list"
# Debian/Ubuntu confine named and chronyd with AppArmor; our rules
# (deploy/apparmor/<profile>) go in each profile's local include, between
# markers so the admin's own lines are kept.
APPARMOR_DIR = "/etc/apparmor.d"
APPARMOR_BEGIN = "# BEGIN portitor (managed by install.py)"
APPARMOR_END = "# END portitor"
LOCAL_NAMES = {"localhost", "127.0.0.1", "::1", ""}
# Where install.py once put Wiregasm, which portitor-manager now embeds; removed on
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


# The oldest release an update to a later one starts from: 1.0.0 moved what
# the database held into files (marking its data directory with
# layout.json), and later releases read no database.
MIN_UPGRADE_FROM = (1, 0, 0)


def check_upgrade_path(tag: str, installed: dict[str, str]) -> None:
    """Refuse, before anything is replaced, an update from before 1.0.0 to a
    release after it: it would leave a database it can't read."""
    rel = parse_version(tag)
    if rel is None or rel <= MIN_UPGRADE_FROM:
        return
    for name, stamp in installed.items():
        cur = parse_version(stamp)
        if cur is not None and cur < MIN_UPGRADE_FROM:
            raise InstallError(
                f"{name} is {stamp}: install 1.0.0 first (and start it once, so it moves what "
                f"its database holds into files), then update to {tag}"
            )


def check_data_dirs(plan: "Plan") -> None:
    """Refuse, before anything is replaced, a firewall whose portitor-config
    data directory is of a release before 1.0.0: it has the database or the
    files, but not the layout.json that 1.0.0 writes once it has moved the
    database into files. This release would not start on it."""
    def there(a: "Host", name: str) -> bool:
        # The directory is the service user's, 0700.
        return a.run(f"test -e {CONFIG_DB_DIR}/{name}", check=False, mutate=False, root=True).returncode == 0

    for a in plan.agents:
        if there(a, "layout.json"):
            continue
        old = [f for f in ("portitor.db", "candidate.json") if there(a, f)]
        if old:
            raise InstallError(
                f"{a}: {CONFIG_DB_DIR} has {', '.join(old)} but no layout.json: it is from a release "
                f"before 1.0.0 (or 1.0.0 never started there). Install 1.0.0 and start it once, then update"
            )


def versions_equal(tag: str, installed: str) -> bool:
    return same_stamp(tag, installed) and not is_dev_build(installed)


def same_base(tag: str, installed: str) -> bool:
    rel = parse_version(tag)
    return rel is not None and rel == parse_version(installed)


def version_of_output(text: str) -> str | None:
    """`portitor-manager --version` prints "portitor-manager version <stamp>"."""
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

    def hosts(self) -> list[Host]:
        return ([self.web] if self.web else []) + self.agents

    def describe(self) -> list[str]:
        out = [f"portitor-agent and portitor-config on {a}" for a in self.agents]
        if self.agent_order_note:
            out.append(self.agent_order_note)
        if self.web:
            out.append(f"portitor-manager on {self.web}")
        return out


def verify_version(host: Host, binary: str, expected: str) -> None:
    if host.dry_run:
        return
    got = host.version(binary)
    if not got or not same_stamp(got, expected):
        raise InstallError(f"{host}: {binary} reports {got or 'no version'}, expected {expected}")
    log(f"    {host}: {Path(binary).name} {got}")


# systemd generators of no use on a firewall, masked by a /dev/null link in
# /etc/systemd/system-generators. systemd-ssh-generator runs on every daemon
# reload (each unit the agent unmasks) and, outside a VM, logs "Failed to query
# local AF_VSOCK CID" to the kernel log, which fills the console.
MASKED_GENERATORS = ("systemd-ssh-generator",)
GENERATORS_DIR = "/etc/systemd/system-generators"


def mask_generators(host: Host) -> None:
    for name in MASKED_GENERATORS:
        link = shlex.quote(f"{GENERATORS_DIR}/{name}")
        host.run(
            f"mkdir -p {GENERATORS_DIR} && ln -sfn /dev/null {link}",
            desc=f"ln -s /dev/null {GENERATORS_DIR}/{name}",
        )


def install_completion(host: Host, command: str) -> None:
    """Bash completion of a command, cobra's "<command> completion bash",
    written like the portitor command's (CLI_COMPLETION)."""
    bin_ = shlex.quote(f"{BIN_DIR}/{command}")
    dest = shlex.quote(f"{COMPLETION_DIR}/{command}")
    host.run(
        f"mkdir -p {shlex.quote(COMPLETION_DIR)} && {bin_} completion bash >{dest}",
        desc=f"{command} completion bash >{COMPLETION_DIR}/{command}",
    )


def install_agent(host: Host, binary: Path, deploy: Path, version: str, assume_yes: bool) -> None:
    log(f"==> Installing portitor-agent {version} on {host}")
    new_config = not host.exists(AGENT_CONFIG)
    if new_config:
        host.put(deploy / "agent.yaml", AGENT_CONFIG, "0600")
    host.put(binary, AGENT_BIN, "0755")
    host.run(f"ln -sfn portitor-agent {shlex.quote(CLI_LINK)}", desc=f"ln -s portitor-agent {CLI_LINK}")
    install_completion(host, "portitor")
    install_completion(host, "portitor-agent")
    host.put(Path(__file__).resolve(), INSTALLER_DEST, "0755", name=INSTALLER_FILENAME)
    actions = {u: install_unit(host, deploy / "systemd" / u, assume_yes) for u in AGENT_UNITS}
    ensure_dhcp_user(host)
    retire_kea(host)
    retire_radvd(host)
    move_bind_dirs(host)
    mask_generators(host)
    host.systemctl("daemon-reload")
    install_apparmor(host, deploy)
    if new_config:
        on = "" if host.local else f" (on {host.name})"
        log(f"==> portitor-agent is installed but not started. Next steps{on}:")
        log("    install nftables, iproute2, wireguard-tools, bind9, frr, frr-pythontools,")
        log("      tcpdump, tshark, mtr-tiny and iperf3 (or your distribution's equivalents)")
        log("    portitor-agent init --host <management address>   # token + fingerprint for the GUI")
        log(f"    $EDITOR {AGENT_CONFIG}                     # listen, allow_from, bind_user")
        log("    the default virtual firewall (the host) runs the distribution's named and FRR:")
        log("      the agent writes their standard config files (keeping the originals as *.portitor-orig)")
        log("      and enables the ones it uses; disable the others if you don't run them yourself")
        log("    remove the firewall's interfaces from netplan, NetworkManager or systemd-networkd")
        log("      (a second DHCP client on the WAN keeps the agent from getting a lease)")
        log(f"    systemctl enable --now {AGENT_UNIT}")
        log(f"    systemctl enable {EARLY_UNIT}   # closed at boot until the agent applies")
        return
    install_packages(host, deploy)
    if actions[AGENT_UNIT] == "installed":
        host.systemctl("enable", AGENT_UNIT)
    # Enabled alone: it takes effect at the next boot, and the agent (which
    # removes it) is the one restarted here.
    if agent_enabled(host):
        host.systemctl("enable", EARLY_UNIT)
    host.systemctl("restart", AGENT_UNIT)
    if not host.dry_run and not agent_answers(host):
        raise InstallError(f"{AGENT_UNIT} does not answer on {host}; see journalctl -u {AGENT_UNIT}")
    verify_version(host, AGENT_BIN, version)


def agent_answers(host: Host, timeout: float = 20) -> bool:
    """Whether the restarted agent answers on its socket within timeout.
    A unit that is active for a moment may still be failing at start and
    restarting (no token, a listen address it can't bind): that one never
    answers."""
    deadline = time.monotonic() + timeout
    while True:
        # "show ha", not "show cluster": an agent before 1.1.0 knows only that.
        if host.run(f"{CLI_LINK} show ha >/dev/null 2>&1", check=False, mutate=False, root=True).returncode == 0:
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(1)


# ---------------------------------------------------------------------------
# The previous release, kept for a restore
# ---------------------------------------------------------------------------

# Each host keeps one copy of what an update replaces, taken before it does:
# the binaries and their links, the units, /etc/portitor and the data
# directories of the services updated there, copied while those are stopped.
# An update that fails on a host (a step, or a health check after the
# restarts) puts it back there, so the old binaries run on the data directory
# they read, and the update stops. Root only: it holds the secrets.
PREVIOUS_ROOT = "/var/lib/portitor-previous"
PREVIOUS_DIR = f"{PREVIOUS_ROOT}/previous"
PREVIOUS_FILES = (AGENT_BIN, CLI_LINK, WEB_BIN, OLD_WEB_BIN, CONFIG_LINK, INSTALLER_DEST, f"{BIN_DIR}/portitor-setup")
# Restarted by a restore when they were running before the update.
PREVIOUS_UNITS = (AGENT_UNIT, CONFIG_UNIT, WEB_UNIT)


def take_previous(host: Host, config: bool, manager: bool) -> bool:
    """Copies the installed release on host into PREVIOUS_DIR (one, the
    last), stopping portitor-config (config) and portitor-manager (manager)
    so that their data directories are copied whole. False when nothing is
    installed there yet: a first install has nothing to go back to."""
    if not (host.exists(AGENT_BIN) or host.exists(WEB_BIN) or host.exists(OLD_WEB_BIN)):
        return False
    dirs = ([CONFIG_DB_DIR] if config else []) + ([WEB_DATA_DIR] if manager else [])
    stop = ([CONFIG_UNIT] if config else []) + ([WEB_UNIT] if manager else [])
    version = host.version(WEB_BIN) or host.version(AGENT_BIN) or "unknown"
    q = shlex.quote
    new = q(f"{PREVIOUS_DIR}.new")
    script = "\n".join([
        "set -e",
        f"rm -rf {new}",
        f"install -d -m 0700 {q(PREVIOUS_ROOT)} {new} {new}/files {new}/data",
        f": >{new}/active",
        f"for u in {' '.join(PREVIOUS_UNITS)}; do",
        f"  if systemctl is-active --quiet \"$u\"; then echo \"$u\" >>{new}/active; fi",
        "done",
        *[f"systemctl stop {u} 2>/dev/null || true" for u in stop],
        f"for f in {' '.join(q(f) for f in PREVIOUS_FILES)} {SYSTEMD_DIR}/portitor-*.service {ETC_DIR}; do",
        f"  if [ -e \"$f\" ] || [ -L \"$f\" ]; then cp -a --parents \"$f\" {new}/files/; fi",
        "done",
        f": >{new}/data.list",
        f"for d in {' '.join(q(d) for d in dirs)}; do",
        f"  if [ -d \"$d\" ]; then cp -a --parents \"$d\" {new}/data/; echo \"$d\" >>{new}/data.list; fi",
        "done",
        f"echo {q(version)} >{new}/version",
        f"rm -rf {q(PREVIOUS_DIR)}",
        f"mv {new} {q(PREVIOUS_DIR)}",
    ])
    log(f"==> Keeping Portitor {version} on {host} for a restore ({PREVIOUS_DIR})")
    host.run(script, desc=f"copy Portitor {version} (binaries, units, {ETC_DIR}"
             + "".join(f", {d}" for d in dirs) + f") to {PREVIOUS_DIR}")
    return True


def restore_previous(host: Host) -> str:
    """Puts PREVIOUS_DIR back on host: the data directories replaced by their
    copies, the files over the new ones, and the units that ran restarted
    (portitor-config's data first, then the agent: the agent is never older
    than portitor-config). The restored version; raises if it doesn't run."""
    p = shlex.quote(PREVIOUS_DIR)
    version = (host.read(f"{PREVIOUS_DIR}/version", root=True) or "").strip() or "the previous release"
    # Read before the restore: a read that fails afterwards must not pass
    # for "nothing ran", which would skip the checks.
    active_text = host.read(f"{PREVIOUS_DIR}/active", root=True)
    if active_text is None and not host.dry_run:
        raise InstallError(f"{host}: can't read {PREVIOUS_DIR}/active")
    active = set((active_text or "").split())
    log(f"==> Restoring Portitor {version} on {host}")
    script = "\n".join([
        "set -e",
        f"test -d {p}",
        f"systemctl stop {CONFIG_UNIT} {WEB_UNIT} 2>/dev/null || true",
        f"while read -r d; do [ -n \"$d\" ] || continue; rm -rf \"$d\"; cp -a {p}/data\"$d\" \"$(dirname \"$d\")/\"; done <{p}/data.list",
        # Each top-level entry: "files/." would give / the mode of files (0700).
        f"for e in {p}/files/*; do cp -a --remove-destination \"$e\" /; done",
        "systemctl daemon-reload",
        f"if grep -qx {AGENT_UNIT} {p}/active; then systemctl restart {AGENT_UNIT}; fi",
        f"for u in {CONFIG_UNIT} {WEB_UNIT}; do if grep -qx \"$u\" {p}/active; then systemctl start \"$u\"; fi; done",
    ])
    host.run(script, desc=f"restore {PREVIOUS_DIR} (data directories, binaries, units) and restart what ran")
    if host.dry_run:
        return version
    if AGENT_UNIT in active and not agent_answers(host):
        raise InstallError(f"{host}: the restored {AGENT_UNIT} does not answer; see journalctl -u {AGENT_UNIT}")
    if CONFIG_UNIT in active:
        service_healthy(host, CONFIG_UNIT, CONFIG_FILE, "8444")
    if WEB_UNIT in active:
        service_healthy(host, WEB_UNIT, WEB_CONFIG, "8080")
    return version


def service_healthy(host: Host, unit: str, config_file: str, default_port: str, timeout: float = 60) -> None:
    """Raises unless unit is active and listening on its config's bind port
    within timeout, and still active 5 s later (a unit failing at start is
    active for a moment between its restarts)."""
    if host.dry_run:
        return
    text = host.read(config_file, root=True) or ""
    m = re.search(r"^bind:\s*[\"']?([^\s\"'#]+)", text, re.M)
    port = (m.group(1).rpartition(":")[2] if m else "") or default_port
    probe = f"systemctl is-active --quiet {unit} && ss -Hltn 'sport = :{port}' | grep -q ."
    deadline = time.monotonic() + timeout
    while host.run(probe, check=False, mutate=False, root=True).returncode != 0:
        if time.monotonic() >= deadline:
            raise InstallError(f"{host}: {unit} does not listen on port {port} after {timeout:.0f} s; "
                               f"see journalctl -u {unit}")
        time.sleep(1)
    time.sleep(5)
    if host.run(f"systemctl is-active --quiet {unit}", check=False, mutate=False, root=True).returncode != 0:
        raise InstallError(f"{host}: {unit} stopped after it started; see journalctl -u {unit}")


def check_config_reads(host: Host, binary: Path, version: str) -> None:
    """Before anything is replaced: the release's portitor-config reads
    (migrates) a copy of the data directory, so a release that can't (a
    later layout, an older release than the one that migrated it) is
    refused with nothing changed."""
    if host.dry_run or not host.exists(f"{CONFIG_DB_DIR}/layout.json"):
        return
    log(f"==> Checking that portitor-config {version} reads the data directory on {host}")
    tmp = host.run("mktemp -d /var/tmp/portitor-check.XXXXXX", desc="mktemp -d /var/tmp/portitor-check.XXXXXX",
                   capture=True).stdout.strip()
    if not tmp.startswith("/var/tmp/portitor-check."):
        raise InstallError(f"{host}: mktemp printed {tmp!r}")
    t = shlex.quote(tmp)
    try:
        host.put(binary, f"{tmp}/portitor-manager", "0755", name="portitor-manager")
        script = "\n".join([
            "set -e",
            f"chmod 0711 {t}",
            f"ln -s portitor-manager {t}/portitor-config",
            f"cp -a {CONFIG_DB_DIR} {t}/data",
            f"chown -R {WEB_USER}: {t}/data",
            f"sed '/^db:/,/^[^[:space:]#]/ s#^\\([[:space:]]*path:\\).*#\\1 {tmp}/data/portitor.db#' {CONFIG_FILE} >{t}/config.yaml",
            f"chown {WEB_USER} {t}/config.yaml",
            f"chmod 0600 {t}/config.yaml",
            f"runuser -u {WEB_USER} -- {t}/portitor-config -f {t}/config.yaml migrate",
        ])
        proc = host.run(script, desc=f"portitor-config {version} migrate, on a copy of {CONFIG_DB_DIR}",
                        check=False, capture=True)
        if proc.returncode != 0:
            raise InstallError(
                f"{host}: portitor-config {version} can't read the data directory, so nothing was changed:\n"
                + ((proc.stderr or "") + (proc.stdout or "")).strip()
            )
    finally:
        host.run(f"rm -rf {t}", desc=f"rm -rf {tmp}", check=False)


def restore_after(host: Host, kept: bool, exc: BaseException, updated: list[str]) -> InstallError:
    """The error to stop the update with after it failed on host: host put
    back to its previous release when one was kept."""
    rest = (f" Already updated: {', '.join(updated)}." if updated else "")
    if not kept:
        return InstallError(f"{exc}\n{host}: there was no previous release to restore.{rest}")
    try:
        version = restore_previous(host)
    except InstallError as err:
        return InstallError(f"{exc}\nRESTORING {host} FAILED: {err}\nThe copy is kept in {PREVIOUS_DIR}.{rest}")
    return InstallError(f"{exc}\n{host} is back on Portitor {version}; the update stopped there.{rest}")


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


def ensure_dhcp_user(host: Host) -> None:
    """The user Portitor's DHCP servers run as (portitor-dhcpd@.service)."""
    host.run(
        f"getent group {DHCP_USER} >/dev/null || groupadd --system {DHCP_USER}; "
        f"getent passwd {DHCP_USER} >/dev/null || useradd --system -g {DHCP_USER} "
        f"--no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin {DHCP_USER}",
        desc=f"create system user {DHCP_USER} unless it exists",
    )


def retire_kea(host: Host) -> None:
    """Stop Kea, which Portitor's own DHCP server replaces.

    Its units would keep the DHCP ports; the distribution's are masked and
    Portitor's template units removed. The packages and lease files stay.
    """
    units = " ".join(f"{SYSTEMD_DIR}/portitor-kea{v}@.service" for v in (4, 6))
    host.run(
        "systemctl stop 'portitor-kea4@*' 'portitor-kea6@*' 2>/dev/null; "
        f"rm -f {units}; "
        "for u in kea-dhcp4-server.service kea-dhcp6-server.service; do\n"
        '  if systemctl cat "$u" >/dev/null 2>&1; then systemctl disable --now "$u" 2>/dev/null; systemctl mask "$u"; fi\n'
        "done\n"
        "true",
        desc="stop and mask Kea (replaced by portitor-dhcpd@)",
    )


def retire_radvd(host: Host) -> None:
    """Stop radvd, whose router advertisements Portitor's DHCP server sends.

    Portitor's template unit and the virtual firewalls' radvd.conf are
    removed. The distribution's radvd is stopped and masked only when it
    runs from our /etc/radvd.conf, and the file it replaced is put back; a
    sysadmin's own radvd keeps running. The package stays.
    """
    host.run(
        "systemctl stop 'portitor-radvd@*' 2>/dev/null; "
        f"rm -f {SYSTEMD_DIR}/portitor-radvd@.service /etc/portitor/instances/*/radvd.conf; "
        "if head -n 1 /etc/radvd.conf 2>/dev/null | grep -q 'Generated by portitor-agent'; then\n"
        "  systemctl disable --now radvd.service 2>/dev/null; systemctl mask radvd.service\n"
        "  if [ -e /etc/radvd.conf.portitor-orig ]; then mv /etc/radvd.conf.portitor-orig /etc/radvd.conf; else rm -f /etc/radvd.conf; fi\n"
        "fi\n"
        "true",
        desc="stop radvd (replaced by portitor-dhcpd@)",
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
    """Let named and chronyd (portitor-named@, -chrony@) use Portitor's paths.

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


def install_web(host: Host, binary: Path, deploy: Path, version: str, assume_yes: bool) -> None:
    """portitor-manager: its configuration (firewalls, users) in its data directory."""
    log(f"==> Installing portitor-manager {version} on {host}")
    ensure_user(host)
    had_old, was_enabled = migrate_manager(host)
    update_setup(host, deploy)
    host.run(f"install -d -o {WEB_USER} -g {WEB_USER} -m 0750 {WEB_DATA_DIR}", desc="create the manager's data directory")
    new_config = not host.exists(WEB_CONFIG)
    if new_config:
        host.put(deploy / "manager.yaml", WEB_CONFIG, "0640", group=WEB_USER)
    install_binary(host, binary)
    install_completion(host, "portitor-manager")
    if host.exists(OLD_WIREGASM_DIR):
        host.run(f"rm -rf {OLD_WIREGASM_DIR}")
    action = install_unit(host, deploy / "systemd" / WEB_UNIT, assume_yes)
    host.systemctl("daemon-reload")
    if new_config:
        log("==> portitor-manager is installed but not started. Next steps:")
        log(f"    make a user: sudo -u {WEB_USER} portitor-manager createadmin <user>")
        log("    start it, log in, and add the firewalls there (Add firewall reads their")
        log("      fingerprints over SSH); or list them under firewalls: in " + WEB_CONFIG)
        log("      before the first start (taken in once)")
        log(f"    this host's address under trusted_proxies: in each firewall's {CONFIG_FILE}")
        log(f"    systemctl enable --now {WEB_UNIT}")
        return
    # Enabled where it ran before: the ISO installs it on every host, and
    # disables it where the host is a firewall.
    if was_enabled or (action == "installed" and not had_old):
        host.systemctl("enable", WEB_UNIT)
    if host.run(f"systemctl is-enabled --quiet {WEB_UNIT}", check=False, mutate=False).returncode != 0:
        log(f"    {WEB_UNIT} is disabled on {host}; not started")
        return
    host.systemctl("restart", WEB_UNIT)
    service_healthy(host, WEB_UNIT, WEB_CONFIG, "8080")
    verify_version(host, WEB_BIN, version)


# The ISO's first-boot setup (iso/target.sh), and its completion.
SETUP_BIN = f"{BIN_DIR}/portitor-setup"
SETUP_COMPLETION = f"{COMPLETION_DIR}/portitor-setup"


def update_setup(host: Host, deploy: Path) -> None:
    """Replaces the ISO's portitor-setup on host, where it is installed, with
    the release's, so that it follows the release's names and files. An
    archive without it (before 1.1.0) leaves it as it is."""
    src = deploy.parent / "iso" / "portitor-setup.py"
    if not src.is_file() or not host.exists(SETUP_BIN):
        return
    host.put(src, SETUP_BIN, "0755")
    bash = deploy.parent / "iso" / "portitor-setup.bash"
    if bash.is_file():
        host.put(bash, SETUP_COMPLETION, "0644")


def install_binary(host: Host, binary: Path) -> None:
    """The binary as portitor-manager, with portitor-web (its name before
    1.1.0) a symlink to it until 1.2.0."""
    host.put(binary, WEB_BIN, "0755")
    host.run(f"ln -sfn portitor-manager {shlex.quote(OLD_WEB_BIN)}", desc=f"ln -s portitor-manager {OLD_WEB_BIN}")


def migrate_manager(host: Host) -> tuple[bool, bool]:
    """Moves portitor-web (before 1.1.0) to portitor-manager's names: its
    unit stopped and removed, web.yaml to manager.yaml, its data directory
    to WEB_DATA_DIR. Whether the old unit was there, and enabled."""
    had_old = host.exists(f"{SYSTEMD_DIR}/{OLD_WEB_UNIT}")
    if not had_old:
        enabled = False
    else:
        enabled = host.run(f"systemctl is-enabled --quiet {OLD_WEB_UNIT}", check=False, mutate=False).returncode == 0
        log(f"==> portitor-web is portitor-manager now: replacing {OLD_WEB_UNIT}")
        host.run(f"systemctl disable --now {OLD_WEB_UNIT} 2>/dev/null || true", desc=f"systemctl disable --now {OLD_WEB_UNIT}")
        host.run(f"rm -f {SYSTEMD_DIR}/{OLD_WEB_UNIT}", desc=f"rm {SYSTEMD_DIR}/{OLD_WEB_UNIT}")
    if host.exists(OLD_WEB_CONFIG) and not host.exists(WEB_CONFIG):
        host.run(f"mv {OLD_WEB_CONFIG} {WEB_CONFIG}", desc=f"mv {OLD_WEB_CONFIG} {WEB_CONFIG}")
        host.run(f"sed -i 's#^data_dir: *{OLD_WEB_DATA_DIR}/*$#data_dir: {WEB_DATA_DIR}#' {WEB_CONFIG}",
                 desc=f"data_dir in {WEB_CONFIG}")
    if host.exists(OLD_WEB_DATA_DIR) and not host.exists(f"{WEB_DATA_DIR}/portal.json"):
        host.run(f"rmdir {WEB_DATA_DIR} 2>/dev/null || true; mv {OLD_WEB_DATA_DIR} {WEB_DATA_DIR}",
                 desc=f"mv {OLD_WEB_DATA_DIR} {WEB_DATA_DIR}")
    return had_old, enabled


def ensure_user(host: Host) -> None:
    host.run(
        f"getent group {WEB_USER} >/dev/null || groupadd --system {WEB_USER}; "
        f"getent passwd {WEB_USER} >/dev/null || useradd --system -g {WEB_USER} "
        f"--no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin {WEB_USER}",
        desc=f"create system user {WEB_USER} unless it exists",
    )



def portal_firewalls(host: Host) -> list[tuple[str, str]]:
    """The firewalls in portitor-manager's configuration on host: (name, URL)
    of `portitor-manager list-firewalls` (portitor-web and web.yaml before
    1.1.0). An older one (before it had a configuration of its own) has no
    such command: the config file's list."""
    binary, config = manager_paths(host)
    proc = host.run(f"runuser -u {WEB_USER} -- {binary} -f {config} list-firewalls",
                    check=False, mutate=False, capture=True, root=True)
    if proc.returncode == 0:
        return [tuple(line.split(None, 1)) for line in (proc.stdout or "").splitlines() if len(line.split(None, 1)) == 2]
    text = host.read(config, root=True) or ""
    return re.findall(r"^\s*-\s*name:\s*(\S+)\s*\n\s*url:\s*[\"']?([^\s\"']+)", text, re.M)



def manager_paths(host: Host) -> tuple[str, str]:
    """The installed manager's binary and config file: portitor-manager's,
    or portitor-web's before 1.1.0."""
    if host.exists(WEB_CONFIG) or not host.exists(OLD_WEB_CONFIG):
        return WEB_BIN, WEB_CONFIG
    return OLD_WEB_BIN, OLD_WEB_CONFIG


def manager_installed(host: Host) -> bool:
    return host.exists(WEB_CONFIG) or host.exists(OLD_WEB_CONFIG)


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
    # Each host keeps its installed release (take_previous) and goes back to
    # it when its update fails, which stops the update there: the hosts
    # before it stay updated, those after it are left alone.
    for agent in plan.agents:
        check_config_reads(agent, roots[archs[agent_key(agent)]] / "portitor-manager", version)
    web_here = plan.web is not None and any(same_host(plan.web, a) for a in plan.agents)
    updated: list[str] = []
    for agent in plan.agents:
        root = roots[archs[agent_key(agent)]]
        kept = take_previous(agent, config=True, manager=web_here and same_host(plan.web, agent))
        try:
            install_agent(agent, root / "portitor-agent", deploy, version, assume_yes)
            install_config(agent, root / "portitor-manager", deploy, version, assume_yes)
        except (InstallError, KeyboardInterrupt) as exc:
            raise restore_after(agent, kept, exc if str(exc) else InstallError("interrupted"), updated) from None
        updated.append(str(agent))
        if agent.name in plan.ha_agents:
            wait_for_ha_peer(agent)
    if plan.web:
        # On a firewall's host, the copy taken with the firewall's.
        kept = web_here or take_previous(plan.web, config=False, manager=True)
        try:
            install_web(plan.web, roots[archs["web"]] / "portitor-manager", deploy, version, assume_yes)
        except (InstallError, KeyboardInterrupt) as exc:
            raise restore_after(plan.web, kept, exc if str(exc) else InstallError("interrupted"), updated) from None
    log("==> Done")


def same_host(a: Host, b: Host) -> bool:
    return a.name == b.name or (a.local and b.local)


def install_config(host: Host, binary: Path, deploy: Path, version: str, assume_yes: bool) -> None:
    """portitor-config on the firewall: the portitor-manager binary run as
    portitor-config, with its own config, certificate, data directory and
    unit, set to deploy to the local agent. A new one is not started: it
    needs an admin."""
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
    set_agent_url(host)
    install_binary(host, binary)
    update_setup(host, deploy)
    if not manager_installed(host):
        # The ISO installs the manager's unit everywhere, disabled.
        migrate_manager(host)
    host.run(f"ln -sfn portitor-manager {shlex.quote(CONFIG_LINK)}", desc=f"ln -s portitor-manager {CONFIG_LINK}")
    install_completion(host, "portitor-config")
    action = install_unit(host, deploy / "systemd" / CONFIG_UNIT, assume_yes)
    host.systemctl("daemon-reload")
    run_config = f"runuser -u {WEB_USER} -- {CONFIG_LINK} -f {CONFIG_FILE}"
    host.run(f"{run_config} migrate", desc="portitor-config migrate")
    if new_config and host.exists(f"{ETC_DIR}/agent.token"):
        # Its own agent, the token read as root and handed over.
        host.run(
            f"fp=$(openssl x509 -in {ETC_DIR}/agent.crt -noout -fingerprint -sha256 | cut -d= -f2 | tr -d :); "
            f"cat {ETC_DIR}/agent.token | {run_config} set-agent --url https://127.0.0.1:8443 "
            f"--token-file - --fingerprint \"$fp\"",
            desc="portitor-config set-agent (the local agent)",
        )
    if new_config and configured_elsewhere(host):
        log("==> portitor-config is installed but not started: this firewall's agent runs a")
        log("    configuration this new portitor-config doesn't have. Restore a backup of it here")
        log("    first. Don't create an admin and commit: a commit from this empty configuration")
        log("    would replace the firewall's configuration.")
        return
    if new_config:
        log("==> portitor-config is installed but not started. Next steps:")
        if not host.exists(f"{ETC_DIR}/agent.token"):
            log(f"    portitor-agent init, then: cat {ETC_DIR}/agent.token | sudo -u {WEB_USER} portitor-config set-agent --token-file - --fingerprint <its fingerprint>")
        log(f"    sudo -u {WEB_USER} portitor-config createadmin admin")
        log(f"    systemctl enable --now {CONFIG_UNIT}")
        log(f"    for portitor-manager: URL https://<this host>:8444, fingerprint: sudo -u {WEB_USER} portitor-config fingerprint")
        return
    if action == "installed":
        host.systemctl("enable", CONFIG_UNIT)
    host.systemctl("restart", CONFIG_UNIT)
    service_healthy(host, CONFIG_UNIT, CONFIG_FILE, "8444")
    verify_version(host, WEB_BIN, version)


def agent_enabled(host: Host) -> bool:
    """True when host runs the agent: the ISO's portitor-manager alone has it
    installed but disabled."""
    return host.run(f"systemctl is-enabled --quiet {AGENT_UNIT}", check=False, mutate=False).returncode == 0


def configured_elsewhere(host: Host) -> bool:
    """True when the agent on host has applied a configuration that its
    portitor-config doesn't have (a new one)."""
    return host.exists(AGENT_APPLIED)


# ---------------------------------------------------------------------------
# what to install where
# ---------------------------------------------------------------------------


def agent_hosts_from_settings(web: Host) -> list[str]:
    """The firewalls portitor-manager on web serves: the hosts of the URLs in the
    portal's configuration (web.yaml's list before it had one), and the HA
    peers their portitor-configs deploy to (`portitor-config agent-url --all` there). One on localhost is the web
    host itself."""
    listed = portal_firewalls(web) if manager_installed(web) else []
    if not listed:
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

    for _name, url in listed:
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
         f"see `portitor show cluster` there")


def make_plan(args: argparse.Namespace) -> Plan:
    web_host: str | None = args.web
    agent_hosts: list[str] = [h for arg in args.agent or [] for h in arg.split(",") if h]
    if args.agent and not agent_hosts:
        raise InstallError("--agent: no host")
    if web_host is None and not agent_hosts:
        # The binary is portitor-config's too: portitor-manager is installed
        # where its config file is.
        if Path(WEB_CONFIG).exists() or Path(OLD_WEB_CONFIG).exists():
            web_host = "localhost"
        elif Path(AGENT_BIN).exists():
            agent_hosts = ["localhost"]
        if web_host is None and not agent_hosts:
            raise InstallError(
                "Portitor is not installed on this host. For a first install pass "
                "--manager [HOST] and/or --agent [HOST]."
            )
    web = Host(web_host, args.ssh_user, args.dry_run) if web_host is not None else None
    if web:
        check_ssh(web)
    if web and not agent_hosts and not args.no_agent:
        agent_hosts = agent_hosts_from_settings(web)
        if agent_hosts:
            log(f"==> portitor-manager's firewalls: {', '.join(agent_hosts)}")
        else:
            log(f"==> No firewalls in {manager_paths(web)[1]}; not updating a firewall")
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
    return Plan(web=web, agents=agents, agent_order_note=note, ha_agents=paired)


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
        out.setdefault(archs["web"], set()).add("portitor-manager")
    for a in plan.agents:
        out.setdefault(archs[agent_key(a)], set()).add("portitor-agent")
    return out


def installed_versions(plan: Plan) -> dict[str, str]:
    out = {}
    if plan.web:
        out["web"] = plan.web.version(manager_paths(plan.web)[0]) or "not installed"
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
    files = ("portitor-manager", "portitor-agent", "deploy/agent.yaml", "deploy/manager.yaml")
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
    raise InstallError(f"{archive.name} does not contain portitor-manager, portitor-agent and deploy/{{agent,manager}}.yaml")


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
    check_upgrade_path(rel.tag, installed)
    log(f"==> Installing {rel.tag}: " + ", ".join(plan.describe()))
    ensure_sudo(plan, args.dry_run)
    check_data_dirs(plan)

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
    needs[local_arch()] = {"portitor-manager", "portitor-agent"}
    for arch, names in needs.items():
        if arch == local_arch():
            continue
        cross = build_dir / f"{ARCHIVE_OS}_{arch}"
        log(f"==> Building {', '.join(sorted(names))} for {arch}")
        if not args.skip_build:
            # release builds the frontend into portitor-manager, as for this host.
            target = "release" if "portitor-manager" in names else "portitor-agent"
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
    proc = subprocess.run([str(build_dir / "portitor-manager"), "--version"], capture_output=True, text=True, check=False)
    version = version_of_output(proc.stdout) or git_describe()

    ensure_sudo(plan, args.dry_run)
    check_data_dirs(plan)
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
                raise InstallError(f"{path} does not contain portitor-manager, portitor-agent and deploy/{{agent,manager}}.yaml")
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
        check_data_dirs(plan)
        install(plan, {local_arch(): root}, archs, root / "deploy", version, args.yes, args.config)
    finally:
        if work:
            shutil.rmtree(work, ignore_errors=True)
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Install or update portitor-manager and portitor-agent.",
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
  ./install.py --install latest --agent fw1,fw2   both firewalls of a cluster, secondary first
  ./install.py --local portitor_1.2.0_linux_amd64.tar.gz --web --agent

Environment:
  GITHUB_TOKEN / GH_TOKEN   token for a private repo (else `gh auth token`)
  SSH_USER                  default for --ssh-user (else portitor)
""",
    )
    what = p.add_argument_group("what to install (default: what is installed on this host)")
    what.add_argument("--manager", "--web", dest="web", nargs="?", const="localhost", metavar="HOST",
                      help="portitor-manager on HOST (default this host); --web until 1.2.0")
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
