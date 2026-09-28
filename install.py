#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 The Portitor contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Install or update Portitor: portitor-web on this host, portitor-agent on
the firewall (this host, or over SSH).

Binaries go to /usr/bin, systemd units to /etc/systemd/system, example
configs to /etc/portitor (only when missing; web.yaml gets a generated
jwt_secret). If an installed unit differs from this release, the installer
shows a diff and asks before overwriting (--yes overwrites).

An update stops portitor-web, runs `portitor-web migrate` and restarts it,
and restarts portitor-agent (its per-instance units follow). The agent is
updated first: it rejects document fields it does not know, so it must never
be older than portitor-web. On a first install, when a config was just
created, nothing is started; the installer prints the remaining steps.

What gets installed:
  (default)       whatever is installed on this host. When that includes
                  portitor-web, also the agent at the host of the agent URL in
                  its settings (`portitor-web agent-url`).
  --web           portitor-web on this host (plus the agent, as above)
  --agent [HOST]  portitor-agent on HOST (default this host), over SSH as
                  --ssh-user (default portitor, which needs passwordless
                  sudo; the installer prints how to set that up), or root
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
INSTALLER_VERSION = 1
INSTALLER_FILENAME = "install.py"

REPO_DIR = Path(__file__).resolve().parent
REPO_DEFAULT = "abundo/portitor"
USER_AGENT = "portitor-install.py"
ARCHIVE_OS = "linux"

BIN_DIR = "/usr/bin"
WEB_BIN = f"{BIN_DIR}/portitor-web"
AGENT_BIN = f"{BIN_DIR}/portitor-agent"
ETC_DIR = "/etc/portitor"
WEB_CONFIG = f"{ETC_DIR}/web.yaml"
AGENT_CONFIG = f"{ETC_DIR}/agent.yaml"
SYSTEMD_DIR = "/etc/systemd/system"
WEB_USER = "portitor"
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
)
LOCAL_NAMES = {"localhost", "127.0.0.1", "::1", ""}

SELF_UPDATED_ENV = "PORTITOR_INSTALL_SELF_UPDATED"
# Set in the selected release's installer, run by this one: the release is
# already chosen, confirmed, downloaded and extracted (to RELEASE_WORK_ENV).
PINNED_ENV = "PORTITOR_INSTALL_PINNED"
RELEASE_WORK_ENV = "PORTITOR_RELEASE_WORK"


class InstallError(Exception):
    """Fatal, already-formatted error for the CLI."""


def log(msg: str = "") -> None:
    print(msg, flush=True)


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


def ensure_sudo(dry_run: bool) -> None:
    if dry_run or not need_sudo():
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
    ) -> subprocess.CompletedProcess[str]:
        where = "" if self.local else f"{self.name}: "
        if mutate:
            if self.dry_run:
                log(f"    [dry-run] {where}{desc or script}")
                return subprocess.CompletedProcess(script, 0, "", "")
            log(f"    $ {where}{desc or script}")
        with (stdin_file.open("rb") if stdin_file else open(os.devnull, "rb")) as stdin:
            proc = subprocess.run(
                self.argv(script, root=mutate),
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

    def read(self, path: str) -> str | None:
        proc = self.run(f"cat {shlex.quote(path)}", check=False, mutate=False, capture=True)
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
    agent: Host | None

    def describe(self) -> list[str]:
        out = []
        if self.agent:
            out.append(f"portitor-agent on {self.agent}")
        if self.web:
            out.append(f"portitor-web on {self.web}")
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
    actions = {u: install_unit(host, deploy / "systemd" / u, assume_yes) for u in AGENT_UNITS}
    host.systemctl("daemon-reload")
    if new_config:
        on = "" if host.local else f" (on {host.name})"
        log(f"==> portitor-agent is installed but not started. Next steps{on}:")
        log("    install nftables, iproute2, wireguard-tools, bind9, kea-dhcp4-server,")
        log("      kea-dhcp6-server and radvd (or your distribution's equivalents)")
        log("    portitor-agent init --host <management address>   # token + fingerprint for the GUI")
        log(f"    $EDITOR {AGENT_CONFIG}                     # listen, allow_from, bind_user")
        log("    systemctl disable --now named kea-dhcp4-server kea-dhcp6-server radvd")
        log("    remove the firewall's interfaces from netplan, NetworkManager or systemd-networkd")
        log("      (a second DHCP client on the WAN keeps the agent from getting a lease)")
        log(f"    systemctl enable --now {AGENT_UNIT}")
        return
    if actions[AGENT_UNIT] == "installed":
        host.systemctl("enable", AGENT_UNIT)
    host.systemctl("restart", AGENT_UNIT)
    if not host.dry_run:
        time.sleep(2)
        if host.run(f"systemctl is-active --quiet {AGENT_UNIT}", check=False, mutate=False).returncode:
            warn(f"{AGENT_UNIT} is not running on {host}; see journalctl -u {AGENT_UNIT}")
    verify_version(host, AGENT_BIN, version)


def install_web(host: Host, binary: Path, deploy: Path, version: str, assume_yes: bool) -> None:
    log(f"==> Installing portitor-web {version} on {host}")
    host.run(
        f"getent group {WEB_USER} >/dev/null || groupadd --system {WEB_USER}; "
        f"getent passwd {WEB_USER} >/dev/null || useradd --system -g {WEB_USER} "
        f"--no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin {WEB_USER}",
        desc=f"create system user {WEB_USER} unless it exists",
    )
    new_config = not host.exists(WEB_CONFIG)
    if new_config:
        example = (deploy / "web.yaml").read_text(encoding="utf-8")
        secret = secrets.token_urlsafe(32)
        text = example.replace("jwt_secret: CHANGE-ME", f'jwt_secret: "{secret}"')
        # The service runs as portitor; the file holds the database password.
        host.put_text(text, WEB_CONFIG, "0640", group=WEB_USER)
    # Migrations must not run under a serving GUI. The unit is missing on a
    # first install, hence no check.
    host.run(f"systemctl stop {WEB_UNIT} 2>/dev/null || true", desc=f"systemctl stop {WEB_UNIT}")
    host.put(binary, WEB_BIN, "0755")
    action = install_unit(host, deploy / "systemd" / WEB_UNIT, assume_yes)
    host.systemctl("daemon-reload")
    if new_config:
        log("==> portitor-web is installed but not started. Next steps:")
        log("    create a PostgreSQL role and database for portitor")
        log(f"    $EDITOR {WEB_CONFIG}      # db settings (jwt_secret is generated)")
        log("    portitor-web migrate")
        log("    portitor-web createadmin admin")
        log(f"    systemctl enable --now {WEB_UNIT}")
        return
    host.run(f"{WEB_BIN} -f {WEB_CONFIG} migrate", desc="portitor-web migrate")
    if action == "installed":
        host.systemctl("enable", WEB_UNIT)
    host.systemctl("restart", WEB_UNIT)
    verify_version(host, WEB_BIN, version)


def install(
    plan: Plan, roots: dict[str, Path], archs: dict[str, str], deploy: Path, version: str, assume_yes: bool
) -> None:
    """roots: arch -> directory with the binaries. deploy: units and example configs."""
    # The agent first: it rejects fields it does not know, so it must never
    # be older than the GUI that deploys to it.
    if plan.agent:
        install_agent(plan.agent, roots[archs["agent"]] / "portitor-agent", deploy, version, assume_yes)
    if plan.web:
        install_web(plan.web, roots[archs["web"]] / "portitor-web", deploy, version, assume_yes)
    log("==> Done")


# ---------------------------------------------------------------------------
# what to install where
# ---------------------------------------------------------------------------


def agent_host_from_settings() -> str | None:
    """Host part of the agent URL in the installed portitor-web's settings."""
    if not (Path(WEB_BIN).exists() and Path(WEB_CONFIG).exists()):
        return None
    cmd = (["sudo"] if need_sudo() else []) + [WEB_BIN, "-f", WEB_CONFIG, "agent-url"]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=30)
    if proc.returncode != 0:
        raise InstallError(
            "could not read the agent URL from portitor-web's settings: "
            f"{(proc.stderr or proc.stdout).strip()}\n"
            "Pass --agent HOST, or --no-agent to update portitor-web alone."
        )
    url = proc.stdout.strip()
    if not url:
        return None
    host = urllib.parse.urlsplit(url).hostname
    if not host:
        raise InstallError(f"cannot find a host in the agent URL {url!r}; pass --agent HOST")
    return host


def make_plan(args: argparse.Namespace) -> Plan:
    web = args.web
    agent_host: str | None = args.agent
    if not web and agent_host is None:
        web = Path(WEB_BIN).exists()
        if not web and Path(AGENT_BIN).exists():
            agent_host = "localhost"
        if not web and agent_host is None:
            raise InstallError(
                "Portitor is not installed on this host. For a first install pass "
                "--web and/or --agent [HOST]."
            )
    if web and agent_host is None and not args.no_agent:
        agent_host = agent_host_from_settings()
        if agent_host:
            log(f"==> Agent from portitor-web's settings: {agent_host}")
        else:
            log("==> No agent URL in portitor-web's settings; not updating an agent")
    if args.no_agent:
        agent_host = None
    elif web and agent_host is None and Path(AGENT_BIN).exists():
        agent_host = "localhost"
    if not web and agent_host is None:
        raise InstallError("nothing to install")
    return Plan(
        web=Host("localhost", args.ssh_user, args.dry_run) if web else None,
        agent=Host(agent_host, args.ssh_user, args.dry_run) if agent_host else None,
    )


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


def plan_archs(plan: Plan) -> dict[str, str]:
    archs = {"web": local_arch(), "agent": local_arch()}
    if plan.agent and not plan.agent.local:
        try:
            archs["agent"] = plan.agent.arch()
        except InstallError as exc:
            raise InstallError(
                f"cannot reach {plan.agent.name} over SSH as {plan.agent.ssh_user} "
                f"with {'root' if plan.agent.ssh_user == 'root' else 'passwordless sudo'}: {exc}\n\n"
                + ssh_setup_help(plan.agent.name, plan.agent.ssh_user)
            ) from exc
    return archs


def installed_versions(plan: Plan) -> dict[str, str]:
    out = {}
    if plan.web:
        out["web"] = plan.web.version(WEB_BIN) or "not installed"
    if plan.agent:
        out["agent"] = plan.agent.version(AGENT_BIN) or "not installed"
    return out


def primary_version(installed: dict[str, str]) -> str:
    return installed.get("web") or installed.get("agent") or "not installed"


def summary_lines(plan: Plan, installed: dict[str, str]) -> list[str]:
    lines = []
    if plan.agent:
        lines.append(f"agent  {installed.get('agent', '?'):<22} {plan.agent}")
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

    def archive(self, arch: str) -> Asset | None:
        suffix = f"_{ARCHIVE_OS}_{arch}.tar.gz"
        return next((a for a in self.assets if a.name.endswith(suffix)), None)

    def checksums(self) -> Asset | None:
        return next((a for a in self.assets if a.name.endswith("_checksums.txt")), None)


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
    return (path / "portitor-web").is_file() and (path / "portitor-agent").is_file() and (path / "deploy").is_dir()


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
    raise InstallError(f"{archive.name} does not contain portitor-web, portitor-agent and deploy/")


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
    return next((r for r in releases if include_pre or not r.prerelease), None)


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
        newer = sum(1 for r in releases if version_newer(r.tag, cur) and not r.prerelease)
        idx = next((i for i, r in enumerate(releases) if version_newer(r.tag, cur) and not r.prerelease), None)
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
    needed = {archs[k] for k, h in (("web", plan.web), ("agent", plan.agent)) if h}
    installed = installed_versions(plan)
    cur = primary_version(installed)

    token = github_token()
    client = GithubClient(args.repo, token)
    log(f"==> Fetching releases from {args.repo}" + ("" if token else " (no GitHub token)"))
    releases = client.list_releases(args.limit)
    if not releases:
        raise InstallError(f"{args.repo} has no releases")
    newer = [r for r in releases if version_newer(r.tag, cur) and (args.pre or not r.prerelease)]

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
    log(f"==> Installing {rel.tag}: " + ", ".join(plan.describe()))
    ensure_sudo(args.dry_run)

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
        install(plan, roots, archs, any_root / "deploy", rel.tag, args.yes)
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
    if plan.agent and archs["agent"] != local_arch():
        arch = archs["agent"]
        cross = build_dir / f"{ARCHIVE_OS}_{arch}"
        log(f"==> Building portitor-agent for {plan.agent.name} ({arch})")
        if not args.skip_build:
            build(["make", "portitor-agent", f"BUILD_DIR={cross.relative_to(REPO_DIR)}"],
                  {"CGO_ENABLED": "0", "GOOS": ARCHIVE_OS, "GOARCH": arch}, args.dry_run)
        roots[arch] = cross
    for arch, root in roots.items():
        for name in ("portitor-web", "portitor-agent"):
            if not (root / name).is_file():
                if args.dry_run:
                    log(f"==> Dry run: {root / name} is not built yet, so nothing more to show")
                    return 0
                raise InstallError(f"{root / name} is missing; run without --skip-build")
    # Stamped into the binary; with a dry run or --skip-build, that is build/'s.
    proc = subprocess.run([str(build_dir / "portitor-web"), "--version"], capture_output=True, text=True, check=False)
    version = version_of_output(proc.stdout) or git_describe()

    ensure_sudo(args.dry_run)
    install(plan, roots, archs, REPO_DIR / "deploy", version, args.yes)
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

Environment:
  GITHUB_TOKEN / GH_TOKEN   token for a private repo (else `gh auth token`)
  SSH_USER                  default for --ssh-user (else portitor)
""",
    )
    what = p.add_argument_group("what to install (default: what is installed on this host)")
    what.add_argument("--web", action="store_true", help="portitor-web on this host")
    what.add_argument("--agent", nargs="?", const="localhost", metavar="HOST",
                      help="portitor-agent on HOST (default this host)")
    what.add_argument("--no-agent", action="store_true", help="never install or update the agent")
    what.add_argument("--ssh-user", default=os.environ.get("SSH_USER", SSH_USER_DEFAULT),
                      help="SSH user for a remote agent: root, or a user with passwordless sudo "
                           f"(default {SSH_USER_DEFAULT})")
    src = p.add_argument_group("where from")
    src.add_argument("--source", action="store_true", help="build and install this source tree")
    src.add_argument("--skip-build", action="store_true", help="with --source, use build/ as it is")
    src.add_argument("--list", action="store_true", help="print GitHub releases and exit")
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
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.no_agent and args.agent is not None:
        raise InstallError("--agent and --no-agent exclude each other")
    if args.skip_build and not args.source:
        raise InstallError("--skip-build needs --source")
    if args.source and (args.list or args.install or args.self_update):
        raise InstallError("--source cannot be combined with --list, --install or --self-update")
    if args.self_update and args.skip_self_update:
        raise InstallError("--self-update and --skip-self-update exclude each other")
    if args.source:
        return main_source(args)
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
