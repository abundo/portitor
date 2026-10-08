#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 The Portitor contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

# End-to-end test of an update from a published release to this tree (make
# iso-e2e-update), in a QEMU virtual machine of iso/vm.sh (build/vm-update):
#
#   iso/test-update.sh          from the latest GitHub release
#   iso/test-update.sh v1.2.0   from this release
#
# Builds a test ISO of the old release (iso/build.sh --release --test),
# installs it and waits for the first-boot setup. Through the GUI's API it
# then runs the update page's check (the old agent and its install.py's
# --list --json) and deploys. The update itself installs this tree's release
# archive with its install.py --local, as a transient unit like the agent's
# update job (a GitHub release is all the GUI can install). Afterwards the
# agent and portitor-web must report this tree's version, the units run, the
# database (migrated) still has its interfaces, the GUI logs in, the new
# agent's check lists the new version installed, and a deploy applies. Logs in
# build/vm-update/. KEEP=1 leaves the virtual machine running. Needs what
# iso/test.sh needs, and gh or curl to reach GitHub.
set -euo pipefail

cd "$(dirname "$0")/.."
DIR=build/vm-update
REPO=${GITHUB_REPO:-abundo/portitor}
export VM_DIR=$DIR VM_GUI_PORT=${VM_GUI_PORT:-28444}
GUI=https://127.0.0.1:$VM_GUI_PORT
PASSWORD=$(sed -n 's/^password: *//p' iso/test.answers)

log() { printf '\033[1m==> [%dm%02ds] %s\033[0m\n' $((SECONDS / 60)) $((SECONDS % 60)) "$*"; }
fail() { printf '\033[1;31mFAIL: %s\033[0m\n' "$*" >&2; failed=1; }
failed=0

from=${1:-}
if [[ -z $from ]]; then
	if command -v gh >/dev/null && { [[ -n ${GH_TOKEN:-}${GITHUB_TOKEN:-} ]] || gh auth status >/dev/null 2>&1; }; then
		from=$(gh release view -R "$REPO" --json tagName -q .tagName)
	else
		from=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" |
			python3 -c 'import json, sys; print(json.load(sys.stdin)["tag_name"])')
	fi
fi
[[ $from == v* ]] || from=v$from

mkdir -p "$DIR"
log "Building the test ISO of $from"
iso/build.sh --release "$from" --test -o "$DIR/from.iso"

# This tree's release archive, as iso/build.sh makes it.
log "Building this tree's release archive"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 make -s release
to=$(build/portitor-agent --version | awk '{ print $NF }')
stage=$(mktemp -d "$DIR/stage.XXXXXX")
trap 'rm -rf "$stage"' EXIT
cp build/portitor-web build/portitor-agent install.py LICENSE README.md "$stage/"
cp -r deploy "$stage/"
tar -czf "$DIR/to.tar.gz" -C "$stage" .
rm -rf "$stage"
log "Updating $from -> $to"

log "Installing $from (serial console in $DIR/install.log)"
VM_SERIAL=$DIR/install.log timeout 45m iso/vm.sh install "$DIR/from.iso" ||
	{ echo "the install failed or timed out; see $DIR/install.log" >&2; exit 1; }

log "Booting (serial console in $DIR/boot.log)"
VM_SERIAL=$DIR/boot.log iso/vm.sh run 2>/dev/null &
vm=$!
cleanup() { [[ -n ${KEEP:-} ]] || kill "$vm" 2>/dev/null || true; }
trap cleanup EXIT

guest() { iso/qga.py "$DIR/qga.sock" "$@"; }

log "Waiting for the first-boot setup"
deadline=$((SECONDS + 1200))
until guest test -e /var/lib/portitor/firstboot.done 2>/dev/null; do
	kill -0 "$vm" 2>/dev/null || { echo "the virtual machine stopped; see $DIR/boot.log" >&2; exit 1; }
	if guest systemctl is-failed --quiet portitor-firstboot.service 2>/dev/null; then
		echo "the first-boot setup failed:" >&2
		guest tail -n 20 /var/log/portitor-setup.log >&2 || true
		exit 1
	fi
	((SECONDS < deadline)) || { echo "no firstboot.done after 20 minutes; see $DIR/boot.log" >&2; exit 1; }
	sleep 10
done

check() {
	local what=$1; shift
	if out=$(guest "$@" 2>&1); then
		echo "ok    $what"
	else
		fail "$what"
		printf '%s\n' "$out" | sed 's/^/      /' >&2
	fi
}
# json EXPR: evaluates the Python expression EXPR on stdin's JSON (j).
json() { python3 -c "import json, sys; j = json.load(sys.stdin); print($1)"; }
jar=$DIR/cookies
api() { curl -skf -b "$jar" "$@"; }
login() {
	local deadline=$((SECONDS + 300))
	until curl -skf -o /dev/null "$GUI/api/version"; do
		((SECONDS < deadline)) || { fail "portitor-web did not answer at $GUI"; return 1; }
		sleep 3
	done
	rm -f "$jar"
	curl -skf -c "$jar" -o /dev/null -H 'Content-Type: application/json' \
		-d "{\"username\":\"portitor\",\"password\":\"$PASSWORD\"}" "$GUI/api/login" ||
		{ fail "GUI login at $GUI"; return 1; }
}
# update_check VERSION: runs the update page's check and expects the agent
# installed at VERSION.
update_check() {
	local want=${1#v} sys deadline=$((SECONDS + 300))
	api -o /dev/null -H 'Content-Type: application/json' -d '{"job":"check"}' "$GUI/api/system/jobs" ||
		{ fail "start the check"; return; }
	while sys=$(api "$GUI/api/system") &&
		[[ $(json '[x["state"] for x in j.get("jobs") or [] if x["name"] == "check"]' <<<"$sys") != "['succeeded']" ]] &&
		[[ $(json '[x["state"] for x in j.get("jobs") or [] if x["name"] == "check"]' <<<"$sys") != "['failed']" ]]; do
		((SECONDS < deadline)) || { fail "the check did not finish"; return; }
		sleep 3
	done
	got=$(json '((j.get("releases") or {}).get("installed") or {}).get("agent", "")' <<<"$sys")
	if [[ ${got#v} == "$want" ]]; then
		echo "ok    update check: agent $got installed, $(json 'len((j.get("releases") or {}).get("releases") or [])' <<<"$sys") releases"
	else
		fail "update check: agent ${got:-?} installed, want $want ($(json 'j.get("releases_error", "")' <<<"$sys"))"
	fi
}
deploy() {
	local out
	if out=$(curl -sk -b "$jar" -w '\n%{http_code}' -H 'Content-Type: application/json' \
		-d '{"confirm_timeout":120}' "$GUI/api/deploy/apply") && [[ ${out##*$'\n'} == 200 ]] &&
		out=$(curl -sk -b "$jar" -w '\n%{http_code}' -H 'Content-Type: application/json' \
			-d '{}' "$GUI/api/deploy/confirm") && [[ ${out##*$'\n'} == 200 ]]; then
		echo "ok    deploy ($1)"
	else
		fail "deploy ($1)"
		printf '%s\n' "$out" | sed 's/^/      /' >&2
	fi
}
versions() {
	local web agent
	web=$(curl -skf "$GUI/api/version" | json 'j["version"]') || web=?
	agent=$(guest portitor-agent --version | awk '{ print $NF }') || agent=?
	if [[ ${web#v} == "${1#v}" && ${agent#v} == "${1#v}" ]]; then
		echo "ok    portitor-web and the agent are $1"
	else
		fail "versions: portitor-web $web, agent $agent, want $1"
	fi
}
units() {
	for unit in portitor-agent portitor-web; do
		check "$unit running" systemctl is-active --quiet "$unit.service"
	done
	check "no failed units" sh -c 'test -z "$(systemctl list-units --failed --plain --no-legend)" || { systemctl list-units --failed --plain --no-legend; false; }'
	check "nftables firewall table loaded" nft list table inet firewall
}

log "Checking $from"
units
login && {
	versions "$from"
	update_check "$from"
	ifaces_before=$(api "$GUI/api/interfaces" | json 'sorted(x["name"] for x in j)')
	deploy "$from"
}
((failed == 0)) || { log "FAILED before the update (logs in $DIR/)"; exit 1; }

log "Updating to $to"
guest /bin/sh -c 'rm -rf /root/portitor-update && mkdir -p /root/portitor-update' >/dev/null
iso/qga.py "$DIR/qga.sock" --put "$DIR/to.tar.gz" /root/portitor-update/portitor.tar.gz ||
	{ echo "cannot copy the release archive into the guest" >&2; exit 1; }
guest tar -xzf /root/portitor-update/portitor.tar.gz -C /root/portitor-update >/dev/null
# A transient unit, as the agent's update job: install.py restarts the agent
# and portitor-web, and the guest agent's command must not be in their way.
guest systemd-run --unit=portitor-test-update.service --property=RemainAfterExit=yes \
	--setenv=DEBIAN_FRONTEND=noninteractive -- \
	python3 /root/portitor-update/install.py --local /root/portitor-update --yes --skip-self-update >/dev/null
deadline=$((SECONDS + 900))
# The guest agent goes away for a moment (none answering reads as running).
while sub=$(guest systemctl show portitor-test-update.service --property=SubState --value 2>/dev/null) || sub=running
	[[ $sub == running || $sub == start* ]]; do
	((SECONDS < deadline)) || { fail "the update did not finish in 15 minutes"; break; }
	sleep 5
done
guest journalctl -u portitor-test-update.service --no-pager -o cat >"$DIR/update.log" 2>&1 || true
if [[ $(guest systemctl show portitor-test-update.service --property=Result --value) == success ]]; then
	echo "ok    install.py --local (output in $DIR/update.log)"
else
	fail "install.py --local; see $DIR/update.log"
	tail -n 20 "$DIR/update.log" | sed 's/^/      /' >&2
fi

log "Checking $to"
units
login && {
	versions "$to"
	ifaces_after=$(api "$GUI/api/interfaces" | json 'sorted(x["name"] for x in j)')
	if [[ $ifaces_after == "$ifaces_before" ]]; then
		echo "ok    interfaces kept: $ifaces_after"
	else
		fail "interfaces: $ifaces_before before, $ifaces_after after"
	fi
	if api -o /dev/null "$GUI/api/agent/status"; then
		echo "ok    portitor-web reaches the agent"
	else
		fail "GET /api/agent/status"
	fi
	update_check "$to"
	deploy "$to"
}

if ((failed)); then
	log "FAILED (logs in $DIR/)"
	exit 1
fi
log "All checks passed: $from -> $to"
[[ -z ${KEEP:-} ]] || echo "The virtual machine keeps running (PID $vm): $GUI/"
