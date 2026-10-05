#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 The Portitor contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

# End-to-end test of the installer ISO and the first-boot setup in the QEMU
# virtual machine of iso/vm.sh (make iso-e2e):
#
#   iso/test.sh            build a test ISO (iso/build.sh --test), install, boot, check
#   iso/test.sh ISO        install and check this test ISO
#
# Checks, through the QEMU guest agent and the GUI: the first-boot setup
# finished, the Portitor units run, the LAN has iso/test.answers' address,
# the admin logs in and portitor-web reaches the agent. Logs in build/vm/.
# KEEP=1 leaves the virtual machine running afterwards (GUI on
# https://127.0.0.1:$VM_GUI_PORT/). Needs qemu-system-x86_64 (KVM, else slow),
# python3 and curl.
set -euo pipefail

cd "$(dirname "$0")/.."
DIR=build/vm
export VM_GUI_PORT=${VM_GUI_PORT:-28443}
GUI=https://127.0.0.1:$VM_GUI_PORT
PASSWORD=$(sed -n 's/^password: *//p' iso/test.answers)
LAN_ADDRESS=$(sed -n 's/^address: *//p' iso/test.answers)

log() { printf '\033[1m==> [%dm%02ds] %s\033[0m\n' $((SECONDS / 60)) $((SECONDS % 60)) "$*"; }
fail() { printf '\033[1;31mFAIL: %s\033[0m\n' "$*" >&2; failed=1; }
failed=0

mkdir -p "$DIR"
iso=${1:-}
if [[ -z $iso ]]; then
	iso=$DIR/test.iso
	log "Building the test ISO"
	iso/build.sh --test -o "$iso"
fi

log "Installing (serial console in $DIR/install.log)"
VM_SERIAL=$DIR/install.log timeout 45m iso/vm.sh install "$iso" ||
	{ echo "the install failed or timed out; see $DIR/install.log" >&2; exit 1; }

log "Booting (serial console in $DIR/boot.log)"
VM_SERIAL=$DIR/boot.log iso/vm.sh run 2>/dev/null &
vm=$!
cleanup() { [[ -n ${KEEP:-} ]] || kill "$vm" 2>/dev/null || true; }
trap cleanup EXIT

# guest CMD...: runs CMD in the guest through the QEMU guest agent, prints
# its output and exits with its status (255: no guest agent).
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

log "Checking"
check() {
	local what=$1; shift
	if out=$(guest "$@" 2>&1); then
		echo "ok    $what"
	else
		fail "$what"
		printf '%s\n' "$out" | sed 's/^/      /' >&2
	fi
}
check "first-boot setup did not fail" sh -c '! systemctl is-failed --quiet portitor-firstboot.service'
for unit in portitor-agent portitor-web; do
	check "$unit running" systemctl is-active --quiet "$unit.service"
done
check "no failed units" sh -c 'test -z "$(systemctl list-units --failed --plain --no-legend)" || { systemctl list-units --failed --plain --no-legend; false; }'
check "LAN has $LAN_ADDRESS" sh -c "ip -o addr show | grep -qF ' $LAN_ADDRESS '"
check "nftables firewall table loaded" nft list table inet firewall
check "bind9 from ISC's repository" sh -c "apt-cache policy bind9 | grep -A1 '^ \\*\\*\\*' | grep -qF bind.debian.net"

jar=$DIR/cookies
rm -f "$jar"
deadline=$((SECONDS + 120))
until curl -skf -o /dev/null "$GUI/api/version"; do
	((SECONDS < deadline)) || break
	sleep 3
done
if curl -skf -c "$jar" -o /dev/null -H 'Content-Type: application/json' \
	-d "{\"username\":\"portitor\",\"password\":\"$PASSWORD\"}" "$GUI/api/login"; then
	echo "ok    GUI login"
	if status=$(curl -skf -b "$jar" "$GUI/api/agent/status"); then
		echo "ok    portitor-web reaches the agent"
	else
		fail "GET /api/agent/status"
		echo "      $status" >&2
	fi
else
	fail "GUI login at $GUI"
fi

if ((failed)); then
	log "FAILED (logs in $DIR/)"
	exit 1
fi
log "All checks passed"
[[ -z ${KEEP:-} ]] || echo "The virtual machine keeps running (PID $vm): $GUI/"
