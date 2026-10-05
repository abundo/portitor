#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 The Portitor contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

# End-to-end test of the split setup (make iso-e2e-split): the agent and
# portitor-web in two QEMU virtual machines of iso/vm.sh, on a LAN of their
# own (a link between their second NICs):
#
#   build/vm-fw   role agent  (iso/test-split-fw.answers), LAN 192.168.1.1
#   build/vm-web  role web    (iso/test-split-web.answers), 192.168.1.10
#
# Builds a test ISO for each, installs both at once and boots them. When both
# first-boot setups have finished, portitor-web joins the firewall with the
# join string `portitor-setup --show-join` prints on it (as `portitor-setup
# --join` would), and the checks run through the QEMU guest agents: the units
# of each role, the firewall's LAN address and ruleset, and from the web VM
# the GUI login and portitor-web reaching the agent across the LAN. Logs in
# build/vm-fw and build/vm-web. KEEP=1 leaves the virtual machines running.
# Needs what iso/test.sh needs, and QEMU 7.2 or later (datagram sockets).
set -euo pipefail

cd "$(dirname "$0")/.."
PASSWORD=$(sed -n 's/^password: *//p' iso/test-split-web.answers)

log() { printf '\033[1m==> [%dm%02ds] %s\033[0m\n' $((SECONDS / 60)) $((SECONDS % 60)) "$*"; }
fail() { printf '\033[1;31mFAIL: %s\033[0m\n' "$*" >&2; failed=1; }
failed=0

# vm NAME CMD...: iso/vm.sh for the firewall (fw) or portitor-web (web).
vm() {
	local name=$1; shift
	local id=1 other=web
	[[ $name == fw ]] || id=2 other=fw
	VM_DIR=build/vm-$name VM_ID=$id \
		VM_LAN="build/vm-$name/lan.sock,build/vm-$other/lan.sock" iso/vm.sh "$@"
}
# guest NAME CMD...: runs CMD in that virtual machine (iso/qga.py).
guest() { local name=$1; shift; iso/qga.py "build/vm-$name/qga.sock" "$@"; }

for name in fw web; do
	mkdir -p "build/vm-$name"
	log "Building the $name test ISO"
	iso/build.sh --answers "iso/test-split-$name.answers" -o "build/vm-$name/test.iso"
done

log "Installing both (serial consoles in build/vm-{fw,web}/install.log)"
pids=()
for name in fw web; do
	VM_SERIAL=build/vm-$name/install.log timeout 45m bash -c "$(declare -f vm); vm $name install build/vm-$name/test.iso" &
	pids+=($!)
done
for i in 0 1; do
	wait "${pids[i]}" || { echo "an install failed or timed out; see build/vm-*/install.log" >&2; exit 1; }
done

log "Booting both (serial consoles in build/vm-{fw,web}/boot.log)"
declare -A pid
for name in fw web; do
	VM_SERIAL=build/vm-$name/boot.log vm "$name" run 2>/dev/null &
	pid[$name]=$!
done
cleanup() { [[ -n ${KEEP:-} ]] || kill "${pid[@]}" 2>/dev/null || true; }
trap cleanup EXIT

log "Waiting for the first-boot setups"
deadline=$((SECONDS + 1200))
for name in fw web; do
	until guest "$name" test -e /var/lib/portitor/firstboot.done 2>/dev/null; do
		kill -0 "${pid[$name]}" 2>/dev/null || { echo "the $name virtual machine stopped; see build/vm-$name/boot.log" >&2; exit 1; }
		if guest "$name" systemctl is-failed --quiet portitor-firstboot.service 2>/dev/null; then
			echo "the first-boot setup failed in $name:" >&2
			guest "$name" tail -n 20 /var/log/portitor-setup.log >&2 || true
			exit 1
		fi
		((SECONDS < deadline)) || { echo "no firstboot.done in $name after 20 minutes; see build/vm-$name/boot.log" >&2; exit 1; }
		sleep 10
	done
done

check() {
	local name=$1 what=$2; shift 2
	if out=$(guest "$name" "$@" 2>&1); then
		echo "ok    $name: $what"
	else
		fail "$name: $what"
		printf '%s\n' "$out" | sed 's/^/      /' >&2
	fi
}

log "Joining the firewall"
join=$(guest fw portitor-setup --show-join | grep -o 'portitor-join:[A-Za-z0-9_-]*') ||
	{ echo "no join string from portitor-setup --show-join on fw" >&2; exit 1; }
check web "portitor-web bootstrap --join" \
	runuser -u portitor -- portitor-web -f /etc/portitor/web.yaml bootstrap --join "$join"

log "Checking"
for name in fw web; do
	check "$name" "first-boot setup did not fail" sh -c '! systemctl is-failed --quiet portitor-firstboot.service'
	check "$name" "no failed units" sh -c 'test -z "$(systemctl list-units --failed --plain --no-legend)" || { systemctl list-units --failed --plain --no-legend; false; }'
done
check fw "portitor-agent running" systemctl is-active --quiet portitor-agent.service
check fw "portitor-web not running" sh -c '! systemctl is-active --quiet portitor-web.service'
check fw "LAN has 192.168.1.1/24" sh -c "ip -o addr show | grep -qF ' 192.168.1.1/24 '"
check fw "nftables firewall table loaded" nft list table inet firewall
check web "portitor-web running" systemctl is-active --quiet portitor-web.service
check web "portitor-agent not running" sh -c '! systemctl is-active --quiet portitor-agent.service'
check web "the firewall answers on the LAN" ping -c 3 -W 2 192.168.1.1
# The GUI from inside the web VM (python3: curl may not be installed).
check web "GUI login, and portitor-web reaches the agent" python3 -c '
import http.cookiejar, json, ssl, sys, urllib.request
ctx = ssl.create_default_context()
ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
op = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx),
                                 urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
gui = "https://127.0.0.1"
op.open(urllib.request.Request(gui + "/api/login", json.dumps({"username": "portitor", "password": sys.argv[1]}).encode(),
                               {"Content-Type": "application/json"}), timeout=10).close()
print(op.open(gui + "/api/agent/status", timeout=30).read().decode()[:500])
' "$PASSWORD"

if ((failed)); then
	log "FAILED (logs in build/vm-fw/ and build/vm-web/)"
	exit 1
fi
log "All checks passed"
[[ -z ${KEEP:-} ]] || echo "The virtual machines keep running (PIDs ${pid[fw]} ${pid[web]})"
