#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 The Portitor contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

# End-to-end test of an update of the split setup from a published release to
# this tree (make iso-e2e-split-update), in two QEMU virtual machines of
# iso/vm.sh as iso/test-split.sh has them:
#
#   iso/test-split-update.sh          from the latest GitHub release
#   iso/test-split-update.sh v0.6.1   from this release
#
#   build/vm-sup-fw   role agent  (iso/test-split-fw.answers), LAN 192.168.1.1
#   build/vm-sup-web  role web    (iso/test-split-web.answers), 192.168.1.10
#
# Builds the old release's two test ISOs with that release's own iso/ files,
# installs and boots both, joins the firewall as that release does, and
# deploys through portitor-web. Then the web VM gets SSH as root to the
# firewall and runs this tree's install.py --local there, as a transient unit,
# with no host given: it must find the firewall in portitor-web's database,
# update it first and move the database to its portitor-config, and make
# portitor-web the portal to it. Afterwards: the versions, the units, the
# database moved (the interfaces kept), the GUI login through the portal at
# /fw/fw/, portitor-config reaching its agent and a deploy. Logs in
# build/vm-sup-*. KEEP=1 leaves the virtual machines running. Needs what
# iso/test-split.sh needs, and gh or curl to reach GitHub.
set -euo pipefail
cd "$(dirname "$0")/.."
REPO=${GITHUB_REPO:-abundo/portitor}
PASSWORD=$(sed -n 's/^password: *//p' iso/test-split-web.answers)

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

# vm NAME CMD...: iso/vm.sh for the firewall (fw) or portitor-web (web).
vm() {
	local name=$1; shift
	local id=1 other=web
	[[ $name == fw ]] || id=2 other=fw
	VM_DIR=build/vm-sup-$name VM_ID=$id \
		VM_LAN="build/vm-sup-$name/lan.sock,build/vm-sup-$other/lan.sock" iso/vm.sh "$@"
}
# guest NAME CMD...: runs CMD in that virtual machine (iso/qga.py).
guest() { local name=$1; shift; iso/qga.py "build/vm-sup-$name/qga.sock" "$@"; }
put() { iso/qga.py "build/vm-sup-$1/qga.sock" --put "$2" "$3"; }

# The old release's ISOs, built with its own iso/ files: this tree's
# first-boot setup runs commands an old release does not have.
old=$(mktemp -d build/sup-old.XXXXXX)
trap 'rm -rf "$old"' EXIT
git archive "$from" | tar -x -C "$old"
for name in fw web; do
	mkdir -p "build/vm-sup-$name"
	log "Building the $name test ISO of $from"
	(cd "$old" && iso/build.sh --release "$from" --answers "iso/test-split-$name.answers" \
		-o "$OLDPWD/build/vm-sup-$name/from.iso")
done

# This tree's release archive, as iso/build.sh makes it.
log "Building this tree's release archive"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 make -s release
to=$(build/portitor-agent --version | awk '{ print $NF }')
stage=$(mktemp -d build/sup-stage.XXXXXX)
cp build/portitor-web build/portitor-agent install.py LICENSE README.md "$stage/"
cp -r deploy "$stage/"
tar -czf build/vm-sup-web/to.tar.gz -C "$stage" .
rm -rf "$stage" "$old"
log "Updating $from -> $to"

log "Installing both (serial consoles in build/vm-sup-{fw,web}/install.log)"
pids=()
for name in fw web; do
	VM_SERIAL=build/vm-sup-$name/install.log timeout 45m bash -c "$(declare -f vm); vm $name install build/vm-sup-$name/from.iso" &
	pids+=($!)
done
for i in 0 1; do
	wait "${pids[i]}" || { echo "an install failed or timed out; see build/vm-sup-*/install.log" >&2; exit 1; }
done

log "Booting both (serial consoles in build/vm-sup-{fw,web}/boot.log)"
declare -A pid
for name in fw web; do
	VM_SERIAL=build/vm-sup-$name/boot.log vm "$name" run 2>/dev/null &
	pid[$name]=$!
done
cleanup() { [[ -n ${KEEP:-} ]] || kill "${pid[@]}" 2>/dev/null || true; }
trap cleanup EXIT

log "Waiting for the first-boot setups"
deadline=$((SECONDS + 1200))
for name in fw web; do
	until guest "$name" test -e /var/lib/portitor/firstboot.done 2>/dev/null; do
		kill -0 "${pid[$name]}" 2>/dev/null || { echo "the $name virtual machine stopped; see build/vm-sup-$name/boot.log" >&2; exit 1; }
		if guest "$name" systemctl is-failed --quiet portitor-firstboot.service 2>/dev/null; then
			echo "the first-boot setup failed in $name:" >&2
			guest "$name" tail -n 20 /var/log/portitor-setup.log >&2 || true
			exit 1
		fi
		((SECONDS < deadline)) || { echo "no firstboot.done in $name after 20 minutes; see build/vm-sup-$name/boot.log" >&2; exit 1; }
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

# The GUI's API from inside the web VM (python3: curl may not be installed):
# gui BASE get PATH prints the answer, gui BASE deploy applies and confirms.
cat >build/vm-sup-web/gui.py <<'EOF'
import http.cookiejar, json, ssl, sys, time, urllib.request
base, password, action = sys.argv[1:4]
ctx = ssl.create_default_context()
ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
op = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx),
                                 urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
def call(path, body=None):
    data = None if body is None else json.dumps(body).encode()
    return op.open(urllib.request.Request(base + path, data, {"Content-Type": "application/json"}), timeout=60).read().decode()
for i in range(60):
    try:
        call("/api/login", {"username": "portitor", "password": password})
        break
    except Exception as e:
        if i == 59:
            sys.exit(f"login at {base}: {e}")
        time.sleep(5)
if action == "get":
    print(call(sys.argv[4]))
elif action == "deploy":
    call("/api/deploy/apply", {"confirm_timeout": 120})
    call("/api/deploy/confirm", {})
EOF
put web build/vm-sup-web/gui.py /root/gui.py >/dev/null
gui() { guest web python3 /root/gui.py "$1" "$PASSWORD" "${@:2}"; }
names() { python3 -c 'import json, sys; print(sorted(x["name"] for x in json.load(sys.stdin)))'; }

log "Joining the firewall ($from)"
join=$(guest fw portitor-setup --show-join | grep -o 'portitor-join:[A-Za-z0-9_-]*') ||
	{ echo "no join string from portitor-setup --show-join on fw" >&2; exit 1; }
check web "portitor-web bootstrap --join" \
	runuser -u portitor -- portitor-web -f /etc/portitor/web.yaml bootstrap --join "$join"
ifaces_before=$(gui https://127.0.0.1 get /api/interfaces | names) || fail "interfaces before the update"
check web "deploy ($from)" python3 /root/gui.py https://127.0.0.1 "$PASSWORD" deploy
((failed == 0)) || { log "FAILED before the update (logs in build/vm-sup-*/)"; exit 1; }

log "SSH from the web VM to the firewall as root"
guest web sh -c 'mkdir -p -m 0700 /root/.ssh && { test -e /root/.ssh/id_ed25519 || ssh-keygen -q -t ed25519 -N "" -f /root/.ssh/id_ed25519; } &&
	ssh-keyscan -t ed25519 192.168.1.1 >>/root/.ssh/known_hosts 2>/dev/null' >/dev/null
guest web cat /root/.ssh/id_ed25519.pub >build/vm-sup-web/id.pub
guest fw mkdir -p -m 0700 /root/.ssh >/dev/null
put fw build/vm-sup-web/id.pub /root/.ssh/authorized_keys >/dev/null
# The guest agent creates files writable by all, which sshd ignores.
guest fw chmod 0600 /root/.ssh/authorized_keys >/dev/null
check web "ssh root@192.168.1.1" ssh -o BatchMode=yes root@192.168.1.1 true

log "Updating to $to (install.py on the web VM)"
guest web sh -c 'rm -rf /root/portitor-update && mkdir -p /root/portitor-update' >/dev/null
put web build/vm-sup-web/to.tar.gz /root/portitor-update/portitor.tar.gz ||
	{ echo "cannot copy the release archive into the web VM" >&2; exit 1; }
guest web tar -xzf /root/portitor-update/portitor.tar.gz -C /root/portitor-update >/dev/null
guest web systemd-run --unit=portitor-test-update.service --property=RemainAfterExit=yes \
	--setenv=DEBIAN_FRONTEND=noninteractive -- \
	python3 /root/portitor-update/install.py --local /root/portitor-update --yes --skip-self-update --ssh-user root >/dev/null
deadline=$((SECONDS + 900))
while sub=$(guest web systemctl show portitor-test-update.service --property=SubState --value 2>/dev/null) || sub=running
	[[ $sub == running || $sub == start* ]]; do
	((SECONDS < deadline)) || { fail "the update did not finish in 15 minutes"; break; }
	sleep 5
done
guest web journalctl -u portitor-test-update.service --no-pager -o cat >build/vm-sup-web/update.log 2>&1 || true
if [[ $(guest web systemctl show portitor-test-update.service --property=Result --value) == success ]]; then
	echo "ok    install.py --local (output in build/vm-sup-web/update.log)"
else
	fail "install.py --local; see build/vm-sup-web/update.log"
	tail -n 20 build/vm-sup-web/update.log | sed 's/^/      /' >&2
fi

log "Checking $to"
for bin in fw:portitor-agent web:portitor-web fw:portitor-web; do
	got=$(guest "${bin%%:*}" "${bin#*:}" --version | awk '{ print $NF }') || got=?
	if [[ ${got#v} == "${to#v}" ]]; then
		echo "ok    ${bin%%:*}: ${bin#*:} $got"
	else
		fail "${bin%%:*}: ${bin#*:} ${got:-?}, want $to"
	fi
done
for name in fw web; do
	check "$name" "no failed units" sh -c 'test -z "$(systemctl list-units --failed --plain --no-legend)" || { systemctl list-units --failed --plain --no-legend; false; }'
done
check fw "portitor-agent running" systemctl is-active --quiet portitor-agent.service
check fw "portitor-config running" systemctl is-active --quiet portitor-config.service
check fw "the database moved in" test -s /var/lib/portitor-config/portitor.db
check fw "portitor-web trusted (trusted_proxies)" grep -q '^trusted_proxies:.*192\.168\.1\.10' /etc/portitor/config.yaml
check fw "nftables firewall table loaded" nft list table inet firewall
check web "portitor-web running" systemctl is-active --quiet portitor-web.service
check web "the old database set aside" test -e /var/lib/portitor-web/portitor.db.moved-to-portitor-config
check web "web.yaml lists the firewall" grep -q 'url: https://192.168.1.1:8444' /etc/portitor/web.yaml
portal=https://127.0.0.1/fw/fw
if ifaces_after=$(gui "$portal" get /api/interfaces | names) && [[ $ifaces_after == "$ifaces_before" ]]; then
	echo "ok    interfaces kept through the portal: $ifaces_after"
else
	fail "interfaces: $ifaces_before before, ${ifaces_after:-none} after"
fi
check web "portitor-config reaches its agent" python3 /root/gui.py "$portal" "$PASSWORD" get /api/agent/status
check web "deploy ($to)" python3 /root/gui.py "$portal" "$PASSWORD" deploy

if ((failed)); then
	log "FAILED (logs in build/vm-sup-fw/ and build/vm-sup-web/)"
	exit 1
fi
log "All checks passed: $from -> $to, split"
[[ -z ${KEEP:-} ]] || echo "The virtual machines keep running (PIDs ${pid[fw]} ${pid[web]})"
