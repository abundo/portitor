#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 The Portitor contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

# Two-container lab for trying a real apply (see DEV.md, "Lab"). Rootless
# podman, systemd inside each container:
#
#   fwlab-fw    portitor-agent as root, not dry-run. eth0 WAN (DHCP from mgmt),
#               eth1 LAN 192.168.1.1/24, eth2 guest.
#   fwlab-mgmt  portitor-web on lan0 192.168.1.2, GUI published on
#               http://127.0.0.1:$LAB_WEB_PORT. Also the ISP: DHCP and NAT on
#               wan0 198.51.100.1/24.
#
#   dev/lab/lab.sh up        build images and binaries, start, install
#   dev/lab/lab.sh install   rebuild binaries and reinstall (after code changes)
#   dev/lab/lab.sh seed      the dev/seed.sh network (login admin / admin)
#   dev/lab/lab.sh deploy    apply and confirm
#   dev/lab/lab.sh client    throwaway shell on the LAN that got a DHCP lease
#   dev/lab/lab.sh shell fw|mgmt
#   dev/lab/lab.sh logs  fw|mgmt
#   dev/lab/lab.sh down      remove containers and networks
#   dev/lab/lab.sh clean     down, and remove the images
set -euo pipefail

cd "$(dirname "$0")/../.."
LAB=dev/lab
RT=podman
# LAB_PREFIX names the containers and networks, so a second lab can run beside one.
PREFIX=${LAB_PREFIX:-fwlab}
WEB_PORT=${LAB_WEB_PORT:-28080}
URL=http://127.0.0.1:$WEB_PORT
ADMIN_PASS=admin
# bcrypt of "admin". portitor-web requires 10+ characters, so the lab user is
# created with a throwaway password and this hash is written over it.
ADMIN_HASH='$2a$10$JDdXPU6gxUFuW8OxWw/ALejgfEkZ4sGpwIM86YY2rHeiEtkXiGMYW'

NETWORKS=(wan lan guest)

log() { printf '\033[1m==> %s\033[0m\n' "$*"; }
ex() { $RT exec "$PREFIX-$1" "${@:2}"; }

cmd_image() {
	log "building images"
	$RT build -q --target fw -t "$PREFIX-fw" $LAB >/dev/null
	$RT build -q --target mgmt -t "$PREFIX-mgmt" $LAB >/dev/null
}

cmd_networks() {
	# No IPAM: the agent (and mgmt's portitor-lab-net.service) own the
	# addresses, as they would on real hardware.
	for n in "${NETWORKS[@]}"; do
		$RT network exists "$PREFIX-$n" ||
			$RT network create --internal --ipam-driver none "$PREFIX-$n" >/dev/null
	done
}

run() { # name args...
	if $RT container exists "$PREFIX-$1"; then
		$RT start "$PREFIX-$1" >/dev/null
		return
	fi
	# --privileged is scoped to the rootless user namespace: enough for
	# netns, nftables and sysctls in the container's own network namespace.
	$RT run -d --name "$PREFIX-$1" --hostname "$1" --privileged --systemd=always "${@:2}" "$PREFIX-$1" >/dev/null
}

cmd_start() {
	cmd_networks
	log "starting containers"
	run mgmt --network podman:interface_name=eth0 \
		--network "$PREFIX-wan:interface_name=wan0" --network "$PREFIX-lan:interface_name=lan0" \
		--sysctl net.ipv4.ip_forward=1 -p "127.0.0.1:$WEB_PORT:8080"
	run fw --network "$PREFIX-wan:interface_name=eth0" --network "$PREFIX-lan:interface_name=eth1" \
		--network "$PREFIX-guest:interface_name=eth2"
	for c in mgmt fw; do
		# "degraded" is fine: some units don't make sense in a container.
		ex $c systemctl is-system-running --wait >/dev/null || true
	done
}

cmd_install() {
	log "building binaries"
	CGO_ENABLED=0 make -s release >/dev/null

	log "installing portitor-agent on fw"
	$RT cp build/portitor-agent "$PREFIX-fw:/usr/bin/portitor-agent"
	for u in portitor-agent.service portitor-named@.service portitor-kea4@.service portitor-kea6@.service portitor-radvd@.service portitor-frr@.service; do
		$RT cp "deploy/systemd/$u" "$PREFIX-fw:/etc/systemd/system/$u"
	done
	ex fw sh -c 'test -e /etc/portitor/agent.token ||
		portitor-agent init --host 192.168.1.1 >/dev/null'
	ex fw systemctl daemon-reload
	ex fw systemctl enable portitor-agent.service
	ex fw systemctl restart portitor-agent.service

	log "installing portitor-web on mgmt"
	$RT cp build/portitor-web "$PREFIX-mgmt:/usr/bin/portitor-web"
	$RT cp deploy/systemd/portitor-web.service "$PREFIX-mgmt:/etc/systemd/system/portitor-web.service"
	# Wiregasm for the packet capture viewer: install.py downloads it, the
	# lab takes the frontend's npm copy.
	ex mgmt install -d /usr/share/portitor/wiregasm
	for f in wiregasm.js wiregasm.wasm.gz wiregasm.data.gz; do
		$RT cp "web/frontend/node_modules/@goodtools/wiregasm/dist/$f" "$PREFIX-mgmt:/usr/share/portitor/wiregasm/$f"
	done
	ex mgmt install -d -o portitor -g portitor -m 0700 /var/lib/portitor-web
	ex mgmt runuser -u portitor -- portitor-web migrate
	openssl rand -hex 16 | $RT exec -i "$PREFIX-mgmt" runuser -u portitor -- portitor-web createadmin admin >/dev/null
	ex mgmt runuser -u portitor -- sqlite3 /var/lib/portitor-web/portitor.db \
		"update users set password_hash = '$ADMIN_HASH' where username = 'admin'"
	ex mgmt systemctl daemon-reload
	ex mgmt systemctl enable portitor-web.service
	ex mgmt systemctl restart portitor-web.service
	until curl -fso /dev/null "$URL/"; do sleep 1; done
	log "GUI on $URL (admin / $ADMIN_PASS)"
}

cmd_up() {
	cmd_image
	cmd_start
	cmd_install
}

cmd_seed() {
	log "seeding"
	AGENT_URL=https://192.168.1.1:8443 \
		AGENT_TOKEN=$(ex fw cat /etc/portitor/agent.token) \
		AGENT_FINGERPRINT=$(ex fw cat /etc/portitor/agent.crt | openssl x509 -outform DER | sha256sum | cut -d' ' -f1) \
		dev/seed.sh "$URL" admin "$ADMIN_PASS"
}

cmd_deploy() {
	local jar
	jar=$(mktemp)
	# shellcheck disable=SC2064
	trap "rm -f '$jar'" RETURN
	req() { curl -sS --fail-with-body -b "$jar" -c "$jar" -X POST -H 'Content-Type: application/json' "$URL/api$1" -d "$2"; echo; }
	req /login "{\"username\":\"admin\",\"password\":\"$ADMIN_PASS\"}" >/dev/null
	log "apply"
	local res
	res=$(req /deploy/apply '{}') || { echo "$res"; return 1; }
	echo "$res" | grep -o '"log":"[^"]*' | head -1 | cut -d'"' -f4- | sed 's/\\n/\n/g'
	# The first apply has nothing to roll back to, so nothing to confirm.
	if [[ $res == *'"status":"pending"'* ]]; then
		log "confirm"
		req /deploy/confirm '{}'
	fi
}

cmd_client() {
	# Stands in for a LAN host: DHCP from the firewall's Kea, then a shell.
	$RT run --rm -it --cap-add NET_ADMIN,NET_RAW --network "$PREFIX-lan:interface_name=eth0" \
		docker.io/library/alpine sh -c 'udhcpc -i eth0 -q && ip addr show eth0 && exec sh'
}

cmd_shell() { $RT exec -it "$PREFIX-${1:?fw or mgmt}" bash; }

cmd_logs() {
	case ${1:?fw or mgmt} in
	fw) ex fw journalctl -f -u portitor-agent -u 'portitor-named@*' -u 'portitor-kea4@*' -u 'portitor-kea6@*' -u 'portitor-radvd@*' -u 'portitor-frr@*' -u named -u kea-dhcp4-server -u kea-dhcp6-server -u radvd -u frr ;;
	mgmt) ex mgmt journalctl -f -u portitor-web -u dnsmasq ;;
	*) echo "fw or mgmt" >&2; exit 2 ;;
	esac
}

cmd_down() {
	log "removing containers and networks"
	$RT rm -f -t 5 "$PREFIX-fw" "$PREFIX-mgmt" >/dev/null 2>&1 || true
	for n in "${NETWORKS[@]}"; do
		$RT network rm -f "$PREFIX-$n" >/dev/null 2>&1 || true
	done
}

cmd_clean() {
	cmd_down
	log "removing images"
	$RT rmi -f "$PREFIX-fw" "$PREFIX-mgmt" >/dev/null 2>&1 || true
}

cmd=${1:-}
case $cmd in
up | image | start | install | seed | deploy | client | shell | logs | down | clean) shift; "cmd_$cmd" "$@" ;;
*) sed -n '2,/^set -e/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 2 ;;
esac
