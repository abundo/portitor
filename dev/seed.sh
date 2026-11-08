#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 The Portitor contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

# Seed a dev database with a typical home setup through the API, and point
# portitor-config at the dev agent. Run after `make dev-agent dev-web`.
#
#   dev/seed.sh [url] [user] [password]
#
# AGENT_URL, AGENT_TOKEN and AGENT_FINGERPRINT override the dev agent's
# (dev/lab/lab.sh seed sets them for the lab firewall).
set -euo pipefail

URL=${1:-http://127.0.0.1:8080}
USER=${2:-admin}
PASS=${3:-dev-password-123}
JAR=$(mktemp)
trap 'rm -f "$JAR"' EXIT

req() { # method path [json]
	curl -sS --fail-with-body -b "$JAR" -c "$JAR" -X "$1" -H 'Content-Type: application/json' \
		"$URL/api$2" ${3:+-d "$3"}
}

req POST /login "{\"username\":\"$USER\",\"password\":\"$PASS\"}" >/dev/null

AGENT_URL=${AGENT_URL:-https://127.0.0.1:8443}
TOKEN=${AGENT_TOKEN:-$(cat dev/run/agent.token)}
FP=${AGENT_FINGERPRINT:-$(openssl x509 -in dev/run/agent.crt -outform DER | sha256sum | cut -d' ' -f1)}
req PUT /firewalls/1 "{\"name\":\"firewall\",\"agent_url\":\"$AGENT_URL\",\"agent_token\":\"$TOKEN\",\"agent_fingerprint\":\"$FP\"}" >/dev/null
req PUT /settings "{\"confirm_timeout\":120,\"wg_endpoint_host\":\"home.example.org\",\"virtual_firewalls\":true}" >/dev/null

# The configuration, through /api/config (dev/design-model-driven.md): by
# path and the YANG leaves' names. cfg METHOD PATH [JSON].
cfg() { req "$1" "/config/candidate/$2" ${3:+"$3"} >/dev/null; }
M=instance=main

# portitor-config start creates the default instance "main"; update it.
cfg PATCH $M '{"description":"Home","dns-upstream":"forward","dns-forwarders":["9.9.9.9"],"dhcp-enabled":true,"dhcp-domain-name":"home.arpa","dhcp-lease-time":43200}'
cfg PUT $M/interface=eth0 '{"kind":"physical","description":"ISP","ipv4-mode":"dhcp","ipv6-accept-ra":true,"enabled":true}'
cfg PUT $M/interface=eth1 '{"kind":"physical","description":"LAN switch","enabled":true,"dns-listen":true,"addresses":["192.168.1.1/24","fd00:1::1/64"]}'
cfg PUT $M/interface=eth1.20 '{"kind":"vlan","parent":"eth1","vlan-id":20,"enabled":true,"dns-listen":true,"addresses":["192.168.20.1/24"]}'
cfg PUT $M/interface=wg0 '{"kind":"wireguard","wg-listen-port":51820,"enabled":true,"dns-listen":true,"addresses":["10.99.0.1/24"]}'
cfg PUT $M/interface-zone=wan '{"interfaces":["eth0"],"description":"Internet"}'
cfg PUT $M/interface-zone=trusted '{"interfaces":["eth1","wg0"],"description":"LAN and VPN clients"}'
cfg PUT $M/interface-zone=iot '{"interfaces":["eth1.20"],"description":"Untrusted gadgets"}'
# Empty until the link to the guest instance exists (below).
cfg PUT $M/interface-zone=guest '{}'

# The zones before the addresses with DNS names in them.
cfg PUT $M/dns-zone=home.arpa '{"type":"forward"}'
cfg PUT $M/dns-zone=192.168.1.0%2F24 '{"type":"reverse4"}'

cfg PUT $M/ipam-prefix=192.168.0.0%2F16 '{"description":"Home"}'
cfg PUT $M/ipam-prefix=192.168.1.0%2F24 '{"description":"LAN","dhcp-enabled":true,"dhcp-range-start":"192.168.1.100","dhcp-range-end":"192.168.1.199"}'
cfg PUT $M/ipam-prefix=192.168.20.0%2F24 '{"description":"IoT","dhcp-enabled":true,"dhcp-range-start":"192.168.20.100","dhcp-range-end":"192.168.20.199"}'
cfg PUT $M/ipam-prefix=10.99.0.0%2F24 '{"description":"WireGuard"}'
cfg PUT $M/ipam-prefix=10.255.0.0%2F30 '{"description":"link to guest"}'
cfg PUT $M/ipam-address=192.168.1.1 '{"dns-name":"gw.home.arpa"}'
cfg PUT $M/ipam-address=192.168.1.10 '{"dns-name":"nas.home.arpa","mac":"02:00:00:00:00:10","description":"NAS"}'
# IPv6 on the LAN: router advertisements with SLAAC, plus DHCPv6.
cfg PUT $M/ipam-prefix=fd00%3A1%3A%3A%2F64 '{"description":"LAN IPv6","ra-enabled":true,"ra-slaac":true,"dhcp-enabled":true,"dhcp-range-start":"fd00:1::1000","dhcp-range-end":"fd00:1::1fff"}'
cfg PUT $M/ipam-address=fd00%3A1%3A%3A10 '{"dns-name":"nas.home.arpa","mac":"02:00:00:00:00:10"}'
cfg PUT host=nas '{"addresses":["192.168.1.10","fd00:1::10"],"description":"NAS, both IP versions"}'

cfg POST $M/dns-zone=home.arpa/record '{"name":"files","type":"CNAME","value":"nas"}'

cfg PUT service=iot-cloud '{"type":"tcp/udp/sctp","port":[{"protocol":"tcp","dst-lo":443,"dst-hi":0,"src-lo":0,"src-hi":0},{"protocol":"tcp","dst-lo":8883,"dst-hi":0,"src-lo":0,"src-hi":0}],"description":"HTTPS and MQTT over TLS"}'
rule() { cfg POST "$1/rule" "$2"; }
rule $M '{"chain":"forward","in-interfaces":["eth1"],"out-interfaces":["wan"],"action":"accept","enabled":true,"description":"LAN to Internet"}'
rule $M '{"chain":"forward","in-interfaces":["eth1"],"out-interfaces":["iot"],"action":"accept","enabled":true,"description":"LAN manages IoT"}'
rule $M '{"chain":"forward","in-interfaces":["iot"],"out-interfaces":["wan"],"services":["iot-cloud"],"action":"accept","enabled":true,"description":"IoT cloud only"}'
rule $M '{"chain":"forward","in-interfaces":["wg0"],"action":"accept","enabled":true,"description":"VPN clients anywhere"}'
rule $M '{"chain":"forward","in-interfaces":["guest"],"out-interfaces":["wan"],"action":"accept","enabled":true,"description":"Guests to Internet"}'
rule $M '{"chain":"input","in-interfaces":["wan"],"services":["ping","ping6"],"action":"accept","enabled":true,"description":"Ping from Internet"}'
rule $M '{"chain":"forward","in-interfaces":["wg0"],"dst-addrs":["nas"],"services":["ssh"],"action":"accept","enabled":true,"description":"SSH to the NAS (IPv4 and IPv6)"}'
cfg POST $M/nat-rule '{"kind":"dnat","in-interfaces":["wan"],"protocol":"tcp","dst-ports":"8443","to-addr":"nas","to-port":443,"enabled":true,"description":"NAS web"}'
rule $M '{"chain":"input","in-interfaces":["trusted"],"action":"accept","enabled":true,"description":"LAN and VPN to the firewall"}'
rule $M '{"chain":"input","in-interfaces":["iot"],"action":"reject","enabled":true,"description":"IoT to the firewall"}'
cfg POST $M/nat-rule '{"kind":"masquerade","out-interfaces":["wan"],"enabled":true,"description":"Internet sharing"}'
cfg PUT $M/interface=wg0/wireguard-peer=phone '{"allowed-ips":["10.99.0.2/32"],"enabled":true}'
cfg PUT $M/interface=wg0/wireguard-peer=laptop '{"allowed-ips":["10.99.0.3/32"],"enabled":true}'

G=instance=guest
cfg PUT $G '{"firewall":"firewall","description":"Guest Wi-Fi, isolated","dhcp-enabled":true}'
cfg PUT $G/interface=eth2 '{"kind":"physical","description":"Guest AP","enabled":true,"addresses":["192.168.50.1/24"]}'
cfg PUT $G/ipam-prefix=192.168.50.0%2F24 '{"dhcp-enabled":true,"dhcp-range-start":"192.168.50.100","dhcp-range-end":"192.168.50.200","dhcp-dns-servers":["9.9.9.9"]}'
cfg PUT link=guestup '{"instance-a":"main","interface-a":"lk-guest","addresses-a":["10.255.0.1/30"],"instance-b":"guest","interface-b":"lk-main","addresses-b":["10.255.0.2/30"]}'
cfg PATCH $M/interface-zone=guest '{"interfaces":["lk-guest"]}'
# The guest instance names its two interfaces directly, without zones.
rule $G '{"chain":"forward","in-interfaces":["eth2"],"out-interfaces":["lk-main"],"dst-addrs":["192.168.0.0/16"],"action":"reject","enabled":true,"description":"No access to home"}'
rule $G '{"chain":"forward","in-interfaces":["eth2"],"out-interfaces":["lk-main"],"action":"accept","enabled":true}'
rule $G '{"chain":"input","in-interfaces":["eth2"],"action":"accept","enabled":true}'
cfg POST $G/nat-rule '{"kind":"masquerade","out-interfaces":["lk-main"],"enabled":true}'
cfg POST $G/route '{"destination":"default","gateway":"10.255.0.1","enabled":true}'

echo "seeded; deploy check:"
req GET /deploy/check
echo
