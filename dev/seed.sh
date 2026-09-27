#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 The Portitor contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

# Seed a dev database with a typical home setup through the API, and point
# portitor-web at the dev agent. Run after `make dev-db dev-agent dev-web`.
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
id() { req POST "$1" "$2" | sed -E 's/.*"id":([0-9]+).*/\1/'; }

req POST /login "{\"username\":\"$USER\",\"password\":\"$PASS\"}" >/dev/null

AGENT_URL=${AGENT_URL:-https://127.0.0.1:8443}
TOKEN=${AGENT_TOKEN:-$(cat dev/run/agent.token)}
FP=${AGENT_FINGERPRINT:-$(openssl x509 -in dev/run/agent.crt -outform DER | sha256sum | cut -d' ' -f1)}
req PUT /settings "{\"agent_url\":\"$AGENT_URL\",\"agent_token\":\"$TOKEN\",\"agent_fingerprint\":\"$FP\",\"confirm_timeout\":120,\"wg_endpoint_host\":\"home.example.org\"}" >/dev/null

MAIN=$(id /instances '{"name":"main","description":"Home","dns_enabled":true,"dns_forward_from_dhcp":true,"dns_forwarders":["9.9.9.9"],"dhcp_enabled":true,"dhcp_domain_name":"home.arpa","dhcp_lease_time":43200}')
WAN=$(id /zones "{\"instance_id\":$MAIN,\"name\":\"wan\",\"input_policy\":\"drop\",\"masquerade\":true,\"description\":\"Internet\"}")
LAN=$(id /zones "{\"instance_id\":$MAIN,\"name\":\"lan\",\"input_policy\":\"accept\"}")
IOT=$(id /zones "{\"instance_id\":$MAIN,\"name\":\"iot\",\"input_policy\":\"reject\",\"description\":\"Untrusted gadgets\"}")
VPN=$(id /zones "{\"instance_id\":$MAIN,\"name\":\"vpn\",\"input_policy\":\"accept\"}")
GUESTZ=$(id /zones "{\"instance_id\":$MAIN,\"name\":\"guest\",\"input_policy\":\"drop\"}")

id /interfaces "{\"instance_id\":$MAIN,\"name\":\"eth0\",\"description\":\"ISP\",\"zone_id\":$WAN,\"ipv4_mode\":\"dhcp\",\"ipv6_accept_ra\":true,\"enabled\":true}" >/dev/null
ETH1=$(id /interfaces "{\"instance_id\":$MAIN,\"name\":\"eth1\",\"description\":\"LAN switch\",\"zone_id\":$LAN,\"enabled\":true,\"dns_listen\":true}")
VL20=$(id /interfaces "{\"instance_id\":$MAIN,\"name\":\"eth1.20\",\"kind\":\"vlan\",\"parent\":\"eth1\",\"vlan_id\":20,\"zone_id\":$IOT,\"enabled\":true,\"dns_listen\":true}")
WG0=$(id /interfaces "{\"instance_id\":$MAIN,\"name\":\"wg0\",\"kind\":\"wireguard\",\"wg_listen_port\":51820,\"zone_id\":$VPN,\"enabled\":true,\"dns_listen\":true}")

id /ipam/prefixes "{\"instance_id\":$MAIN,\"prefix\":\"192.168.0.0/16\",\"description\":\"Home\"}" >/dev/null
id /ipam/prefixes "{\"instance_id\":$MAIN,\"prefix\":\"192.168.1.0/24\",\"description\":\"LAN\",\"dhcp_enabled\":true,\"dhcp_range_start\":\"192.168.1.100\",\"dhcp_range_end\":\"192.168.1.199\"}" >/dev/null
id /ipam/prefixes "{\"instance_id\":$MAIN,\"prefix\":\"192.168.20.0/24\",\"description\":\"IoT\",\"dhcp_enabled\":true,\"dhcp_range_start\":\"192.168.20.100\",\"dhcp_range_end\":\"192.168.20.199\"}" >/dev/null
id /ipam/prefixes "{\"instance_id\":$MAIN,\"prefix\":\"10.99.0.0/24\",\"description\":\"WireGuard\"}" >/dev/null
id /ipam/prefixes "{\"instance_id\":$MAIN,\"prefix\":\"10.255.0.0/30\",\"description\":\"link to guest\"}" >/dev/null
id /ipam/addresses "{\"instance_id\":$MAIN,\"address\":\"192.168.1.1\",\"interface_id\":$ETH1,\"dns_name\":\"gw.home.arpa\"}" >/dev/null
id /ipam/addresses "{\"instance_id\":$MAIN,\"address\":\"192.168.20.1\",\"interface_id\":$VL20}" >/dev/null
id /ipam/addresses "{\"instance_id\":$MAIN,\"address\":\"10.99.0.1\",\"interface_id\":$WG0}" >/dev/null
id /ipam/addresses "{\"instance_id\":$MAIN,\"address\":\"192.168.1.10\",\"dns_name\":\"nas.home.arpa\",\"mac\":\"02:00:00:00:00:10\",\"description\":\"NAS\"}" >/dev/null
# IPv6 on the LAN: router advertisements with SLAAC, plus DHCPv6.
id /ipam/prefixes "{\"instance_id\":$MAIN,\"prefix\":\"fd00:1::/64\",\"description\":\"LAN IPv6\",\"ra_enabled\":true,\"ra_slaac\":true,\"dhcp_enabled\":true,\"dhcp_range_start\":\"fd00:1::1000\",\"dhcp_range_end\":\"fd00:1::1fff\"}" >/dev/null
id /ipam/addresses "{\"instance_id\":$MAIN,\"address\":\"fd00:1::1\",\"interface_id\":$ETH1}" >/dev/null
id /ipam/addresses "{\"instance_id\":$MAIN,\"address\":\"fd00:1::10\",\"dns_name\":\"nas.home.arpa\",\"mac\":\"02:00:00:00:00:10\"}" >/dev/null
id /objects '{"name":"nas","addresses":["192.168.1.10","fd00:1::10"],"description":"NAS, both IP versions"}' >/dev/null

ZONE=$(id /dns/zones "{\"instance_id\":$MAIN,\"name\":\"home.arpa\",\"type\":\"forward\"}")
id /dns/zones "{\"instance_id\":$MAIN,\"name\":\"192.168.1.0/24\",\"type\":\"reverse4\"}" >/dev/null
id /dns/records "{\"zone_id\":$ZONE,\"name\":\"files\",\"type\":\"CNAME\",\"value\":\"nas\"}" >/dev/null

id /rules "{\"instance_id\":$MAIN,\"chain\":\"forward\",\"src_zone_id\":$LAN,\"dst_zone_id\":$WAN,\"action\":\"accept\",\"enabled\":true,\"description\":\"LAN to Internet\"}" >/dev/null
id /rules "{\"instance_id\":$MAIN,\"chain\":\"forward\",\"src_zone_id\":$LAN,\"dst_zone_id\":$IOT,\"action\":\"accept\",\"enabled\":true,\"description\":\"LAN manages IoT\"}" >/dev/null
id /rules "{\"instance_id\":$MAIN,\"chain\":\"forward\",\"src_zone_id\":$IOT,\"dst_zone_id\":$WAN,\"protocol\":\"tcp\",\"dst_ports\":\"443,8883\",\"action\":\"accept\",\"enabled\":true,\"description\":\"IoT cloud only\"}" >/dev/null
id /rules "{\"instance_id\":$MAIN,\"chain\":\"forward\",\"src_zone_id\":$VPN,\"action\":\"accept\",\"enabled\":true,\"description\":\"VPN clients anywhere\"}" >/dev/null
id /rules "{\"instance_id\":$MAIN,\"chain\":\"forward\",\"src_zone_id\":$GUESTZ,\"dst_zone_id\":$WAN,\"action\":\"accept\",\"enabled\":true,\"description\":\"Guests to Internet\"}" >/dev/null
id /rules "{\"instance_id\":$MAIN,\"chain\":\"input\",\"src_zone_id\":$WAN,\"protocol\":\"icmp\",\"action\":\"accept\",\"enabled\":true,\"description\":\"Ping from Internet\"}" >/dev/null
id /rules "{\"instance_id\":$MAIN,\"chain\":\"forward\",\"src_zone_id\":$VPN,\"dst_addrs\":[\"nas\"],\"protocol\":\"tcp\",\"dst_ports\":\"22\",\"action\":\"accept\",\"enabled\":true,\"description\":\"SSH to the NAS (IPv4 and IPv6)\"}" >/dev/null
id /nat "{\"instance_id\":$MAIN,\"kind\":\"dnat\",\"in_zone_id\":$WAN,\"protocol\":\"tcp\",\"dst_ports\":\"8443\",\"to_addr\":\"nas\",\"to_port\":443,\"enabled\":true,\"description\":\"NAS web\"}" >/dev/null
id /wg/peers "{\"interface_id\":$WG0,\"name\":\"phone\",\"allowed_ips\":[\"10.99.0.2/32\"],\"enabled\":true}" >/dev/null
id /wg/peers "{\"interface_id\":$WG0,\"name\":\"laptop\",\"allowed_ips\":[\"10.99.0.3/32\"],\"enabled\":true}" >/dev/null

GUEST=$(id /instances '{"name":"guest","description":"Guest Wi-Fi, isolated","dhcp_enabled":true}')
GLAN=$(id /zones "{\"instance_id\":$GUEST,\"name\":\"lan\",\"input_policy\":\"accept\"}")
GUP=$(id /zones "{\"instance_id\":$GUEST,\"name\":\"up\",\"input_policy\":\"drop\",\"masquerade\":true}")
ETH2=$(id /interfaces "{\"instance_id\":$GUEST,\"name\":\"eth2\",\"description\":\"Guest AP\",\"zone_id\":$GLAN,\"enabled\":true}")
id /ipam/prefixes "{\"instance_id\":$GUEST,\"prefix\":\"192.168.50.0/24\",\"dhcp_enabled\":true,\"dhcp_range_start\":\"192.168.50.100\",\"dhcp_range_end\":\"192.168.50.200\",\"dhcp_dns_servers\":[\"9.9.9.9\"]}" >/dev/null
id /ipam/addresses "{\"instance_id\":$GUEST,\"address\":\"192.168.50.1\",\"interface_id\":$ETH2}" >/dev/null
id /rules "{\"instance_id\":$GUEST,\"chain\":\"forward\",\"src_zone_id\":$GLAN,\"dst_zone_id\":$GUP,\"dst_addrs\":[\"192.168.0.0/16\"],\"action\":\"reject\",\"enabled\":true,\"description\":\"No access to home\"}" >/dev/null
id /rules "{\"instance_id\":$GUEST,\"chain\":\"forward\",\"src_zone_id\":$GLAN,\"dst_zone_id\":$GUP,\"action\":\"accept\",\"enabled\":true}" >/dev/null
id /routes "{\"instance_id\":$GUEST,\"destination\":\"default\",\"gateway\":\"10.255.0.1\",\"enabled\":true}" >/dev/null
id /links "{\"name\":\"guestup\",\"instance_a_id\":$MAIN,\"interface_a\":\"lk-guest\",\"zone_a_id\":$GUESTZ,\"addresses_a\":[\"10.255.0.1/30\"],\"instance_b_id\":$GUEST,\"interface_b\":\"lk-main\",\"zone_b_id\":$GUP,\"addresses_b\":[\"10.255.0.2/30\"]}" >/dev/null

echo "seeded; deploy check:"
req GET /deploy/check
echo
