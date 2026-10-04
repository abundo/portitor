#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 The Portitor contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

# Seed a dev database with a typical home setup through the API, and point
# portitor-web at the dev agent. Run after `make dev-agent dev-web`.
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
req PUT /settings "{\"agent_url\":\"$AGENT_URL\",\"agent_token\":\"$TOKEN\",\"agent_fingerprint\":\"$FP\",\"confirm_timeout\":120,\"wg_endpoint_host\":\"home.example.org\",\"virtual_firewalls\":true}" >/dev/null

# portitor-web start creates the default instance "main"; update it.
MAIN=$(req GET /instances | grep -oE '"id":[0-9]+,[^}]*"name":"main"' | sed -E 's/"id":([0-9]+).*/\1/')
req PUT /instances/$MAIN '{"name":"main","description":"Home","dns_upstream":"forward","dns_forwarders":["9.9.9.9"],"dhcp_enabled":true,"dhcp_domain_name":"home.arpa","dhcp_lease_time":43200}' >/dev/null
id /interfaces "{\"instance_id\":$MAIN,\"name\":\"eth0\",\"description\":\"ISP\",\"ipv4_mode\":\"dhcp\",\"ipv6_accept_ra\":true,\"enabled\":true}" >/dev/null
id /interfaces "{\"instance_id\":$MAIN,\"name\":\"eth1\",\"description\":\"LAN switch\",\"enabled\":true,\"dns_listen\":true,\"addresses\":[\"192.168.1.1/24\",\"fd00:1::1/64\"]}" >/dev/null
id /interfaces "{\"instance_id\":$MAIN,\"name\":\"eth1.20\",\"kind\":\"vlan\",\"parent\":\"eth1\",\"vlan_id\":20,\"enabled\":true,\"dns_listen\":true,\"addresses\":[\"192.168.20.1/24\"]}" >/dev/null
WG0=$(id /interfaces "{\"instance_id\":$MAIN,\"name\":\"wg0\",\"kind\":\"wireguard\",\"wg_listen_port\":51820,\"enabled\":true,\"dns_listen\":true,\"addresses\":[\"10.99.0.1/24\"]}")
id /interface-zones "{\"instance_id\":$MAIN,\"name\":\"wan\",\"interfaces\":[\"eth0\"],\"description\":\"Internet\"}" >/dev/null
id /interface-zones "{\"instance_id\":$MAIN,\"name\":\"trusted\",\"interfaces\":[\"eth1\",\"wg0\"],\"description\":\"LAN and VPN clients\"}" >/dev/null
id /interface-zones "{\"instance_id\":$MAIN,\"name\":\"iot\",\"interfaces\":[\"eth1.20\"],\"description\":\"Untrusted gadgets\"}" >/dev/null
# Empty until the link to the guest instance exists (below).
GUESTZ=$(id /interface-zones "{\"instance_id\":$MAIN,\"name\":\"guest\"}")

id /ipam/prefixes "{\"instance_id\":$MAIN,\"prefix\":\"192.168.0.0/16\",\"description\":\"Home\"}" >/dev/null
id /ipam/prefixes "{\"instance_id\":$MAIN,\"prefix\":\"192.168.1.0/24\",\"description\":\"LAN\",\"dhcp_enabled\":true,\"dhcp_range_start\":\"192.168.1.100\",\"dhcp_range_end\":\"192.168.1.199\"}" >/dev/null
id /ipam/prefixes "{\"instance_id\":$MAIN,\"prefix\":\"192.168.20.0/24\",\"description\":\"IoT\",\"dhcp_enabled\":true,\"dhcp_range_start\":\"192.168.20.100\",\"dhcp_range_end\":\"192.168.20.199\"}" >/dev/null
id /ipam/prefixes "{\"instance_id\":$MAIN,\"prefix\":\"10.99.0.0/24\",\"description\":\"WireGuard\"}" >/dev/null
id /ipam/prefixes "{\"instance_id\":$MAIN,\"prefix\":\"10.255.0.0/30\",\"description\":\"link to guest\"}" >/dev/null
id /ipam/addresses "{\"instance_id\":$MAIN,\"address\":\"192.168.1.1\",\"dns_name\":\"gw.home.arpa\"}" >/dev/null
id /ipam/addresses "{\"instance_id\":$MAIN,\"address\":\"192.168.1.10\",\"dns_name\":\"nas.home.arpa\",\"mac\":\"02:00:00:00:00:10\",\"description\":\"NAS\"}" >/dev/null
# IPv6 on the LAN: router advertisements with SLAAC, plus DHCPv6.
id /ipam/prefixes "{\"instance_id\":$MAIN,\"prefix\":\"fd00:1::/64\",\"description\":\"LAN IPv6\",\"ra_enabled\":true,\"ra_slaac\":true,\"dhcp_enabled\":true,\"dhcp_range_start\":\"fd00:1::1000\",\"dhcp_range_end\":\"fd00:1::1fff\"}" >/dev/null
id /ipam/addresses "{\"instance_id\":$MAIN,\"address\":\"fd00:1::10\",\"dns_name\":\"nas.home.arpa\",\"mac\":\"02:00:00:00:00:10\"}" >/dev/null
id /objects '{"name":"nas","addresses":["192.168.1.10","fd00:1::10"],"description":"NAS, both IP versions"}' >/dev/null

ZONE=$(id /dns/zones "{\"instance_id\":$MAIN,\"name\":\"home.arpa\",\"type\":\"forward\"}")
id /dns/zones "{\"instance_id\":$MAIN,\"name\":\"192.168.1.0/24\",\"type\":\"reverse4\"}" >/dev/null
id /dns/records "{\"zone_id\":$ZONE,\"name\":\"files\",\"type\":\"CNAME\",\"value\":\"nas\"}" >/dev/null

id /custom-services '{"name":"iot-cloud","type":"tcp/udp/sctp","ports":[{"protocol":"tcp","dst_lo":443},{"protocol":"tcp","dst_lo":8883}],"description":"HTTPS and MQTT over TLS"}' >/dev/null
id /rules "{\"instance_id\":$MAIN,\"chain\":\"forward\",\"in_interfaces\":[\"eth1\"],\"out_interfaces\":[\"wan\"],\"action\":\"accept\",\"enabled\":true,\"description\":\"LAN to Internet\"}" >/dev/null
id /rules "{\"instance_id\":$MAIN,\"chain\":\"forward\",\"in_interfaces\":[\"eth1\"],\"out_interfaces\":[\"iot\"],\"action\":\"accept\",\"enabled\":true,\"description\":\"LAN manages IoT\"}" >/dev/null
id /rules "{\"instance_id\":$MAIN,\"chain\":\"forward\",\"in_interfaces\":[\"iot\"],\"out_interfaces\":[\"wan\"],\"services\":[\"iot-cloud\"],\"action\":\"accept\",\"enabled\":true,\"description\":\"IoT cloud only\"}" >/dev/null
id /rules "{\"instance_id\":$MAIN,\"chain\":\"forward\",\"in_interfaces\":[\"wg0\"],\"action\":\"accept\",\"enabled\":true,\"description\":\"VPN clients anywhere\"}" >/dev/null
id /rules "{\"instance_id\":$MAIN,\"chain\":\"forward\",\"in_interfaces\":[\"guest\"],\"out_interfaces\":[\"wan\"],\"action\":\"accept\",\"enabled\":true,\"description\":\"Guests to Internet\"}" >/dev/null
id /rules "{\"instance_id\":$MAIN,\"chain\":\"input\",\"in_interfaces\":[\"wan\"],\"services\":[\"ping\",\"ping6\"],\"action\":\"accept\",\"enabled\":true,\"description\":\"Ping from Internet\"}" >/dev/null
id /rules "{\"instance_id\":$MAIN,\"chain\":\"forward\",\"in_interfaces\":[\"wg0\"],\"dst_addrs\":[\"nas\"],\"services\":[\"ssh\"],\"action\":\"accept\",\"enabled\":true,\"description\":\"SSH to the NAS (IPv4 and IPv6)\"}" >/dev/null
id /nat "{\"instance_id\":$MAIN,\"kind\":\"dnat\",\"in_interfaces\":[\"wan\"],\"protocol\":\"tcp\",\"dst_ports\":\"8443\",\"to_addr\":\"nas\",\"to_port\":443,\"enabled\":true,\"description\":\"NAS web\"}" >/dev/null
id /rules "{\"instance_id\":$MAIN,\"chain\":\"input\",\"in_interfaces\":[\"trusted\"],\"action\":\"accept\",\"enabled\":true,\"description\":\"LAN and VPN to the firewall\"}" >/dev/null
id /rules "{\"instance_id\":$MAIN,\"chain\":\"input\",\"in_interfaces\":[\"iot\"],\"action\":\"reject\",\"enabled\":true,\"description\":\"IoT to the firewall\"}" >/dev/null
id /nat "{\"instance_id\":$MAIN,\"kind\":\"masquerade\",\"out_interfaces\":[\"wan\"],\"enabled\":true,\"description\":\"Internet sharing\"}" >/dev/null
id /wg/peers "{\"interface_id\":$WG0,\"name\":\"phone\",\"allowed_ips\":[\"10.99.0.2/32\"],\"enabled\":true}" >/dev/null
id /wg/peers "{\"interface_id\":$WG0,\"name\":\"laptop\",\"allowed_ips\":[\"10.99.0.3/32\"],\"enabled\":true}" >/dev/null

GUEST=$(id /instances '{"name":"guest","description":"Guest Wi-Fi, isolated","dhcp_enabled":true}')
id /interfaces "{\"instance_id\":$GUEST,\"name\":\"eth2\",\"description\":\"Guest AP\",\"enabled\":true,\"addresses\":[\"192.168.50.1/24\"]}" >/dev/null
id /ipam/prefixes "{\"instance_id\":$GUEST,\"prefix\":\"192.168.50.0/24\",\"dhcp_enabled\":true,\"dhcp_range_start\":\"192.168.50.100\",\"dhcp_range_end\":\"192.168.50.200\",\"dhcp_dns_servers\":[\"9.9.9.9\"]}" >/dev/null
id /links "{\"name\":\"guestup\",\"instance_a_id\":$MAIN,\"interface_a\":\"lk-guest\",\"addresses_a\":[\"10.255.0.1/30\"],\"instance_b_id\":$GUEST,\"interface_b\":\"lk-main\",\"addresses_b\":[\"10.255.0.2/30\"]}" >/dev/null
req PUT /interface-zones/$GUESTZ '{"interfaces":["lk-guest"]}' >/dev/null
# The guest instance names its two interfaces directly, without zones.
id /rules "{\"instance_id\":$GUEST,\"chain\":\"forward\",\"in_interfaces\":[\"eth2\"],\"out_interfaces\":[\"lk-main\"],\"dst_addrs\":[\"192.168.0.0/16\"],\"action\":\"reject\",\"enabled\":true,\"description\":\"No access to home\"}" >/dev/null
id /rules "{\"instance_id\":$GUEST,\"chain\":\"forward\",\"in_interfaces\":[\"eth2\"],\"out_interfaces\":[\"lk-main\"],\"action\":\"accept\",\"enabled\":true}" >/dev/null
id /rules "{\"instance_id\":$GUEST,\"chain\":\"input\",\"in_interfaces\":[\"eth2\"],\"action\":\"accept\",\"enabled\":true}" >/dev/null
id /nat "{\"instance_id\":$GUEST,\"kind\":\"masquerade\",\"out_interfaces\":[\"lk-main\"],\"enabled\":true}" >/dev/null
id /routes "{\"instance_id\":$GUEST,\"destination\":\"default\",\"gateway\":\"10.255.0.1\",\"enabled\":true}" >/dev/null

echo "seeded; deploy check:"
req GET /deploy/check
echo
