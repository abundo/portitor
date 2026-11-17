<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Adding a VPN

Portitor has two VPNs. Both are under *VPN* in the menu.

| | WireGuard | OpenVPN |
|---|---|---|
| **Good for** | Links between sites, and remote access from your own devices. | Remote access for many users who log in with a name and password. |
| **Logins** | A key per device. | Your firewall's users, or the users in your directory (LDAP or Active Directory), optionally with two-factor login. |
| **Clients** | WireGuard apps on every platform; most routers. | OpenVPN Connect, Tunnelblick, NetworkManager and others. |
| **Through strict networks** | UDP only. | Falls back to TCP where UDP is blocked. |

The firewall's address for the clients to connect to is usually its WAN address. If
that address changes, keep a name pointing at it with a dynamic DNS zone (*Services →
DNS*, *New dynamic zone*).

## Remote access with WireGuard

1. *VPN → WireGuard*: add a WireGuard interface, for example `wg0`, with a tunnel
   address such as `10.10.0.1/24` and a listen port such as `51820`. Its keys are
   generated for you.
2. Add a peer for each device, with its own tunnel address, `10.10.0.2/32` and so
   on. The firewall generates the device's keys.
3. Add **forward rules** from `wg0` to what the devices may reach, the LAN say. For
   Internet access through the tunnel, also add a rule from `wg0` to the WAN and a
   masquerade rule out of the WAN.
4. Commit and confirm.
5. The peer's config button gives a config file and a QR code for the WireGuard app.
   It holds the device's private key: hand it over securely, and delete the
   downloaded copy.

The firewall opens the listen port on the WAN for you.

## Between two sites with WireGuard

A peer is a **site** when it has *Networks*: the networks behind it, for example the
other office's LAN `192.168.50.0/24`. The firewall routes those networks into the
tunnel for you; you don't add routes.

1. On each firewall, add a WireGuard interface (above).
2. On each side, add the other side as a peer, with its public key, its tunnel
   address and its networks.
3. On one side, give the peer an *Endpoint* (the other side's public address or name
   and port) and a *Keepalive* of 25. Leave the endpoint empty on the side that waits.
4. On each side, add forward rules between the WireGuard interface and the LAN, in
   both directions as needed. You don't need NAT between sites.
5. Commit and confirm on both.

When the other side isn't a Portitor firewall, the peer's config button gives a
config file for it.

A firewall cluster connects as one site: the active firewall carries the tunnel.

## Remote access with OpenVPN

1. Get a certificate for the name the clients connect to, such as
   `vpn.example.com`, under *Services → Certificates* (see
   [Certificates](certificates.md)).
2. *VPN → OpenVPN*: *Add OpenVPN server*, choose the certificate and the listen
   interface (the WAN), choose who may log in, and turn it on.
3. Add forward rules from the OpenVPN interface to what the users may reach. For
   Internet access through the tunnel, also add a masquerade rule out of the WAN.
4. Commit and confirm, then download the client config from the *Info* tab. Every
   user gets the same config and logs in with their own name and password.

More: [OpenVPN](openvpn.md).

## When it doesn't connect

- *Dashboard* and *VPN → WireGuard* show each peer's last handshake. No handshake at
  all means the packets don't arrive: check the endpoint, the port, and any firewall
  or NAT in front of yours.
- A handshake but no traffic means a missing forward rule, or wrong *Allowed IPs* or
  *Networks*.
- *Tools → Packet capture* on the WAN, filtered on the VPN port, shows whether the
  client's packets arrive at all.
