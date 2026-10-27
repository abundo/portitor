<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# OpenVPN

Under **VPN → OpenVPN**, each virtual firewall can run an
[OpenVPN](https://openvpn.net/) server for remote users. They log in with a user
name and password, over IPv4 or IPv6, with any OpenVPN client: OpenVPN Connect,
the OpenVPN GUI on Windows, Tunnelblick, NetworkManager, or `openvpn` itself. The
firewall checks the password as it checks a login to the GUI: its own users, and
the OpenLDAP and Active Directory servers of the [directory](directory.md).
Clients are not given certificates of their own: everyone gets the same client
config.

The server is an interface of kind **OpenVPN server** (`ovpn0`): firewall rules,
interface zones, NAT, DNS and the other services treat it like any interface.

- On the **default virtual firewall** (the host itself) OpenVPN runs as the
  distribution's `openvpn-server@portitor-udp.service` and
  `openvpn-server@portitor-tcp.service`, from `/etc/openvpn/server/`.
- On **another virtual firewall** it runs in the virtual firewall
  (`portitor-openvpn-udp@<name>.service`,
  `portitor-openvpn-tcp@<name>.service`).

Changing the server's settings restarts
OpenVPN, which disconnects the clients for a moment (they reconnect by
themselves); changing who may log in does not.

## Getting started

1. Get a certificate for the server under **Services → Certificates**: an ACME
   certificate (Let's Encrypt) for the name clients connect to, e.g.
   `vpn.example.com`, or an imported or generated one. Clients check the server
   by the certificate's **common name**.
2. Under **VPN → OpenVPN → Configuration**, **Add OpenVPN server**. It is added
   as `ovpn0`, disabled, with the tunnel address `10.8.0.1/24` (and `10.9.0.1/24`
   for the TCP clients).
3. Choose its **certificate**, set the **listen interface** (the WAN), add an IPv6
   tunnel address if you like (`fd00:8::1/64`), choose who may log in, and enable
   it.
4. Add **firewall rules** for what the clients may reach: forward rules from
   `ovpn0` (or a zone holding it) to the LANs. With **All traffic through the
   tunnel**, add a NAT rule that masquerades `ovpn0`'s traffic out of the WAN.
5. Commit, and download the **Client config** from the Info tab.

## Settings

- **Mode**:
  - **Adaptive** (the default): the server listens on UDP and on TCP, on the same
    port. Clients try UDP first and fall back to TCP within seconds where UDP is
    blocked (hotel and guest networks often let only TCP out). UDP and TCP
    clients each have a tunnel of their own, with its own prefixes (**UDP tunnel
    addresses** and **TCP tunnel addresses**), and each side's clients get a route
    to the other's: a second device, `ovt-ovpn0`, carries the TCP clients, and
    rules, zones and services naming `ovpn0` cover it too.
  - **UDP only** or **TCP only**: one process, one tunnel.
- **Tunnel addresses** (**UDP tunnel addresses** in the adaptive mode): the
  firewall's address in the tunnel, one IPv4 and/or one IPv6 address with its
  prefix length. Clients get the other addresses of the prefixes. IPv4 prefixes
  may be /16 to /30. IPv6: /64 is usual; at most /112, and without an IPv4
  address, when OpenVPN reserves 65536 addresses, at most /111.
- **TCP tunnel addresses** (adaptive mode only): the same for the TCP clients'
  tunnel, in prefixes of their own, apart from the UDP tunnel's: `10.9.0.1/24`,
  `fd00:9::1/64`.
- **Port**: 1194 by default. It is opened automatically in the firewall (auto
  rule `openvpn ovpn0`) for UDP and TCP, on the listen interface only when one is
  set. Port 443/TCP gets through the strictest networks.
- **Listen interface**: where clients come in, usually the WAN. Empty: any
  interface.
- **Certificate**: the server's. An ACME certificate is renewed by the firewall,
  and OpenVPN restarts with the new one within a minute. Until the certificate is
  there, OpenVPN keeps restarting (shown as failed under Status).
- **Public host**: the name or address in the client config; empty: the
  certificate's common name.

### Logins

Users log in to OpenVPN as to the GUI ([Directory](directory.md)): a local
user's password is checked against its hash; a directory user's, and a user the
firewall doesn't have yet, at the directory's servers in their order. A user a
server lets in is copied to the users within half a minute, with no global role,
as a first login to the GUI would.

- **Required role**: only the role's members may log in, and the directory users
  in a group mapped to the role (**Admin → Directory → Authorization**), first
  logins included. Make a role "VPN users" and add its members, or map a
  directory group to it. A user who only uses the VPN gets the global role
  **none**: they cannot use the GUI. Without a required role, every user of the
  directory may log in. If the required role is deleted, no one logs in until
  another is chosen. On a virtual firewall whose admin is not a global admin, the
  users are always the members of that virtual firewall's role.

The password is checked by portitor-agent, which OpenVPN asks for each login
(through its management socket): no password is written to a file, and no
script runs. The agent reaches the directory servers from the firewall host. A
refused login is answered after two seconds, and logged in the agent's log with
the user name and the client's address. Two-factor login codes are not asked
for: OpenVPN logins take the password alone.

When a local user may no longer log in (removed from the role, deleted), or a
directory server they logged in through is removed, their sessions end when the
change is committed.

### Clients

- **Routes**: the networks pushed to the clients, reached through the tunnel.
- **All traffic through the tunnel**: pushes the default route, IPv4 and IPv6
  (or blocks IPv6 on the client when the tunnel has no IPv6 address).
- **DNS servers** and **DNS domain**: pushed to the clients. Empty: the
  interface's own addresses when the virtual firewall's DNS server answers on
  it (**DNS listen** under Interfaces).
- **Client to client**: clients reach each other inside OpenVPN, without passing
  the firewall rules. Off, their traffic to each other goes through the rules.

## Client config

**Client config** on the Info tab shows the `.ovpn` file to download or copy:
the server (UDP first, then TCP in the adaptive mode), the CA that signed the
server's certificate, the name to check, and the server's **tls-crypt key**.
The key keeps anyone without the file from even starting a handshake, so the
server doesn't answer port scans; hand the file to your users only. It holds no
password: the client asks for the user name and password.

The CA is the root of the certificate's chain: the system CA that signed an ACME
certificate (ISRG Root X1 for Let's Encrypt), or the certificate itself when it
is self-signed. Commit first, and wait for an ACME certificate to be issued.

## Status

The **OpenVPN info** tab shows each OpenVPN process (UDP, TCP) and the connected clients:
user, address, tunnel addresses, traffic, and what checked the password (`local`
or the directory server's name).

## HA pairs

Both hosts of an HA pair run the server, with the same tunnel addresses (no HA
peer addresses): only the active host has clients, and the LAN reaches them
through the VRRP gateway. Point clients at the address the active host has (a
VRRP virtual address on the WAN). After a failover they reconnect to the other
host, log in again, and find the same server address, gateway and DNS server.
