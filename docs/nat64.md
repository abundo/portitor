<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# NAT64 and 464XLAT

With NAT64, clients that have only IPv6 can still reach IPv4 hosts. A NAT64 gateway
translates IPv6 packets sent to the **NAT64 prefix** (usually the well-known
`64:ff9b::/96`) to IPv4: the IPv4 address `192.0.2.1` is reached as
`64:ff9b::192.0.2.1`. Clients find those addresses in one of two ways:

- **DNS64**: the DNS server answers a name that has only IPv4 addresses with IPv6
  addresses in the prefix. This works for any client, but only for names, and not
  for programs that use IPv4 literals.
- **464XLAT** (RFC 6877): the client has a CLAT, a small translator of its own
  (Android, iOS and macOS have one), that gives programs an IPv4 address and sends
  their IPv4 packets as IPv6 to the prefix. The NAT64 gateway is then the PLAT.
  The client learns the prefix from the router advertisements (PREF64, RFC 8781).

Portitor can be the NAT64 gateway itself, with [Jool](https://nicmx.github.io/Jool/),
in every virtual firewall that has it turned on, or announce the prefix of another
router that does it.

## Settings

Under *Network → NAT64*, per virtual firewall:

- **NAT64 prefix**: `64:ff9b::/96`, or a network-specific prefix of length 32, 40,
  48, 56, 64 or 96. Use a network-specific one if the clients must reach IPv4
  hosts with private addresses: RFC 6052 keeps those out of the well-known prefix.
- **Translate here**: Jool translates the prefix on this firewall. Off, another
  router is the gateway and must have a route to it.
- **IPv4 pool**: the IPv4 prefixes that translated packets leave from. They must be
  routed to the firewall. Leave it empty to use the address of the interface the
  packets leave on, the WAN's, as NAT44 masquerade does; Jool then uses ports
  61001-65535 of it.
- **DNS64**: the DNS server synthesizes the IPv6 addresses.

Under *Network → Interfaces*, per interface:

- **464XLAT**: the router advertisements on the interface announce the prefix
  (PREF64), and DHCPv4 on it sends option 108 (IPv6-only preferred, RFC 8925) to
  the clients that ask for it, so those with a CLAT give up their IPv4 address.
  The interface needs router advertisements (turned on under DHCP).

Only packets that come in on an interface with 464XLAT are translated: packets to
the prefix from any other interface are dropped. Jool translates before the
firewall's forward rules, so those rules don't see translated traffic, and the rule
counters don't count it.

## Requirements

Jool is a kernel module, built by DKMS: the installer and the Portitor update
install `jool-dkms`, `jool-tools` and the kernel headers. With Secure Boot, the
module must be signed with a key enrolled with `mokutil`, or it won't load.

A firewall that has rebooted, or a virtual firewall whose namespace is made again,
gets its Jool instance back at the next commit or start of the agent.
