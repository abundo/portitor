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
- **IPv4 pool**: the IPv4 prefixes the translated packets get their source address
  from, one address for each interface with 464XLAT. The addresses are used only
  inside the firewall: the packets then leave like those of any IPv4 client, through
  the NAT rules. Leave it empty to use `192.0.0.0/29` (RFC 7335, never routed), which
  is masqueraded where it leaves and has room for 8 interfaces. With more, give a
  prefix of your own, such as a `/24` of `198.18.0.0/15` or an unused private range;
  it must not overlap an address or route of the firewall, nor what the WAN gets by
  DHCP. A pool of your own is masqueraded only by your NAT rules.
- **DNS64**: the DNS server synthesizes the IPv6 addresses.

Under *Network → Interfaces*, per interface:

- **464XLAT**: the router advertisements on the interface announce the prefix
  (PREF64), and DHCPv4 on it sends option 108 (IPv6-only preferred, RFC 8925) to
  the clients that ask for it, so those with a CLAT give up their IPv4 address.
  The interface needs router advertisements (turned on under DHCP).

Only packets that come in on an interface with 464XLAT are translated: packets to
the prefix from any other interface are dropped.

## Rules, NAT and shaping

Translated traffic is filtered, NATed, counted and shaped like any other IPv4
traffic. A rule that names an interface with 464XLAT, or an interface zone with it,
also matches the interface's NAT64 traffic. A rule from `lan` to `wan` then also lets
`lan`'s IPv6-only clients reach IPv4 hosts through NAT64, counts their connections,
and its rate limit or shaper applies to them. No rule of its own is needed.

Two things differ from ordinary IPv4 clients, because the translated packets get the
interface's pool address as their source:

- A rule that matches the clients' IPv4 source addresses doesn't match their NAT64
  traffic. Match the interface, or the IPv6 clients' addresses with an IPv6 rule.
- A rate limit per source address counts all of an interface's NAT64 clients as one.

## How it works

Jool translates in the kernel, before the firewall's forward rules would see a
packet. To get the rules applied anyway, each interface with 464XLAT has a **loop
device**, `n64-<interface>` (`n64-lan` for `lan`), and its own address from the IPv4
pool (`192.0.0.0` for the first, `192.0.0.1` for the next, in the order of the
interfaces' names). Interface names can't start with `n64-`.

A client on `lan` opening a connection to `64:ff9b::192.0.2.1`:

1. The IPv6 packet comes in on `lan`. The firewall marks it as `lan`'s (the
   `prerouting_nat64` chain).
2. Jool translates it to IPv4. The mark makes it use `lan`'s pool address as the
   source: `192.0.0.0 → 192.0.2.1`.
3. A routing rule sends what Jool sends from `192.0.0.0` to `n64-lan`, which hands
   every packet straight back to the firewall, as if it had come in on `n64-lan`.
4. The packet is forwarded like any other: the forward rules see it coming in on
   `n64-lan` (a rule naming `lan` matches it), the connection is counted under the
   rule, and the rule's shaper marks it.
5. It leaves on the WAN, where the NAT rules (or the masquerade of the default pool)
   give it the WAN's address, and the WAN's shaping queues it.

The reply comes in on the WAN. Undoing the NAT gives it the destination
`192.0.0.0` again, and Jool translates it back to IPv6 right away, before the
forward chain, so replies don't go round the loop. The `nat64_reply` chain gives
them what the forward chain would: the rule's rate limit, shaper mark and counter.
The reply leaves on `lan`, where the shaper queues it.

## Troubleshooting

On the firewall, as root, in the virtual firewall's namespace
(`ip netns exec fw-<name> ...`) for a virtual firewall:

- `jool -i portitor pool4 display --icmp` (or `--tcp`, `--udp`): one entry per
  interface with 464XLAT, with its mark and pool address. Empty means Jool sends
  translated packets straight out with the WAN's address, past the rules and
  shapers; a commit makes Jool's instance again.
- `jool -i portitor session display --numeric --tcp`: the clients' sessions and the
  pool address each one got.
- `ip rule` and `ip route show table all proto 99`: a rule `from <pool address> iif
  lo` per loop device, and its table with the default route to `n64-<interface>`.
- `ip -br link | grep n64-`: the loop devices, which must be up.
- `nft list chain inet firewall prerouting_nat64` and `nft list chain inet firewall
  nat64_reply`: the marks, and what the replies get.
- `tcpdump -ni n64-lan`: the translated packets going round the loop.

## Requirements

Jool is a kernel module, built by DKMS: the installer and the Portitor update
install `jool-dkms`, `jool-tools` and the kernel headers. With Secure Boot, the
module must be signed with a key enrolled with `mokutil`, or it won't load.

A firewall that has rebooted, or a virtual firewall whose namespace is made again,
gets its Jool instance back at the next commit or start of the agent.
