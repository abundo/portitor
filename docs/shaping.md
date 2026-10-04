<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Traffic shaping

Shaping makes the firewall the narrowest point of a link, so the queue builds where
it can be managed: in the firewall, with CAKE, instead of in the modem's large
buffer. The link stays responsive under load (calls and games keep a low latency
while something downloads), and CAKE shares the bandwidth fairly between the hosts
and connections behind it.

## How to set it up

On *Network → Interfaces*, open the WAN interface and set:

| Field | Meaning |
|---|---|
| Shape upload (Mbit/s) | What the interface sends. 0 is off. |
| Shape download (Mbit/s) | What the interface receives. 0 is off. |

Set each a little below what the line really delivers, about 90–95% of a measured
speed test: if the firewall isn't the narrowest point, the queue stays in the modem
and shaping does nothing. Shaping the download direction is less exact than the
upload (the packets have already crossed the line when the firewall delays them),
so leave it a bit more margin.

Deploy, then run a speed test that measures latency under load (a "bufferbloat"
test); the latency should barely rise during the download and upload.

## What happens

- What the interface sends goes through a CAKE queue at the upload rate
  (`tc qdisc ... root cake bandwidth <n>mbit`).
- What it receives is redirected to an IFB device named `ifb-<interface>` (a hash
  for a long name), with a CAKE queue at the download rate. That device is the
  firewall's own: interface names starting with `ifb-` are reserved.
- The agent owns the queues of its interfaces: turning shaping off removes the CAKE
  queue and the redirect. A disabled interface is not shaped.
- It needs the kernel's `sch_cake` and `ifb` modules, which Debian's kernel has.

## Shaping a rule

To cap a host, a network or a service rather than the whole link, make a rate limit
(*Firewall → Rate limits*) with mode *Shape* and a rate in Mbit/s (or kbit/s), and
name it in an accept rule's *Rate limit* field. The connections the rule
accepts are queued to that rate, in each direction, together with those of the
other rules that name the same rate limit. The same rate limit with mode *Police*
would drop what is over the rate instead.

Example: the guest network gets at most 20 mbit/s each way, all guests together,
with *guests* shaping at 20 mbit:

| In | Out | Services | Source | Destination | Action | Rate limit |
|---|---|---|---|---|---|---|
| guest | wan | | | | accept | guests |

How it works:

- The rule marks its connections (as it does for its counters); each packet of
  them gets the shaper's packet mark where it leaves the firewall.
- While any rule of the virtual firewall names a rate limit that shapes, every
  interface of it sends
  through an HTB tree: a class at the interface's *Shape upload* rate (or unlimited),
  and under it one class per shaping rate limit, capped at its rate, plus a default class for
  everything else. fq_codel queues in each. On an interface with upload shaping,
  this replaces CAKE.
- A packet is queued where it goes out, so a forward rule's uploads are shaped on
  the WAN and its downloads on the inside interface. Traffic to the firewall itself
  (an input rule's connections) is shaped only in the firewall's answers: what an
  interface receives has been queued before the rules see it.
- Packets already marked by a hairpin port forward keep their mark and are not
  shaped.

## Shaping or rate limits

| | Shaping | Rate limits |
|---|---|---|
| Where | An interface, both directions; or a rule's connections (a rate limit with mode *Shape*) | A firewall rule |
| Over the rate | Queued (delayed), fairly | Dropped (Police) or queued (Shape) |
| For | The whole link: bufferbloat, fairness | A host, network or service: a cap, flood protection |

They combine: shape the WAN, and cap the guest network with a rate limit on its
rules; see [Rate limits](rules.md#rate-limits).
