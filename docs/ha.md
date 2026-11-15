<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# High availability (HA pairs)

Two firewalls can run as an **HA pair**: one **active** host forwards and answers for
the pair's addresses, and a **standby** with the same configuration waits to take over.
The two have the same addresses and the same MAC addresses on their traffic
interfaces, so when the standby takes over, the clients keep their gateway, their
DHCP leases and their open connections.

- **Every commit goes to both.** A change is applied to the two hosts together, waits
  for confirmation on both, and is rolled back on both if either fails.
- **Only one host is open.** The standby's traffic interfaces stay up but closed: it
  sends and takes nothing on them. A host opens only with a vote from a third party,
  the **witness**, or when its peer hands over, so two hosts that can't hear each
  other never both answer for the same addresses.
- **State follows.** DHCP leases, open connections and ACME certificates are copied to
  the standby as they change.
- **The configuration survives.** portitor-config on the primary holds the pair's
  configuration; the secondary's keeps a read-only copy, and can be **promoted** when
  the primary is lost.

**Primary and secondary** say who owns the configuration. **Active and standby** say who
forwards. Either host can be active; a failover changes no configuration.

## What you need

- **Two firewalls with the same interface names** (`ens18`, `ens19`, ...). The
  secondary runs the primary's interfaces by name.
- **Two interfaces of their own on each host**, besides the traffic interfaces:
  - the **HA link**, a direct cable between the hosts (or a VLAN only they share);
  - the **management** interface, on a network of its own, with the witness, the GUI
    and the host's own traffic (updates, NTP, ACME, DNS blocklist downloads).

  The two must not share a failure: with one switch carrying both, losing that switch
  would close both healthy hosts.
- **portitor-agent and portitor-config on both** (`install.py --agent HOST` installs
  both).
- **An external witness** for an automatic failover: portitor-web on a third host on
  the management network, usually the portal ([HA pair and
  portal](deployments.md#ha-pair-and-portal)). Without one, the primary's
  portitor-config is the witness and goes with the primary: the pair still never has
  two active hosts, but losing the primary takes a step by hand (see [The
  witness](#the-witness)).
- **Hypervisors that allow changed MAC addresses** on the traffic interfaces (Proxmox's
  MAC filter off, VMware's *forged transmits* on), as both hosts use the pair's MAC
  addresses.
- **A watchdog.** The active host arms one, so a hung host resets and the standby
  takes over. The agent loads `softdog` if there is nothing better, which covers a
  hung agent but not a hung kernel; on Proxmox, add the `i6300esb` watchdog device.
- **conntrackd** on both (`install.py` installs it).

## Step by step from the ISO

Three machines, set up in this order. The two firewalls come first, the portal last,
because it needs both firewalls' fingerprints and the witness string. Every machine
is installed from the same [installer ISO](appliance.md); the first-boot setup asks
what it is.

**The shortest way: from the portal.** Nothing has to be copied between hosts, which
helps on physical hardware or a hypervisor console without paste:

1. Install the portal (ISO *web*) and log in.
2. Install the primary (ISO *primary*; choose *Later* when it asks for a secondary
   string) and the secondary (ISO *secondary*; ignore the secondary string it shows).
3. In the portal, *Add HA firewall*: give the pair a name and leave *Witness* on.
4. In its form, *Add* the primary: its address and an SSH login (the user
   `portitor` and its password), and confirm its SSH host key.
5. *Add* the secondary the same way, at its management address. The two are not a
   pair yet, so the portal also asks for the login to the primary (its host key was
   confirmed in step 4).

The portal logs in to the secondary and reads its details (`portitor-config
secondary-info`: name, ports, agent token and the two certificate fingerprints),
logs in to the primary and gives them to `portitor-config add-secondary`, which adds
the secondary under *Admin → Firewalls*, sets the primary's management *HA peer
address* and commits the pair, and with the witness checked sets *HA witness* to
*External* and has the portal take the pair's `witness-string` (it must reach both hosts'
management addresses). The pair is one firewall in the portal, served by whichever
host is primary now. Adding two hosts that are a pair already only checks that they
are, and asks for no second login. The agent token
travels over the two SSH connections only and is never kept by the portal. The SSH
passwords are used for these connections and not stored. The steps below are the
same by hand.

**Before you start.** Cable the HA link between the two firewalls, and put both
*management* interfaces (and the portal's second interface) on the same management
network. Both firewalls need the same interface names. Note the management address of
each host.

1. **Install the primary.** At first boot pick the machine type *primary*. It asks, besides the
   usual, for the *management* interface, its address and gateway (optional: left empty,
   the secondary uses the primary as its gateway, `peer` below), and the *HA link*
   interface (no address). Choose a password for the user `portitor`: it is the
   password of the GUI and of the console and SSH on this host. Wait for the setup to
   finish: it ends by asking for a secondary string. Choose *Later* for now.
2. **Install the secondary.** Pick *secondary*. It asks only for its management
   interface, address and gateway (optional, as on the primary), and its HA link. At the end it shows a **secondary
   string** (`portitor-secondary:...`). It holds the secondary's agent token: keep it
   to yourself. `sudo portitor-setup --show-join` on the secondary shows it again.
3. **Add the secondary to the primary.** Paste the string into the primary's setup,
   or log in on the primary (`ssh portitor@<primary management address>`) and run:

   ```
   sudo portitor-setup --join
   ```

   and paste it when asked. This adds the secondary under *Admin → Firewalls* and
   commits the pair. Check it with `portitor show ha` on either host.
4. **Log in.** The GUI is `https://<management address>/` on either host, user
   `portitor`, with the **primary's** password: the secondary's portitor-config is a
   read-only copy of the primary's database, so the primary's users apply on both.
   Configure the pair (rules, interfaces, services) on the primary only.
5. **Install the portal (and witness).** Pick *web*, with the two interfaces (one on
   the management network). At the end choose *Later*: the pair's hosts are added
   next, one at a time.
6. **Add both firewalls to the portal.** Each host of a pair prints a **portal
   string** (`portitor-portal:...`): on each firewall run

   ```
   sudo portitor-setup --show-join
   ```

   (on the secondary it prints the secondary string too; the portal string is the
   last part). Then on the portal host, once for each string:

   ```
   sudo portitor-setup --join
   ```

   and paste it when asked, or `sudo portitor-setup --join <portal string>`. The
   strings name the hosts by their **host names**, which must differ (a portal keeps
   one entry per name: the second would replace the first). They hold each host's
   management address, GUI port (443) and certificate fingerprint, and no secret.
   Each firewall already trusts the management network for `trusted_proxies`, so the
   portal needs an address there. The strings add the two hosts as two firewalls of
   the portal; to have the pair as one, served by whichever host is primary now, add
   it in the portal's GUI instead (*Add HA firewall*, then its two hosts: a pair
   already made is only checked).
7. **Check.** On the portal host:

   ```
   portitor-web check                      # both must answer
   ```

   `does not answer` means the portal cannot reach the firewall's GUI: a wrong
   address, or a portal that is not on the management network. The firewall's ruleset
   lets the management interface reach SSH and the GUI, not ping, so a failed ping
   proves nothing.

   Without the ISO (`install.py`), add each host in the portal (*Add firewall*,
   which reads the fingerprint over SSH; or by hand, `https://<management address>:443` and
   the `portitor-config fingerprint` of the host), and put the portal's
   address in `trusted_proxies` in the host's `/etc/portitor/config.yaml`
   (`sudo systemctl restart portitor-config`).
8. **Let both logins work as one.** In the primary's GUI, under *Admin → Firewalls*,
   check that each host has its *portitor-config URL* (`https://<management address>:443`)
   and *fingerprint*. The portal uses them to know the two hosts are a pair and to
   share the login. The setup fills them in on its own; check them if the login on the
   portal asks again for the other host.
9. **The witness, for automatic failover.** In the primary's GUI, under *Admin →
   Firewalls*, set *HA witness* to *External* on the primary and commit. Then on the
   primary run `portitor-config witness-string` (or copy the *Witness string* from the
   form) and add it in the portal's *HA witness* page, or
   `sudo -u portitor portitor-web add-witness portitor-witness:eyJwYWlyIjoi...`.
   The portal is now the pair's witness. Without this step the
   pair works, but if the primary fails the secondary stays closed until you open it
   by hand (see [The witness](#the-witness)).
10. **Open the portal** at `https://<portal address>/`. Log in at each firewall with
    `portitor` and the primary's password.

**If the login says "wrong username or password"** on a host where the console
password works: the console login (a system account) and the GUI login (portitor-config's
database) are separate. Set the GUI password again on the primary:

```
sudo -u portitor portitor-config createadmin portitor
```

The secondary follows within about 15 seconds.

## Setting up a pair

By hand, or with the ISO, everything is done in the primary's portitor-config; the ISO's
steps are listed above.

1. **The two links.** On the primary's host, under *Network → Interfaces*, give one
   physical interface the *HA role* *HA link* and another *Management*. The HA link
   takes no address: the hosts use the IPv6 link-local addresses `fe80::1` (primary)
   and `fe80::2` (secondary) on it, fixed by role, and each virtual firewall
   `fe80::<id>:1` and `fe80::<id>:2` on a device of its own there. The management
   interface gets its address(es), and under *HA peer addresses* the secondary's, in the
   same prefix and order, and its *Management gateway*, which the host uses for its own
   traffic while its traffic interfaces are closed: a router on the management
   network, or `peer` (see [The management gateway](#the-management-gateway)).
2. **The primary's agent URL** under *Admin → Firewalls* is its management address
   (`https://172.25.38.1:8443`), not `127.0.0.1`: the secondary and the witness use it.
   Set its *portitor-config URL* (`https://172.25.38.1:8444`) and *fingerprint*
   (`portitor-config fingerprint` on it), for the secondary to copy from.
3. **The secondary**: *New firewall*, with its agent URL (its management address),
   token and fingerprint (`portitor-agent init` there prints them), its
   *portitor-config URL* and *fingerprint*, and *HA secondary of* the primary. This can
   only be chosen when the firewall is created. The secondary has no virtual firewalls
   of its own: it runs the primary's.
4. **The witness.** On the primary, set *HA witness* to *External* and copy the
   *Witness string* to the third host (see [The witness](#the-witness)).
5. **Commit.** Both hosts get the configuration; confirm it as usual.

A commit lists what is missing (`HA: interface ens21: the secondary needs an address of
its own for each address (peer addresses)`). The agents reach each other on the HA
link's link-local addresses and their management addresses, both on the agent's port:
in each `/etc/portitor/agent.yaml`, `listen` on all addresses (`":8443"`, which takes
IPv6 too), and `allow_from` the witness's addresses (the peer's heartbeats carry the
pair's secret, which `allow_from` doesn't apply to).

Everything else (traffic interfaces, rules, routes, services, virtual firewalls) is
the same on both hosts. VRRP is refused on a pair: the pair shares its addresses
itself.

From that commit on, the secondary's portitor-config is a **replica**: it copies the
primary's database every 15 seconds (when it changed), users included, and refuses
changes. Its GUI shows an *HA secondary* badge with the last copy. Log in there with
the primary's users.

## Who is active

The hosts send each other heartbeats every half second, over the HA link and over
management. Two kinds of lease decide which host is open:

- **The witness's vote** goes to one host at a time, for 4 seconds, renewed every
  second while that host answers. It follows the active host.
- **The standby's promise** to stay closed, for 2 seconds, comes back with each
  heartbeat answer.

The active host stays open while it holds either. A host opens only with the vote,
once the promises it gave have run out and it hears no active peer, or when its peer
hands over. A healthy pair needs no witness to run: at start the primary opens on the
secondary's promise.

| What fails | What happens |
|---|---|
| The active host (power, kernel, hung agent) | Its vote runs out and the witness gives it to the standby, which opens: about 6 seconds. A hung agent or kernel is reset by the watchdog. |
| A monitored traffic interface on the active host loses its carrier | The standby has more monitored interfaces with a carrier for 2 seconds: the active host hands over (about 3 seconds). |
| The HA link | The heartbeats go over management. Nothing moves. |
| The management network | The hosts hear each other over the HA link. Nothing moves. |
| The witness | Nothing moves while the hosts hear each other. |
| Both links, from the active host | It can't renew its leases and closes; the standby opens with the witness's vote. |
| The HA link and management together | The active host closes; the standby can't get the vote: **both closed** until one comes back, or [by hand](#on-the-console). |

**Interface monitoring.** Physical traffic interfaces are monitored by default (*HA
monitor* on the interface); turn it off for one a failover wouldn't help. After a
monitored handover, that host doesn't hand over again for a minute, so a flapping link
moves the traffic there and back at most.

**There is no automatic failback.** A host that comes back joins as the standby. Move
the traffic by hand with *Switch over* under *Admin → Firewalls* (on either host's
form), or `portitor request ha switchover` on the active host.

**Handover.** A switchover, a monitored handover and a clean stop of the active agent
(an update, a reboot) hand over: the active host closes and the standby opens at once,
taking the vote. Clients lose a packet or two. A host that restarts comes up closed.

**At takeover** the new active host sends gratuitous ARP and unsolicited neighbour
advertisements for every address, twice, router advertisements at once, and clears
its BGP sessions so they come up without waiting for a retry timer. OSPF waits for its
hellos.

In the lab, with a download through the pair held open across each event:

| Event | Outage | Download |
|---|---|---|
| Switchover | One ping lost at most | Survives |
| Clean restart of the active agent | One ping lost at most | Survives |
| A traffic interface's carrier lost on the active host | 2.7 to 2.9 s | Survives |
| Active host hard reset | 5 to 6 s | Survives |

## What the pair keeps in step

| | How |
|---|---|
| **Configuration** | Kept by the primary's portitor-config, copied by the secondary's. Every commit goes to both hosts. If one can't be reached and the other can, the commit goes to the reachable one, and the other is shown as *skipped*: it gets the commit as soon as it answers again. |
| **DHCP leases** | The active host sends every change to the standby over the HA link: a new lease is on the standby before the client gets its answer, renewals within a second. A standby that missed changes gets all the leases first. After a takeover, a client that renews an address the new host doesn't know keeps it, and a new client is never given an address another host answers for. |
| **Connections** | conntrackd sends each host's connections to the other, which keeps them in its own table, so connections through the firewall live on after a takeover. Each virtual firewall syncs over a device of its own on the HA link. Connections to the firewall itself (SSH to it, say) end there. |
| **DHCP clients** (a WAN by DHCP) | Run on the active host only. The standby keeps the lease and address behind its closed interfaces, so masqueraded connections survive; the new active host renews it, with the same MAC address and DHCPv6 DUID. |
| **ACME certificates** | The active host orders and renews them; the standby copies them every minute, so it has them when it takes over. |
| **DNS updates, tunnel broker** | Only on the active host, so the two never publish their addresses in turn. |
| **IP lists, DNS blocklists** | Each host downloads them over management. |

Services (DNS, NTP, router advertisements, FRR, WireGuard, OpenVPN) run on both hosts;
the standby's are behind its closed interfaces, so a takeover starts nothing.

Each static traffic prefix has a blackhole route at the highest metric, so traffic for
the clients of a dead link isn't sent out of the WAN while the standby takes over.

## The management gateway

The traffic interfaces of the standby are closed, so what the host sends itself
(updates, NTP, ACME, IP list and DNS blocklist downloads, syslog) goes by the
management interface's *Management gateway*. It is one of two:

- **A router on the management network**, with its own way out. The pair's own
  traffic then doesn't depend on either host.
- **`peer`**, when there is no such router (one address from the ISP, say): each host
  uses the other's management address. The active host forwards what the standby sends
  from its management address and masquerades it where it leaves (the auto rule *ha
  peer gateway*), as it does the LAN's. Only the closed host uses the gateway; the
  active host's own traffic leaves by its traffic interfaces. After a takeover the
  roles swap with no change. The standby reaches the internet only while the active
  host and the management network are up, which is when it has traffic to carry
  anyway.

## The witness

A pair has one witness, never two: two could each vote for another host.

- **External** (*HA witness*: *External*): portitor-web on a third host on the
  management network, which may be the portal or not. Set it on the primary under
  *Admin → Firewalls*, commit, and copy the *Witness string* (or `portitor-config
  witness-string` on the primary's console) into the portal's *HA witness* on the third
  host (or `portitor-web add-witness <string>` there). `portitor-web start` (the portal) is then the witness too; `portitor-web witness`
  is the witness alone, without the GUI. The string holds both agents' URLs and
  certificate fingerprints, and the pair's witness secret, which opens nothing on the
  agents but the state and the vote. The agents must let the third host in
  (`allow_from`).
- **The primary's portitor-config** (*HA witness*: *This firewall's portitor-config*,
  the default). Nothing else to run, and the pair never has two active hosts. But it
  goes with the primary: when the primary is lost, the secondary stays closed until you
  open it by hand (`portitor request ha active`) and
  [promote](#promoting-the-secondary) it.

## On the console

On either host, as root:

```
portitor show ha                          # state, peer, vote, monitored interfaces, watchdog, DHCP lease sync
portitor request ha switchover            # on the active host: hand over to the standby
portitor request ha active --minutes 60   # break glass: open without the peer or the witness
```

`portitor request ha active` is for a host that hears neither its peer nor the witness
(both links down, the witness gone). It is logged. Never use it while the other host
may still be running: both would answer for the same addresses.

*Admin → Firewalls* shows each host's role and state in the *HA* column; a host's form
has the same as `portitor show ha` under *HA state*, with *Switch over*.

## Updates

`./install.py` updates a pair one host at a time, the secondary first. Each agent
restart hands over cleanly, so clients lose a packet or two at most each time.

Keep to that order across the release that moved portitor-config's state from its
database into files: the secondary's portitor-config, updated first, still copies
the database file of a primary that has not been updated (and adopts its users, roles,
directory and firewalls from it); a primary that has been updated gives its secondary
the files, which one not updated cannot read. Update the pair together, and the
secondary first.

## Promoting the secondary

When the primary is lost (dead hardware, a site gone), promote the secondary: its
copy of the configuration becomes the pair's.

- In the secondary's GUI: the *HA secondary* badge in the top bar, then *Promote* (a
  global admin). Or on its console: `sudo -u portitor portitor-config promote`.
- It is refused while the secondary's agent hears the primary: promote only a
  secondary whose primary is gone. `--force` (or *Force* in the GUI) promotes anyway;
  then both believe they own the configuration until the old primary is caught up.

The promotion swaps the two hosts in the configuration: the virtual firewalls and
tasks move to the secondary, the management addresses swap with their *HA peer
addresses* (and the HA link's by role), the old primary becomes the secondary, the pair's **epoch** goes
up, and it commits. The commit skips the old primary while it is away.

When the old primary comes back, it hears its peer answer as primary at a higher epoch:
it has been taken over, so it stays closed (*stale*) and refuses configurations of the
earlier epoch. Its portitor-config becomes a replica of the new primary, which then
catches it up, and it takes part as the secondary. To drop it instead, delete it under
*Admin → Firewalls* and add a new secondary later.

Lost with the primary: changes made there since the secondary's last copy, and the
*Revert* snapshots (Revert works again after the next commit).

## Troubleshooting

- **Both hosts show *peer: not heard*.** The heartbeats go to the agent on the peer's
  HA link (`fe80::1`, `fe80::2`) and management addresses: check `listen` and
  `allow_from` in each `agent.yaml`, the fingerprints, and that IPv6 is not turned off
  on the HA link (`ping fe80::2%ens20` from the primary). The agents log `ha:` lines (`journalctl -u
  portitor-agent | grep ha:`).
- **A host shows *fenced*.** It hears neither its peer nor the witness. Check both
  links and that the witness is up (portitor-web logs `witness:` lines). *stale* is an
  old primary that was taken over: wait for the new primary to catch it up.
- **Clients lose their gateway after a takeover.** The hypervisor or switch drops
  frames from the pair's MAC address on the new host: allow changed MAC addresses.
- **`DHCP leases ... not sent`** in `portitor show ha`: the active host can't reach the
  standby's agent. Clients still get leases; after a takeover they keep their
  addresses when they renew.
- **The watchdog is `softdog`.** A hung kernel isn't caught: add a hardware or emulated
  watchdog (`i6300esb` on Proxmox).
- **The secondary's copy fails** (the *HA secondary* badge shows the error): check
  the *portitor-config URL* and *fingerprint* of the primary under *Firewalls*
  (commit after setting them), and that the secondary reaches port 8444 there (the
  auto rule *portitor-config peer* on the primary).
- **A commit lists HA problems.** Each names the host and what is missing (an HA link
  or management interface, a peer address, a management gateway).
