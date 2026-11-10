<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Command line and NETCONF

The whole configuration can be read and changed from a command line, on the console
or over SSH, in the style of Nokia SR Linux, and by NETCONF. The commands follow the configuration's
YANG model, so every setting the GUI has is there, by the same names. The CLI and the
GUI work on the same configuration: what you commit in one is in the other.

## Starting it

- **On the console** (or an SSH login to the firewall's own shell):
  `portitor-config cli` as `portitor` (the console login of a firewall installed from
  the ISO, and the service user), or `sudo -u portitor portitor-config cli` as another
  user. You are the console admin and may change everything.
- **Over SSH**, with a GUI user's name and password: set `ssh_listen` in
  `/etc/portitor/config.yaml` (for example `ssh_listen: ":2222"`), restart
  portitor-config, open the port with an input rule, and run
  `ssh -p 2222 admin@<firewall>`. A user with two-factor login is asked for the
  code. The port is separate from the firewall's own SSH (port 22), which stays the
  Linux login.

A user sees and changes what they may in the GUI: global admins everything, global
viewers everything read-only, and an instance admin their virtual firewalls (and
reads the shared hosts, lists and services). Secrets (keys, passwords) can be set but
are never shown.

## Modes

The CLI starts in **running** mode, where it shows what the firewall runs. To make
changes, enter **candidate** mode:

```
--{ running }--[  ]--
admin@fw# enter candidate

--{ candidate shared default }--[  ]--
admin@fw#
```

The line above the prompt shows the mode and where you are in the tree. The candidate
is shared by all CLI sessions; it starts from the configuration as it stands, edits
made in the GUI included.

## Paths and values

The tree is the YANG model's: `instance <name>` is a virtual firewall (the host's has
its firewall's name), with `interface <name>`, `rule <id>`, `route <id>`, `vrf
<name>`, `bgp <vrf>` and so on below it. Hosts, address lists, IP lists and services
are at the top, as are `settings`.

- A path to a leaf and a value sets it:
  `instance fw interface wan0 mtu 1500`
- A path to an entry or container goes there. Later paths are from there:

  ```
  instance fw interface wan0
  kind physical
  addresses [ 192.0.2.10/24 2001:db8::10/64 ]
  ```

- `[ ... ]` sets all the values of a list (`addresses`, `in-interfaces`); a single
  value adds one.
- `/` starts a path from the top: `/ instance fw route 1 gateway 192.0.2.1`.
- `exit` goes up one level, `exit all` to the top, `back` to where you were before.
- A value with spaces is quoted: `description "the uplink"`.

Going to an entry that doesn't exist creates it, in candidate mode. Names may be
shortened while they stay unambiguous (`inst fw int wan0`).

**?** lists what may follow, with a short help; **Tab** completes names, existing
entries and values (interface names where an interface is wanted, and so on).

## Commands

| Command | Does |
|---|---|
| `show [flat\|json\|detail] [path]` | shows the configuration here or at the path; `flat` as `set` lines, `detail` with defaults; in candidate mode the candidate, `show from running` what runs |
| `diff [flat] [path]` | shows the candidate's changes against what runs (`+` added, `-` removed) |
| `set <path> [value]` | sets a leaf or creates an entry, without going there |
| `delete <path> [value]` | deletes a leaf (back to its default), one value of a list, an entry or a container; it warns when other settings still name the entry |
| `rename <path> to <new key>` | renames an entry and what refers to it (rules, routes, zones naming an interface) |
| `move <path> first\|last\|before <id>\|after <id>` | reorders rules, NAT rules and policy routes |
| `commit stay\|now\|validate\|confirmed [seconds]` | commits the candidate (`now` also leaves candidate mode); `validate` only checks it; `confirmed` rolls back unless confirmed in time |
| `confirm`, `rollback` | confirms or rolls back a commit that waits for confirmation |
| `discard stay\|now` | drops the candidate's changes |
| `tools <path> <action> [<input> <value>]...` | runs an action of an entry (see [Actions](#actions)) |
| `tree [path]` | shows the model below here: names, keys and types |
| `show interface [name]` | the interfaces as they run: a table of every virtual firewall's (name, kind, admin and operational state, MTU, MAC, addresses), or a named one's detail with its counters; inside a virtual firewall, its own. Directly in a virtual firewall `interface` is its configuration list, which wins there |
| `show deployments`, `show api <path>` | shows the commits, or the answer of a GET of the API (`show api /api/agent/status`); the version is `show from state / system version` |
| `pwc`, `help`, `quit` | where you are, the commands, log out |

## Actions

Some things are done rather than set: a WireGuard interface's new keys, a
certificate made or renewed, an IP list downloaded now. They are actions of an
entry, run with `tools`, its path, the action and its input:

```
tools instance fw interface wg0 wg-rekey
tools instance fw interface wg0 wg-next-free
tools instance fw interface lan5 move-to instance branch
tools instance fw certificate web generate domains [ fw.example.com ] days 365
tools instance fw certificate le renew
tools ip-list spamhaus update
tools ip-list spamhaus schedule schedule "0 */6 * * *"
tools task backup run
```

`?` after the entry lists its actions, and after the action its input. A leaf-list
takes its values in `[ ]` or one at a time. What an action answers is shown as
leaves (`wg-public-key ...`).

| Action | Of | Does |
|---|---|---|
| `wg-rekey` | interface (WireGuard) | new key pair; its peers need the new public key |
| `wg-next-free` | interface (WireGuard) | the next free peer addresses |
| `move-to instance <vf>` | interface | moves it, with its addresses and peers, to another virtual firewall |
| `chain` | certificate | what an imported certificate's chain says |
| `generate` | certificate | makes a self-signed certificate or CA, or one signed by a CA of the firewall's host |
| `renew` | certificate | orders an ACME certificate now |
| `next-free` | ipam-prefix | the prefix's next free address |
| `update` | ip-list, dns-blocklist | downloads the list now |
| `schedule schedule <cron>` | ip-list | adds a task that downloads it on schedule |
| `run` | task | runs the task now |

A change (`wg-rekey`, `move-to`, `generate`, `schedule`) edits the candidate, so it
needs candidate mode and a commit, like `set`. A view (`wg-next-free`, `chain`,
`next-free`) reads the mode's configuration, and an operation (`renew`, `update`,
`run`) has the firewall do it now, in either mode. What gives a file (a WireGuard
peer's or OpenVPN client's config, a certificate download, a virtual firewall's
bundle) is the GUI's alone.

## State

What the firewall runs and sees is under `state` in each virtual firewall, and
`system` at the top: interfaces with their state, addresses and counters, the
routes, WireGuard peers, the daemons, DHCP leases (client and server), ARP/ND and
LLDP neighbours, each rule's and rate limit's traffic, BGP, OSPF and IS-IS
(neighbours, interfaces, areas), VRRP routers, BFD peers, NTP sources, NAT64 sessions
and OpenVPN clients, and the agent and machine (version, the commit it runs, a commit
waiting for confirmation, memory, CPU, load, disks, and an HA pair's state).
It is read-only and read from the firewalls when shown:

```
show from state / instance fw state interfaces
show from state / system
instance fw state
show
```

Going into `state` (in running mode) shows the state there with a plain `show`. You
see the state of the virtual firewalls you may read; `system` is for global
admins and viewers. `system errors` says what could not be read (a firewall
that doesn't answer).

## Committing

`commit` checks the candidate against the model (types, required settings, names that
must exist), writes it into the configuration and deploys it as the GUI's commit
does, with the same confirm window from Settings. If the deploy fails, the
configuration is left as it was and the candidate keeps your changes.

The GUI and the CLI share the configuration: an edit saved in the GUI but not
committed is also committed by a commit from the CLI, as it is by a commit from the
GUI.

## Pasting and scripts

`show` output can be pasted back: a line ending in `{` goes into the entry, `}` comes
back out. `show flat` writes `set / ...` lines that work from anywhere.

Without a terminal, the CLI runs the lines it is given and stops at the first error:

```
ssh -p 2222 admin@fw 'enter candidate; instance fw interface lan0 mtu 9000; commit now'
portitor-config cli < changes.txt
```

## NETCONF

The same SSH port serves NETCONF (RFC 6241) as the `netconf` subsystem, to the same
users with the same rights:

```
ssh -p 2222 -s admin@fw netconf
```

or, from Python, `ncclient.manager.connect(host="fw", port=2222, username="admin",
password=...)`. The model is the same YANG, namespace `urn:portitor:config`; a client
gets the modules with `<get-schema>` (RFC 6022).

- The **candidate** is the CLI's, shared; **running** changes only by a commit, as on
  SR Linux (no `:writable-running`).
- `<edit-config>` to the candidate with every operation (`merge`, `replace`,
  `create`, `delete`, `remove`) and `default-operation`; an edit is all or nothing.
  `yang:insert` places rules and other ordered entries. A replace that leaves out a
  secret keeps the secret, since a client can't read it back.
- `<get-config>` with subtree filters; `<get>` is running with the state (config
  false: each instance's `state` and `system`). Secrets are left out.
- `<commit>`, with `<confirmed/>` and `<confirm-timeout>` (600 s by default): a plain
  `<commit/>` while one waits confirms it, `<cancel-commit/>` rolls it back. A plain
  commit applies at once, without Settings' confirm window.
- `<action>` (RFC 7950) runs the [actions](#actions): the path to the entry, and
  innermost the action with its input, on the candidate. The reply holds the output,
  or `<ok/>`:

  ```xml
  <action xmlns="urn:ietf:params:xml:ns:yang:1">
    <instance xmlns="urn:portitor:config"><name>fw</name>
      <interface><name>wg0</name><wg-rekey/></interface>
    </instance>
  </action>
  ```
- `<validate>`, `<discard-changes>`, `<copy-config>` to the candidate (from running
  or an inline config), and `<lock>`/`<unlock>` on candidate and running. A lock
  keeps the CLI's sessions out too, and goes when its session ends.
