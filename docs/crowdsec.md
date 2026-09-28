<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Blocking with CrowdSec

[CrowdSec](https://www.crowdsec.net) collects attacking addresses: those its engine
detects in your own logs, and a community blocklist built from what every engine
reports. Portitor can drop traffic from them. Portitor acts as the *bouncer*: it
downloads the ban decisions into an IP list, and your rules use that list as `@name`.

There are two ways to get the decisions:

- **Run a CrowdSec engine** (recommended). Portitor reads its Local API (LAPI). You get
  the community blocklist and the engine's own detections.
- **Use a CrowdSec Console blocklist integration**, with no engine at all. Portitor
  downloads a plain IP list from the Console. What you can subscribe to depends on
  your Console plan.

## With a CrowdSec engine

### 1. Install the engine

Installing it on the firewall host is easiest: the agent downloads lists from the
host's own network (the default instance), so it reaches the LAPI on `127.0.0.1`.
On Debian or Ubuntu:

```sh
curl -s https://install.crowdsec.net | sudo sh
sudo apt install crowdsec
```

Don't install `crowdsec-firewall-bouncer-nftables` or another firewall bouncer.
Portitor is the bouncer, and a second one would only add its own nftables tables
beside Portitor's.

Check that the engine is registered with CrowdSec's Central API, which is where the
community blocklist comes from:

```sh
sudo cscli capi status
```

The community blocklist is filtered to the scenarios your engine runs. The default
collections (Linux, SSH) already give you a list; installing more collections
(`sudo cscli collections install ...`) widens it.

The engine refreshes the community blocklist from the Central API every two hours or
so.

### 2. Create a bouncer key

```sh
sudo cscli bouncers add portitor
```

It prints an API key, and shows it only once. Copy it.

### 3. Add the IP list in Portitor

*Firewall → IP lists → New IP list*:

| Field | Value |
|---|---|
| Name | `crowdsec` (rules then use `@crowdsec`) |
| Source | CrowdSec Local API |
| URL | `http://127.0.0.1:8080` |
| Bouncer API key | the key from step 2 |

The key is stored by portitor-web and never shown again. To change it, enter a new
one; leaving the field empty keeps the stored key.

### 4. Add rules that drop it

*Firewall → Rules*. Put the rules near the top of their chain, since the first match
decides:

- an **input** rule: incoming interface your WAN (`wan` or its interface zone), source
  `@crowdsec`, action drop. This protects the firewall itself.
- a **forward** rule: the same, for port forwards and anything else reaching your
  network.

Enable *Log matches* on them if you want to see the drops in the kernel log.

A list matches IPv4 and IPv6, so each rule covers both.

### 5. Schedule the download

*Services → Scheduled tasks → New task*:

| Field | Value |
|---|---|
| Name | `crowdsec` |
| Task | Download an IP list |
| IP list | `@crowdsec` |
| Schedule | `*/15 * * * *` (the *Every 15 min* preset) |

Every 15 minutes catches the engine's own bans soon after it makes them. The
community blocklist itself changes less often.

### 6. Deploy and check

Deploy. The agent downloads the list right away; after that, the task downloads it
again on its schedule.

- *Firewall → IP lists* shows the state, the number of IPv4 and IPv6 entries, and when
  the list was last downloaded. The refresh button downloads it now.
- *Services → Scheduled tasks* shows the next run and the result of the last one. The
  play button runs the task now.
- On the firewall, compare the counts with the engine's decisions:

  ```sh
  sudo cscli metrics                       # "Local API Decisions", origin CAPI = community list
  sudo nft list set inet firewall crowdsec_v4 | head
  ```

### The engine on another host

The LAPI listens on `127.0.0.1:8080` by default. To run the engine elsewhere, make
it listen on an address the firewall can reach: set `api.server.listen_uri` in
`/etc/crowdsec/config.yaml` (for example `0.0.0.0:8080`), restart crowdsec, and allow
only the firewall to reach that port. In Portitor, use `http://<engine-host>:8080`
as the URL.

The firewall host downloads the list through its own routes, so it needs a route to
the engine.

## With a Console blocklist integration

1. In the CrowdSec Console (app.crowdsec.net), subscribe to the blocklists you want.
2. Under *Blocklists → Integrations*, create an integration for a generic firewall /
   raw IP list, and subscribe the blocklists to it. The Console shows an endpoint URL,
   a username and a password.
3. In Portitor, *Firewall → IP lists → New IP list*:

   | Field | Value |
   |---|---|
   | Source | URL |
   | URL | the endpoint URL |
   | Username, password | from the integration |

4. Add the rules and the scheduled task as in steps 4 to 6 above. Once an hour is
   plenty for Console blocklists.

## When something goes wrong

The IP lists page shows the last error of each list:

- `connection refused`: the LAPI isn't listening where the URL says. Check
  `sudo systemctl status crowdsec` and the listen address.
- `403 Forbidden`: wrong bouncer key. Run `sudo cscli bouncers list`, then add a new key
  and enter it in Portitor.
- `401 Unauthorized` (integration): wrong username or password.
- *not deployed* in the State column, and a disabled refresh button: the list isn't in
  the deployed configuration yet. Deploy first.

A failed download keeps the last good list in force, including across an agent
restart, so a CrowdSec outage doesn't open the firewall.
