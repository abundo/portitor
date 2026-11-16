<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# portitor-web, the portal: the code map

Moved from AGENTS.md; keep it up to date with the code as AGENTS.md is.

**portitor-web, the portal** (`web/portal.go`, `portalapi.go`, `portalstore.go`,
`portalssh.go`, `web.yaml`), is optional and standalone, with a configuration of
its own: a tree of the YANG module `yang/portal/portitor-portal.yang`
(`schema.LoadPortal`; `firewall`, `ha-firewall` (an HA pair as one firewall: its
`primary` and `secondary` hosts; names shared with `firewall`, `portalCheck`),
`witness` (the string is `px:secret`) and `user` lists), kept as a firewall's is: a `datastore.Store` candidate (`candidate.json`)
and what runs, `<data_dir>/portal.json` (`PortalStore`, whose `portalBackend`
commits by writing it; `portalCheck` is its `Store.Check`; proxies and the witness are
rebuilt on a commit, and when another process commits, `Watch`). The GUI's and the
console's edits are an edit and a commit in one (`PortalStore.Edit`). The same
frontends reach it as a firewall's: `portitor-web cli`, the CLI and NETCONF over
SSH on `ssh_listen` (`portalcli.go`; the portal's users, all access), with the
module's name, namespace and files taken from the schema root (`schema.Compile`,
`Node.ModuleNamespace`), not constants. `web.yaml` is only what it needs to start (`bind`, TLS, `data_dir`); its
old `firewalls:` and `witness:` are taken into an empty tree once. It has its own
users (`portitor-web createadmin`, bcrypt hash `px:secret`, a signed cookie, key
in `session.key`), and everything but its shell and login is behind them,
`/fw/<name>/` too. Its GUI is a second entry of the Vue frontend (`web/frontend/portal.html`,
`src/portal/`: hash routes, `/portal/v1` through `src/portal/api.js`), built into
`web/static` beside `index.html` and served from `staticFS()` (`handlePage`, the assets
before login), sharing the firewall GUI's frame (`layout/AppShell.vue`, which knows no
store), `DataGrid`, dialogs and form rules. A firewall's GUI opens in a tab of the
portal (`src/portal/tabs.js`: an iframe of `/fw/<name>/`, kept loaded; closing it or
logging out asks the frame's `window.portitorConfirmDiscard`); opened on its own, its
top bar leads back (`PortalLink`, hidden when framed). A firewall
is added by `POST /portal/v1/probe`: SSH to the host (the host key is returned for
the administrator to confirm before any login; credentials are never stored), which
runs `portitor-config portal-info` (as the service user through `sudo` unless root)
for its port and `tls_cert` fingerprint. An HA firewall's hosts are added one at a
time the same way (`web/portalpair.go`, `POST /portal/v1/ha/<name>/<role>`,
`AddHAHost`); when the second is added the portal pairs them, unless they are a pair
already (each portitor-config's public `GET /api/pair`: replica or not, and its pair's
`config_fingerprint`s): over SSH to the secondary `portitor-config secondary-info`
(`web/pairing.go`: name, ports, the agent token and both fingerprints, which
portitor-config holds; the portal adds the address it reached the host on), then over
SSH to the primary (its confirmed host key) `portitor-config add-secondary`
(`AddSecondary`, in-process console requests: the firewall row with `ha_primary_id`,
the management interface's `peer-addresses`, commit and confirm; `portitor-setup
--join` runs it too, so the logic is there alone), and with the HA firewall's
`witness` `--external-witness` and `witness-string` into the portal's witness list.
The login to the host added first is asked for again (`HAHostRequest.Other`, 409
without it). The token goes on standard input only, the SSH credentials are never
kept, and the portal runs these fixed commands only (`configCommand`). An HA firewall
is served at `/fw/<name>/` from its host that answers as no replica (`settleHA`,
asked every 5 s by `watchRoles`; one transport per host, `hostsTransport`), its
session cookie on that one path. It serves each firewall it lists at `/fw/<name>/` with
`httputil.ReverseProxy` to that firewall's portitor-config (its `tls_cert` pinned
and asked for by `PinnedServerName`, so a certificate chosen under Settings never
breaks the pin), streams flushed as they come, the console's WebSocket passed
through, the browser's `Host` kept, `X-Forwarded-For` (believed by portitor-config
from `trusted_proxies` only, for the login limits) and `X-Forwarded-Prefix`, which
portitor-config writes into index.html as `<base>` (`serveIndex`). Session cookies
are kept to `/fw/<name>/` (`portalCookies`), so each firewall has its own login,
but an HA pair's: portitor-config signs sessions with a key made from the pair's
secret (`sessionKey`; the users are the replica's copy) and names both hosts'
`config_fingerprint`s in `X-Portitor-Pair` (`PairHeader`), and the portal sets the
cookie on the paths of the firewalls it pins by them (`pairPrefixes`). `/` is the
shell, and `/portal/v1/firewalls` lists the firewalls for it and the GUI's switcher.
