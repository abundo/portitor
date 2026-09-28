<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub:
[Report a vulnerability](https://github.com/abundo/portitor/security/advisories/new).
Do not open a public issue.

Include what you can of:

- the affected component (`portitor-web`, `portitor-agent`, `install.py`) and version
  (shown in the GUI's top bar),
- steps to reproduce, or a proof of concept,
- the impact as you see it.

You will get an answer as soon as possible. Fixes are released as a new version, and
the advisory is published once a release is available.

## Supported versions

Only the latest release gets security fixes. Update with `install.py`.

## Scope

Portitor is a firewall, so we are especially interested in:

- anything that lets traffic through that the deployed rules should drop,
- ways around commit-confirm or the anti-lockout rule,
- unauthenticated or unauthorised access to the agent API or the web GUI,
- input that reaches an nftables, BIND, Kea, radvd or WireGuard file without being
  validated,
- secrets (WireGuard keys, agent token, password hashes) leaking to the browser or
  into deployment history.

The design assumes portitor-web runs on a trusted host other than the firewall and is
not exposed to the internet. See [Safety](README.md#safety) for the security model.
