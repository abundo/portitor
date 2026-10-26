<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Directory

**Admin → Directory** holds who may log in: the firewall's own **users** and
**roles**, and the **OpenLDAP** and **Active Directory** servers that check the
passwords of the users the firewall doesn't have. It is one tree: Local (Users,
Roles), then the servers in the order logins try them. Select a node to edit it
on the right.

Every login takes the same path, to the GUI and to [OpenVPN](openvpn.md):

1. A **local user** (added here, with a password) is checked against their
   password.
2. A **directory user** (copied from a server, below) is checked at the
   servers again, so a disabled or changed directory account takes effect at
   once.
3. A user the firewall **doesn't have** is checked at each enabled server in
   turn. A server that is down or doesn't accept the password is passed over;
   when none accepts it, the login is refused. The first server that accepts it
   lets the user in, and the user is **copied** to the users: name, email, the
   server they came from, the global role **none** (no GUI access beyond their
   roles), and the roles their groups map to.

A copied user shows their server under Users (**From**). Their password is the
directory's: they change it there, not here. Two-factor login works for them as
for any user. **Set a local password** makes one a local user.

## Servers

**OpenLDAP** and **Active Directory** add a server. Drag a server above or
below another to change the order logins try them.

- **Host** and **Port**: the server as the firewall host resolves and reaches it
  (636 for LDAPS, 389 otherwise).
- **TLS**: **LDAPS**, **StartTLS** (TLS before anything is sent) or **None**
  (passwords in clear text: only on a trusted network). **CA certificate**: the CA
  of the server's certificate (an Active Directory's own enterprise CA), PEM;
  empty: the system's CAs. **Skip certificate check** is only for testing.
- **Bind DN** and **password**: the account that looks users up, e.g.
  `CN=svc-portitor,CN=Users,DC=example,DC=com`; empty: anonymously. The password
  is never shown again once saved.
- **Base DN**: where users are looked for, and below.
- **User filter**: finds the user, `%s` the name logged in with. Empty:
  `(sAMAccountName=%s)` for Active Directory, `(uid=%s)` for OpenLDAP.
  `(userPrincipalName=%s)` logs in with `user@domain`.
- **Attributes**: read for the copy of a user: email (`mail`), name
  (`displayName`) and groups (`memberOf`; OpenLDAP needs its memberof overlay).

**Test** connects, binds with the account and searches the base DN, with the
form as it is (the stored password when the field is empty).

Expand a server to browse its tree (read-only), as the bind account sees it.
Selecting a group shows the roles it maps to; pick a role and a level and
**Map** to add one.

## Authorization

**Groups to roles** makes a directory group's members members of a role, as an
admin or a viewer of the role's virtual firewalls, and members of a role an
OpenVPN server requires. The group is its DN, as the users' `memberOf` has it
(compared without regard to case). A user's roles follow their groups at each of
their logins: one who leaves the group leaves the role. A role no group maps to
is left as you set it, for directory users too.
