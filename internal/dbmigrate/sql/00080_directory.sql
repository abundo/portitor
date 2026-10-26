-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- The directory (Admin → Directory): the users, roles and the OpenLDAP and
-- Active Directory servers every login tries, in position order, for a user
-- the firewall doesn't have or has from a server (users.ldap_server, whose
-- password_hash is '@LDAP'); such a user is copied in on the first login.
-- ldap_role_mappings give a server's group the members of a role, synced at
-- each login. OpenVPN's own LDAP servers and login switches (00079) go: it
-- logs users in the same way.
DROP TABLE ldap_servers;
ALTER TABLE interfaces DROP COLUMN ovpn_auth_local;
ALTER TABLE interfaces DROP COLUMN ovpn_auth_ldap;
ALTER TABLE users ADD COLUMN ldap_server TEXT NOT NULL DEFAULT '';

CREATE TABLE ldap_servers (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    position          INTEGER NOT NULL DEFAULT 0,
    name              TEXT NOT NULL UNIQUE,
    description       TEXT NOT NULL DEFAULT '',
    enabled           BOOLEAN NOT NULL DEFAULT true,
    server_type       TEXT NOT NULL DEFAULT 'generic',
    host              TEXT NOT NULL DEFAULT '',
    port              INTEGER NOT NULL DEFAULT 389,
    tls_mode          TEXT NOT NULL DEFAULT 'none',
    skip_tls_verify   BOOLEAN NOT NULL DEFAULT false,
    ca_cert           TEXT NOT NULL DEFAULT '',
    bind_dn           TEXT NOT NULL DEFAULT '',
    bind_password     TEXT NOT NULL DEFAULT '',
    base_dn           TEXT NOT NULL DEFAULT '',
    user_filter       TEXT NOT NULL DEFAULT '',
    attr_email        TEXT NOT NULL DEFAULT '',
    attr_display_name TEXT NOT NULL DEFAULT '',
    attr_groups       TEXT NOT NULL DEFAULT ''
);

CREATE TABLE ldap_role_mappings (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    group_dn   TEXT NOT NULL,
    role_id    INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    level      TEXT NOT NULL DEFAULT 'viewer',
    UNIQUE (group_dn, role_id)
);

-- +goose Down
DROP TABLE ldap_role_mappings;
DROP TABLE ldap_servers;
ALTER TABLE users DROP COLUMN ldap_server;
ALTER TABLE interfaces ADD COLUMN ovpn_auth_ldap BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE interfaces ADD COLUMN ovpn_auth_local BOOLEAN NOT NULL DEFAULT true;
CREATE TABLE ldap_servers (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    instance_id   INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    description   TEXT NOT NULL DEFAULT '',
    enabled       BOOLEAN NOT NULL DEFAULT true,
    url           TEXT NOT NULL DEFAULT '',
    start_tls     BOOLEAN NOT NULL DEFAULT false,
    ca_cert       TEXT NOT NULL DEFAULT '',
    bind_dn       TEXT NOT NULL DEFAULT '',
    bind_password TEXT NOT NULL DEFAULT '',
    base_dn       TEXT NOT NULL DEFAULT '',
    user_filter   TEXT NOT NULL DEFAULT '(|(uid={user})(sAMAccountName={user}))',
    group_dn      TEXT NOT NULL DEFAULT '',
    UNIQUE (instance_id, name)
);
