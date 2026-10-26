-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- OpenVPN servers: interfaces of kind openvpn (fwconfig.OpenVPN). Users log
-- in with a password, checked against the users (ovpn_auth_local; members
-- of ovpn_role_id only, with ovpn_require_role) and the instance's LDAP
-- servers (ovpn_auth_ldap). ovpn_tls_crypt is the static key the clients
-- get too; ovpn_host is the name they connect to.
ALTER TABLE interfaces ADD COLUMN ovpn_mode TEXT NOT NULL DEFAULT 'adaptive';
ALTER TABLE interfaces ADD COLUMN ovpn_port INTEGER NOT NULL DEFAULT 1194;
ALTER TABLE interfaces ADD COLUMN ovpn_listen TEXT NOT NULL DEFAULT '';
ALTER TABLE interfaces ADD COLUMN ovpn_certificate_id INTEGER REFERENCES certificates(id) ON DELETE SET NULL;
ALTER TABLE interfaces ADD COLUMN ovpn_tls_crypt TEXT NOT NULL DEFAULT '';
ALTER TABLE interfaces ADD COLUMN ovpn_auth_local BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE interfaces ADD COLUMN ovpn_require_role BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE interfaces ADD COLUMN ovpn_role_id INTEGER REFERENCES roles(id) ON DELETE SET NULL;
ALTER TABLE interfaces ADD COLUMN ovpn_auth_ldap BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE interfaces ADD COLUMN ovpn_routes TEXT NOT NULL DEFAULT '[]';
ALTER TABLE interfaces ADD COLUMN ovpn_redirect_gateway BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE interfaces ADD COLUMN ovpn_dns TEXT NOT NULL DEFAULT '[]';
ALTER TABLE interfaces ADD COLUMN ovpn_dns_domain TEXT NOT NULL DEFAULT '';
ALTER TABLE interfaces ADD COLUMN ovpn_client_to_client BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE interfaces ADD COLUMN ovpn_host TEXT NOT NULL DEFAULT '';

-- External directories (OpenLDAP, Active Directory) an instance's OpenVPN
-- asks, in name order (fwconfig.LDAPServer). bind_password is a secret.
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

-- +goose Down
DROP TABLE ldap_servers;
ALTER TABLE interfaces DROP COLUMN ovpn_host;
ALTER TABLE interfaces DROP COLUMN ovpn_client_to_client;
ALTER TABLE interfaces DROP COLUMN ovpn_dns_domain;
ALTER TABLE interfaces DROP COLUMN ovpn_dns;
ALTER TABLE interfaces DROP COLUMN ovpn_redirect_gateway;
ALTER TABLE interfaces DROP COLUMN ovpn_routes;
ALTER TABLE interfaces DROP COLUMN ovpn_auth_ldap;
ALTER TABLE interfaces DROP COLUMN ovpn_role_id;
ALTER TABLE interfaces DROP COLUMN ovpn_require_role;
ALTER TABLE interfaces DROP COLUMN ovpn_auth_local;
ALTER TABLE interfaces DROP COLUMN ovpn_tls_crypt;
ALTER TABLE interfaces DROP COLUMN ovpn_certificate_id;
ALTER TABLE interfaces DROP COLUMN ovpn_listen;
ALTER TABLE interfaces DROP COLUMN ovpn_port;
ALTER TABLE interfaces DROP COLUMN ovpn_mode;
