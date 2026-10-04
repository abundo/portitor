-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- BFD (FRR's bfdd) per interface of an instance, by name, with its
-- timers; static routes, OSPF interfaces and BGP neighbours and peer
-- groups that ask for BFD use it on the interfaces that have it enabled.
CREATE TABLE bfd_interfaces (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    instance_id       INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    interface         TEXT NOT NULL,
    enabled           BOOLEAN NOT NULL DEFAULT true,
    detect_multiplier INTEGER NOT NULL DEFAULT 3,
    receive_interval  INTEGER NOT NULL DEFAULT 300,
    transmit_interval INTEGER NOT NULL DEFAULT 300,
    passive           BOOLEAN NOT NULL DEFAULT false,
    description       TEXT NOT NULL DEFAULT '',
    UNIQUE (instance_id, interface)
);
ALTER TABLE routes ADD COLUMN bfd BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE ospf_interfaces ADD COLUMN bfd BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE bgp_neighbors ADD COLUMN bfd BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE bgp_peer_groups ADD COLUMN bfd BOOLEAN NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE bgp_peer_groups DROP COLUMN bfd;
ALTER TABLE bgp_neighbors DROP COLUMN bfd;
ALTER TABLE ospf_interfaces DROP COLUMN bfd;
ALTER TABLE routes DROP COLUMN bfd;
DROP TABLE bfd_interfaces;
