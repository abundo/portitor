-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- The DNS server's upstream is one of: forwarders, the root servers, or the
-- DNS servers of the DHCP lease on one interface (interfaces.dns_from_dhcp,
-- at most one per instance). It replaces forward mode "off" and "also use
-- the DNS servers of every DHCP lease".
ALTER TABLE instances ADD COLUMN dns_upstream TEXT NOT NULL DEFAULT 'forward';
ALTER TABLE interfaces ADD COLUMN dns_from_dhcp BOOLEAN NOT NULL DEFAULT false;
UPDATE instances SET dns_upstream = 'root', dns_forward_mode = 'first' WHERE dns_forward_mode = 'off';
-- DHCP servers without forwarders: the instance's first DHCP client interface.
UPDATE interfaces SET dns_from_dhcp = true WHERE id IN (
    SELECT MIN(i.id) FROM interfaces i JOIN instances n ON n.id = i.instance_id
    WHERE n.dns_forward_from_dhcp AND n.dns_forwarders = '[]' AND n.dns_upstream = 'forward'
      AND i.ipv4_mode = 'dhcp'
    GROUP BY i.instance_id);
UPDATE instances SET dns_upstream = 'dhcp' WHERE id IN (SELECT instance_id FROM interfaces WHERE dns_from_dhcp);
ALTER TABLE instances DROP COLUMN dns_forward_from_dhcp;

-- +goose Down
ALTER TABLE instances ADD COLUMN dns_forward_from_dhcp BOOLEAN NOT NULL DEFAULT false;
UPDATE instances SET dns_forward_from_dhcp = true WHERE dns_upstream = 'dhcp';
UPDATE instances SET dns_forward_mode = 'off' WHERE dns_upstream = 'root';
ALTER TABLE interfaces DROP COLUMN dns_from_dhcp;
ALTER TABLE instances DROP COLUMN dns_upstream;
