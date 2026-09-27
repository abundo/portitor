-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- Firewall zones are replaced by interface zones: named groups of zero or
-- more interfaces of an instance. Rules and NAT rules list interfaces and
-- interface zones by name. An interface may be in several zones.
--
-- Each old zone becomes an interface zone with the same members (link ends
-- included), renamed with a _zone suffix if an interface of its instance
-- has the same name. Its input policy becomes an input rule after the
-- instance's other rules (accept/reject; drop is the chain policy), and
-- its masquerade flag a masquerade NAT rule after the other NAT rules, so
-- the rendered ruleset matches the same traffic.
CREATE TABLE interface_zones (
    id           BIGSERIAL PRIMARY KEY,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    instance_id  BIGINT NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    description  TEXT NOT NULL DEFAULT '',
    interfaces   JSONB NOT NULL DEFAULT '[]',
    old_zone_id  BIGINT,
    UNIQUE (instance_id, name)
);

INSERT INTO interface_zones (instance_id, name, description, interfaces, old_zone_id)
SELECT z.instance_id,
       CASE WHEN EXISTS (SELECT 1 FROM interfaces i WHERE i.instance_id = z.instance_id AND i.name = z.name)
              OR EXISTS (SELECT 1 FROM links l WHERE (l.instance_a_id = z.instance_id AND l.interface_a = z.name)
                                                  OR (l.instance_b_id = z.instance_id AND l.interface_b = z.name))
            THEN left(z.name, 19) || '_zone' ELSE z.name END,
       z.description,
       COALESCE((SELECT jsonb_agg(m.name ORDER BY m.name) FROM (
                    SELECT i.name FROM interfaces i WHERE i.zone_id = z.id
                    UNION SELECT l.interface_a FROM links l WHERE l.zone_a_id = z.id
                    UNION SELECT l.interface_b FROM links l WHERE l.zone_b_id = z.id) m), '[]'),
       z.id
FROM zones z;

ALTER TABLE rules ADD COLUMN in_interfaces JSONB NOT NULL DEFAULT '[]';
ALTER TABLE rules ADD COLUMN out_interfaces JSONB NOT NULL DEFAULT '[]';
UPDATE rules r SET in_interfaces = jsonb_build_array(iz.name) FROM interface_zones iz WHERE iz.old_zone_id = r.src_zone_id;
UPDATE rules r SET out_interfaces = jsonb_build_array(iz.name) FROM interface_zones iz WHERE iz.old_zone_id = r.dst_zone_id;

ALTER TABLE nat_rules ADD COLUMN in_interfaces JSONB NOT NULL DEFAULT '[]';
ALTER TABLE nat_rules ADD COLUMN out_interfaces JSONB NOT NULL DEFAULT '[]';
UPDATE nat_rules n SET in_interfaces = jsonb_build_array(iz.name) FROM interface_zones iz WHERE iz.old_zone_id = n.in_zone_id;
UPDATE nat_rules n SET out_interfaces = jsonb_build_array(iz.name) FROM interface_zones iz WHERE iz.old_zone_id = n.out_zone_id;

INSERT INTO rules (instance_id, position, chain, in_interfaces, action, enabled, description)
SELECT z.instance_id,
       (SELECT COALESCE(MAX(r.position), 0) FROM rules r WHERE r.instance_id = z.instance_id)
         + 10 * row_number() OVER (PARTITION BY z.instance_id ORDER BY z.name),
       'input', jsonb_build_array(iz.name), z.input_policy, true,
       'traffic to the firewall from zone ' || z.name
FROM zones z JOIN interface_zones iz ON iz.old_zone_id = z.id
WHERE z.input_policy IN ('accept', 'reject');

INSERT INTO nat_rules (instance_id, position, kind, out_interfaces, enabled, description)
SELECT z.instance_id,
       (SELECT COALESCE(MAX(n.position), 0) FROM nat_rules n WHERE n.instance_id = z.instance_id)
         + 10 * row_number() OVER (PARTITION BY z.instance_id ORDER BY z.name),
       'masquerade', jsonb_build_array(iz.name), true,
       'masquerade zone ' || z.name
FROM zones z JOIN interface_zones iz ON iz.old_zone_id = z.id
WHERE z.masquerade;

ALTER TABLE rules DROP COLUMN src_zone_id, DROP COLUMN dst_zone_id;
ALTER TABLE nat_rules DROP COLUMN in_zone_id, DROP COLUMN out_zone_id;
ALTER TABLE interfaces DROP COLUMN zone_id;
ALTER TABLE links DROP COLUMN zone_a_id, DROP COLUMN zone_b_id;
ALTER TABLE interface_zones DROP COLUMN old_zone_id;
DROP TABLE zones;

-- +goose Down
-- Lossy: each interface zone becomes a zone with input policy drop and
-- no masquerade; an interface keeps the first zone (by name) it is in;
-- a rule keeps the first interface zone of each list. A rule with an
-- interface list but no zone in it is deleted, as it would otherwise match
-- any interface. The rules and NAT rules added by Up stay.
CREATE TABLE zones (
    id           BIGSERIAL PRIMARY KEY,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    instance_id  BIGINT NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    description  TEXT NOT NULL DEFAULT '',
    input_policy TEXT NOT NULL DEFAULT 'drop',
    masquerade   BOOLEAN NOT NULL DEFAULT false,
    UNIQUE (instance_id, name)
);
INSERT INTO zones (instance_id, name, description) SELECT instance_id, name, description FROM interface_zones;

ALTER TABLE interfaces ADD COLUMN zone_id BIGINT REFERENCES zones(id) ON DELETE SET NULL;
UPDATE interfaces i SET zone_id = (
    SELECT z.id FROM zones z JOIN interface_zones iz ON iz.instance_id = z.instance_id AND iz.name = z.name
    WHERE z.instance_id = i.instance_id AND iz.interfaces ? i.name ORDER BY z.name LIMIT 1);

ALTER TABLE links ADD COLUMN zone_a_id BIGINT REFERENCES zones(id) ON DELETE SET NULL;
ALTER TABLE links ADD COLUMN zone_b_id BIGINT REFERENCES zones(id) ON DELETE SET NULL;
UPDATE links l SET
    zone_a_id = (SELECT z.id FROM zones z JOIN interface_zones iz ON iz.instance_id = z.instance_id AND iz.name = z.name
                 WHERE z.instance_id = l.instance_a_id AND iz.interfaces ? l.interface_a ORDER BY z.name LIMIT 1),
    zone_b_id = (SELECT z.id FROM zones z JOIN interface_zones iz ON iz.instance_id = z.instance_id AND iz.name = z.name
                 WHERE z.instance_id = l.instance_b_id AND iz.interfaces ? l.interface_b ORDER BY z.name LIMIT 1);

ALTER TABLE rules ADD COLUMN src_zone_id BIGINT REFERENCES zones(id) ON DELETE CASCADE;
ALTER TABLE rules ADD COLUMN dst_zone_id BIGINT REFERENCES zones(id) ON DELETE CASCADE;
UPDATE rules r SET
    src_zone_id = (SELECT z.id FROM zones z WHERE z.instance_id = r.instance_id AND r.in_interfaces ? z.name ORDER BY z.name LIMIT 1),
    dst_zone_id = (SELECT z.id FROM zones z WHERE z.instance_id = r.instance_id AND r.out_interfaces ? z.name ORDER BY z.name LIMIT 1);
DELETE FROM rules WHERE (in_interfaces <> '[]' AND src_zone_id IS NULL) OR (out_interfaces <> '[]' AND dst_zone_id IS NULL);
ALTER TABLE rules DROP COLUMN in_interfaces, DROP COLUMN out_interfaces;

ALTER TABLE nat_rules ADD COLUMN in_zone_id BIGINT REFERENCES zones(id) ON DELETE CASCADE;
ALTER TABLE nat_rules ADD COLUMN out_zone_id BIGINT REFERENCES zones(id) ON DELETE CASCADE;
UPDATE nat_rules n SET
    in_zone_id = (SELECT z.id FROM zones z WHERE z.instance_id = n.instance_id AND n.in_interfaces ? z.name ORDER BY z.name LIMIT 1),
    out_zone_id = (SELECT z.id FROM zones z WHERE z.instance_id = n.instance_id AND n.out_interfaces ? z.name ORDER BY z.name LIMIT 1);
DELETE FROM nat_rules WHERE (in_interfaces <> '[]' AND in_zone_id IS NULL) OR (out_interfaces <> '[]' AND out_zone_id IS NULL);
ALTER TABLE nat_rules DROP COLUMN in_interfaces, DROP COLUMN out_interfaces;

DROP TABLE interface_zones;
