-- Copyright (c) 2026 Cloudflare, Inc.
-- Licensed under the Apache 2.0 license found in the LICENSE file or at:
--     https://opensource.org/licenses/Apache-2.0

-- Orgs contribute intel. Each contributor has a trust multiplier that ramps
-- up with confirmed true-positives and decays with confirmed false-positives.
CREATE TABLE orgs (
    uuid TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    contact TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    trust REAL NOT NULL DEFAULT 1.0
);

-- Invite-based trust circles — MISP "sharing groups".
CREATE TABLE sharing_groups (
    uuid TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE sharing_group_orgs (
    sharing_group_uuid TEXT NOT NULL,
    org_uuid TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'member', -- owner | member
    PRIMARY KEY (sharing_group_uuid, org_uuid),
    FOREIGN KEY (sharing_group_uuid) REFERENCES sharing_groups(uuid) ON DELETE CASCADE,
    FOREIGN KEY (org_uuid) REFERENCES orgs(uuid) ON DELETE CASCADE
);

-- API keys. Stored as sha256(key) so leaked DB can't impersonate. Each key
-- belongs to exactly one org; org permissions flow from sharing_group_orgs.
CREATE TABLE api_keys (
    key_hash TEXT PRIMARY KEY,
    org_uuid TEXT NOT NULL,
    label TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_used_at TEXT,
    revoked INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (org_uuid) REFERENCES orgs(uuid) ON DELETE CASCADE
);
CREATE INDEX idx_api_keys_org ON api_keys(org_uuid);

-- Single-use invite tokens. Accepting an invite creates an org + api_key.
CREATE TABLE invites (
    token_hash TEXT PRIMARY KEY,
    sharing_group_uuid TEXT,
    note TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL,
    consumed_at TEXT
);

-- MISP-compatible events + attributes. `event_json` stores the full payload
-- for opaque passthrough; normalized fields are extracted for querying.
CREATE TABLE events (
    uuid TEXT PRIMARY KEY,
    orgc_uuid TEXT NOT NULL,
    sharing_group_uuid TEXT,
    info TEXT NOT NULL,
    date TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    distribution TEXT NOT NULL DEFAULT '1',
    analysis TEXT NOT NULL DEFAULT '0',
    threat_level_id TEXT NOT NULL DEFAULT '2',
    event_json TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (orgc_uuid) REFERENCES orgs(uuid) ON DELETE CASCADE
);
CREATE INDEX idx_events_orgc ON events(orgc_uuid);
CREATE INDEX idx_events_sharing_group ON events(sharing_group_uuid);
CREATE INDEX idx_events_date ON events(date);

CREATE TABLE attributes (
    uuid TEXT PRIMARY KEY,
    event_uuid TEXT NOT NULL,
    type TEXT NOT NULL,
    category TEXT NOT NULL,
    value TEXT NOT NULL,
    to_ids INTEGER NOT NULL DEFAULT 0,
    comment TEXT,
    FOREIGN KEY (event_uuid) REFERENCES events(uuid) ON DELETE CASCADE
);
CREATE INDEX idx_attributes_type_value ON attributes(type, value);
CREATE INDEX idx_attributes_event ON attributes(event_uuid);

-- Per-(type,value,sharing_group) corroboration record. Updated by the
-- aggregate step: each attribute contribution adds orgc.trust to the score;
-- contributors[] dedups on orgc_uuid.
CREATE TABLE corroboration (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sharing_group_uuid TEXT,
    attribute_type TEXT NOT NULL,
    value TEXT NOT NULL,
    first_seen TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen TEXT NOT NULL DEFAULT (datetime('now')),
    contributor_count INTEGER NOT NULL DEFAULT 0,
    score REAL NOT NULL DEFAULT 0.0,
    UNIQUE (sharing_group_uuid, attribute_type, value)
);
CREATE INDEX idx_corroboration_type_value ON corroboration(attribute_type, value);
CREATE INDEX idx_corroboration_sharing_group ON corroboration(sharing_group_uuid);

CREATE TABLE corroboration_contributors (
    corroboration_id INTEGER NOT NULL,
    orgc_uuid TEXT NOT NULL,
    PRIMARY KEY (corroboration_id, orgc_uuid),
    FOREIGN KEY (corroboration_id) REFERENCES corroboration(id) ON DELETE CASCADE,
    FOREIGN KEY (orgc_uuid) REFERENCES orgs(uuid) ON DELETE CASCADE
);

CREATE TABLE tags (
    name TEXT PRIMARY KEY
);

CREATE TABLE event_tags (
    event_uuid TEXT NOT NULL,
    tag_name TEXT NOT NULL,
    PRIMARY KEY (event_uuid, tag_name),
    FOREIGN KEY (event_uuid) REFERENCES events(uuid) ON DELETE CASCADE,
    FOREIGN KEY (tag_name) REFERENCES tags(name) ON DELETE CASCADE
);
