-- Copyright (c) 2026 Cloudflare, Inc.
-- Licensed under the Apache 2.0 license found in the LICENSE file or at:
--     https://opensource.org/licenses/Apache-2.0

-- Allow operators to designate a sharing group as publicly-readable.
-- When is_public = 1, promoted entries from that group are served by
-- GET /feeds/public/destroylist.txt without authentication, enabling any
-- downstream operator to pull the community destroylist without provisioning
-- hub credentials (issue #23).
--
-- The sybil-resistance threshold (score >= 2.0 AND contributors >= 2) still
-- applies on the public endpoint — the only change is the auth requirement.
ALTER TABLE sharing_groups ADD COLUMN is_public INTEGER NOT NULL DEFAULT 0;

-- Partial index: the public feed query filters on is_public=1 once per
-- request. Partial index is tiny (only public groups) so it costs nothing
-- on the common case.
CREATE INDEX idx_sharing_groups_is_public
    ON sharing_groups(uuid)
    WHERE is_public = 1;
