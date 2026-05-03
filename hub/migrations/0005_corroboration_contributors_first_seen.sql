-- Copyright (c) 2026 Cloudflare, Inc.
-- Licensed under the Apache 2.0 license found in the LICENSE file or at:
--     https://opensource.org/licenses/Apache-2.0

-- Per-contributor join timestamp on `corroboration_contributors`. Lets
-- /api/v1/corroboration answer the literal question "how many of MY
-- attributes got a SECOND contributor in the last N hours" precisely,
-- instead of approximating via `corroboration.last_seen` (which advances
-- on every contribution to the row, not just on a new contributor join).
-- See issue #131 for the counter-examples that motivated this.
--
-- Stored as epoch milliseconds (INTEGER) — directly usable from JS, and
-- consistent with `cron_runs.last_run_at` (migration 0003).
ALTER TABLE corroboration_contributors
    ADD COLUMN first_seen INTEGER NOT NULL DEFAULT (unixepoch() * 1000);

-- Backfill existing rows from `corroboration.last_seen` as the
-- best-available estimate (the only timestamp recorded before this
-- migration). `last_seen` is an ISO-8601 TEXT column ('YYYY-MM-DDTHH:MM:SS.sssZ');
-- `unixepoch(text)` parses it and returns seconds, so we multiply for ms.
UPDATE corroboration_contributors
SET first_seen = (
    SELECT unixepoch(c.last_seen) * 1000
    FROM corroboration c
    WHERE c.id = corroboration_contributors.corroboration_id
)
WHERE EXISTS (
    SELECT 1 FROM corroboration c WHERE c.id = corroboration_contributors.corroboration_id
);

-- Index supports the JOIN in /api/v1/corroboration: we look up "other
-- contributors of attribute X whose first_seen >= cutoff" once per
-- candidate attribute, and `(orgc_uuid, first_seen)` lets the planner
-- range-scan within an org.
CREATE INDEX idx_corroboration_contributors_orgc_first_seen
    ON corroboration_contributors(orgc_uuid, first_seen);
