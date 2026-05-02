// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Hub corroboration count for an org's "own" attributes (#72).
 *
 * Returns the number of attributes contributed by `orgUuid` that have
 * received at least one additional contributor on the hub within the
 * window `[since, now]`.
 *
 * Schema caveat (worth knowing as a reviewer):
 *   `corroboration_contributors` carries no per-row timestamp, so we cannot
 *   tell precisely *when* a second contributor arrived. The closest we can
 *   express is "rows where this org is a contributor AND ≥2 distinct
 *   contributors AND `last_seen >= since`". `last_seen` updates on any
 *   contribution to the row, so this is a reasonable proxy for "the row
 *   saw activity in the window" — including the case where the second
 *   contributor showed up earlier and our org re-submitted in-window. For
 *   a 24h dashboard widget that's fine; if drilldown lands later (out of
 *   scope here) we'd want a contributor timestamp column.
 */

import { Hono } from "hono";
import { requireOrg, type HubContext } from "../lib/auth";

export const corroborationRoutes = new Hono<HubContext>();

corroborationRoutes.use("*", requireOrg);

/**
 * `GET /api/v1/corroboration?orgUuid=<self>&since=<iso>`
 *
 * Auth model: the caller must be authenticated and `orgUuid` must equal the
 * authenticated org. Cross-tenant reads are rejected with 403 — otherwise
 * any authed org could enumerate another org's corroboration count.
 */
corroborationRoutes.get("/", async (c) => {
	const orgUuid = c.req.query("orgUuid");
	const since = c.req.query("since");

	if (!orgUuid) return c.json({ error: "orgUuid required" }, 400);
	if (!since) return c.json({ error: "since required" }, 400);

	// Reject malformed `since` — must be parseable ISO-8601. `last_seen` is
	// written by `applyCorroboration` as `new Date().toISOString()` (ISO with
	// T and Z), so we compare against the same canonical form. SQLite text
	// comparison is lexicographic, which sorts ISO-8601 timestamps correctly.
	const sinceMs = Date.parse(since);
	if (Number.isNaN(sinceMs)) {
		return c.json({ error: "since must be a parseable ISO-8601 timestamp" }, 400);
	}
	const sinceSql = new Date(sinceMs).toISOString();

	if (orgUuid !== c.var.org.uuid) {
		return c.json({ error: "orgUuid must match authenticated org" }, 403);
	}

	// Count distinct corroboration rows where:
	//  - this org is in `corroboration_contributors` (the row is "ours")
	//  - the row has ≥2 distinct contributors total (someone else corroborated)
	//  - the row was touched within the window
	//
	// The `last_seen >= ?` filter narrows the scan first; for a 24h window
	// this is a small slice in practice. EXISTS short-circuits per row.
	const row = await c.env.DB
		.prepare(
			`SELECT COUNT(*) AS n
			 FROM corroboration c
			 WHERE c.last_seen >= ?1
			   AND c.contributor_count >= 2
			   AND EXISTS (
			     SELECT 1 FROM corroboration_contributors cc
			     WHERE cc.corroboration_id = c.id AND cc.orgc_uuid = ?2
			   )`,
		)
		.bind(sinceSql, orgUuid)
		.first<{ n: number }>();

	return c.json({ corroboratedCount: row?.n ?? 0 });
});
