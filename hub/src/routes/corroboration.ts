// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Hub corroboration count for an org's "own" attributes (#72).
 *
 * Returns the number of attributes contributed by `orgUuid` that have
 * received at least one additional contributor on the hub within the
 * window `[since, now]`.
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

	// Reject malformed `since` — must be parseable ISO-8601. We compare
	// against `corroboration_contributors.first_seen`, which is epoch
	// milliseconds (INTEGER), so convert here.
	const sinceMs = Date.parse(since);
	if (Number.isNaN(sinceMs)) {
		return c.json({ error: "since must be a parseable ISO-8601 timestamp" }, 400);
	}

	if (orgUuid !== c.var.org.uuid) {
		return c.json({ error: "orgUuid must match authenticated org" }, 403);
	}

	// Count distinct corroboration rows where MY org is a contributor
	// AND some OTHER contributor joined within the window. The JOIN on
	// `other.first_seen >= ?` is the precise expression of "got a second
	// contributor in-window" — it doesn't conflate row-touch time
	// (`corroboration.last_seen`) with contributor-join time the way the
	// previous approximation did. See issue #131.
	const row = await c.env.DB
		.prepare(
			`SELECT COUNT(DISTINCT c.id) AS n
			 FROM corroboration c
			 JOIN corroboration_contributors me
			   ON me.corroboration_id = c.id AND me.orgc_uuid = ?1
			 JOIN corroboration_contributors other
			   ON other.corroboration_id = c.id
			   AND other.orgc_uuid != ?1
			   AND other.first_seen >= ?2`,
		)
		.bind(orgUuid, sinceMs)
		.first<{ n: number }>();

	return c.json({ corroboratedCount: row?.n ?? 0 });
});
