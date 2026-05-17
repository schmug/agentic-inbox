// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Published feeds: the community's distilled intel. PhishDestroy/URLhaus
 * consumers can pull a plain newline-delimited file here; MISP-aware tools
 * can pull structured events via /events/restSearch.
 *
 * Two route groups:
 *   feedRoutes      — authenticated; mounted at /feeds
 *   publicFeedRoutes — unauthenticated; mounted at /feeds/public (issue #23)
 *
 * Format note: both endpoints emit corroboration counts as `# score=X
 * contributors=N` comment lines immediately before each value. Parsers
 * that skip `#` lines (including workers/intel/feeds.ts parseFeedBody)
 * continue to work unchanged; parsers that want to threshold on score or
 * contributor count can read the comments.
 */

import { Hono } from "hono";
import { requireOrg, type HubContext } from "../lib/auth";
import { getPromotedForSharingGroup, type PromotedEntry } from "../lib/aggregate";
import type { Env } from "../types";

export const feedRoutes = new Hono<HubContext>();

feedRoutes.use("*", requireOrg);

/**
 * Plain destroylist of promoted URLs/domains visible to the caller.
 * Returns one value per line; `# ` lines are metadata comments.
 *
 * Query params:
 *   sharing_group — restrict to one group (must be a member)
 *   kinds — comma-separated attribute types to include (default url,domain)
 */
feedRoutes.get("/destroylist.txt", async (c) => {
	const sharingGroup = c.req.query("sharing_group") ?? null;
	const kinds = (c.req.query("kinds") ?? "url,domain").split(",").map((s) => s.trim());

	if (sharingGroup) {
		const mem = await c.env.DB
			.prepare(`SELECT 1 FROM sharing_group_orgs WHERE sharing_group_uuid = ?1 AND org_uuid = ?2`)
			.bind(sharingGroup, c.var.org.uuid)
			.first();
		if (!mem) return c.text("not a member of that sharing group", 403);
	}

	// Collect promoted entries from the requested group plus all groups this
	// org belongs to (if no specific group requested).
	const groups: (string | null)[] = [];
	if (sharingGroup) {
		groups.push(sharingGroup);
	} else {
		groups.push(null);
		const memberships = await c.env.DB
			.prepare(`SELECT sharing_group_uuid FROM sharing_group_orgs WHERE org_uuid = ?1`)
			.bind(c.var.org.uuid)
			.all<{ sharing_group_uuid: string }>();
		for (const m of memberships.results ?? []) groups.push(m.sharing_group_uuid);
	}

	const seen = new Set<string>();
	const lines: string[] = [
		`# destroylist published ${new Date().toISOString()}`,
		`# caller org ${c.var.org.uuid}`,
		`# kinds ${kinds.join(",")}`,
		"",
	];
	for (const g of groups) {
		// Pass the caller's org so their own contributions echo back immediately,
		// bypassing the cross-org `contributor_count ≥ 2` threshold for the
		// caller only. Sybil resistance is preserved for entries contributed
		// solely by other orgs — see `getPromotedForSharingGroup` for details.
		const promoted = await getPromotedForSharingGroup(c.env.DB, g, c.var.org.uuid);
		for (const p of promoted) {
			if (!kinds.includes(p.attribute_type)) continue;
			if (seen.has(p.value)) continue;
			seen.add(p.value);
			appendEntry(lines, p);
		}
	}

	return c.text(lines.join("\n"), 200, { "Content-Type": "text/plain; charset=utf-8" });
});

// ── Public (unauthenticated) feed (issue #23) ─────────────────────────────

export const publicFeedRoutes = new Hono<{ Bindings: Env }>();

/**
 * Unauthenticated destroylist of promoted entries from all sharing groups
 * that the operator has marked `is_public = 1`.
 *
 * Applies the standard sybil-resistance threshold (score ≥ 2.0 AND
 * contributors ≥ 2) — no own-org echo since there is no authenticated caller.
 * Operators designate a sharing group as public via
 * `PATCH /admin/sharing-groups/:uuid { is_public: true }`.
 *
 * Query params:
 *   kinds — comma-separated attribute types to include (default url,domain)
 */
publicFeedRoutes.get("/destroylist.txt", async (c) => {
	const kinds = (c.req.query("kinds") ?? "url,domain").split(",").map((s) => s.trim());

	const publicGroups = await c.env.DB
		.prepare(`SELECT uuid FROM sharing_groups WHERE is_public = 1`)
		.all<{ uuid: string }>();

	if ((publicGroups.results ?? []).length === 0) {
		const lines = [
			`# destroylist published ${new Date().toISOString()}`,
			"# no public sharing groups configured",
			"",
		];
		return c.text(lines.join("\n"), 200, { "Content-Type": "text/plain; charset=utf-8" });
	}

	const seen = new Set<string>();
	const lines: string[] = [
		`# destroylist published ${new Date().toISOString()}`,
		"# public feed — no authentication required",
		`# kinds ${kinds.join(",")}`,
		"",
	];
	for (const { uuid } of publicGroups.results ?? []) {
		// callerOrgUuid omitted — standard cross-org threshold only, no own-org echo.
		const promoted = await getPromotedForSharingGroup(c.env.DB, uuid);
		for (const p of promoted) {
			if (!kinds.includes(p.attribute_type)) continue;
			if (seen.has(p.value)) continue;
			seen.add(p.value);
			appendEntry(lines, p);
		}
	}

	return c.text(lines.join("\n"), 200, { "Content-Type": "text/plain; charset=utf-8" });
});

/**
 * Emit a corroboration-count comment followed by the raw value line.
 * Comment format: `# score=X.XX contributors=N`
 *
 * Parsers that skip `#`-prefixed lines (e.g. parseFeedBody in
 * workers/intel/feeds.ts) see only the value and work unchanged.
 * Parsers that want to threshold on score or contributor count can read
 * the comment line that precedes each value.
 */
function appendEntry(lines: string[], p: PromotedEntry): void {
	lines.push(`# score=${p.score.toFixed(2)} contributors=${p.contributor_count}`);
	lines.push(p.value);
}
