// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Published feeds: the community's distilled intel. PhishDestroy/URLhaus
 * consumers can pull a plain newline-delimited file here; MISP-aware tools
 * can pull structured events via /events/restSearch.
 */

import { Hono } from "hono";
import { requireOrg, type HubContext } from "../lib/auth";
import { getPromotedForSharingGroup } from "../lib/aggregate";

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
		const promoted = await getPromotedForSharingGroup(c.env.DB, g);
		for (const p of promoted) {
			if (!kinds.includes(p.attribute_type)) continue;
			if (seen.has(p.value)) continue;
			seen.add(p.value);
			lines.push(p.value);
		}
	}

	return c.text(lines.join("\n"), 200, { "Content-Type": "text/plain; charset=utf-8" });
});
