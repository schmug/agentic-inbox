// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Trust-weighted aggregation.
 *
 * When a new event lands, we update a per-(type, value, sharing_group) row in
 * `corroboration`. Each distinct contributor org contributes `org.trust`
 * points (first-time contribution only — de-duped via corroboration_contributors).
 *
 * An attribute promotes to a sharing group's public feed when BOTH:
 *   - score ≥ PROMOTION_SCORE
 *   - contributor_count ≥ PROMOTION_CONTRIBUTORS
 */

import type { D1Database } from "@cloudflare/workers-types";

export const PROMOTION_SCORE = 2.0;
export const PROMOTION_CONTRIBUTORS = 2;

/** Attribute types that belong on the published destroylist feed. */
const PROMOTABLE_TYPES = new Set(["url", "domain", "hostname", "ip-src", "ip-dst", "sha256"]);

interface AggregateInput {
	event_uuid: string;
	orgc_uuid: string;
	sharing_group_uuid: string | null;
	attributes: Array<{ type: string; value: string }>;
}

export async function applyCorroboration(db: D1Database, input: AggregateInput) {
	const orgRow = await db
		.prepare(`SELECT trust FROM orgs WHERE uuid = ?1`)
		.bind(input.orgc_uuid)
		.first<{ trust: number }>();
	const trust = orgRow?.trust ?? 1.0;
	const now = new Date().toISOString();

	for (const attr of input.attributes) {
		if (!PROMOTABLE_TYPES.has(attr.type)) continue;

		// Upsert corroboration row
		await db
			.prepare(
				`INSERT INTO corroboration
				   (sharing_group_uuid, attribute_type, value, first_seen, last_seen, contributor_count, score)
				 VALUES (?1, ?2, ?3, ?4, ?4, 0, 0.0)
				 ON CONFLICT (sharing_group_uuid, attribute_type, value)
				 DO UPDATE SET last_seen = ?4`,
			)
			.bind(input.sharing_group_uuid, attr.type, attr.value, now)
			.run();

		const row = await db
			.prepare(
				`SELECT id FROM corroboration
				 WHERE (sharing_group_uuid IS ?1 OR (sharing_group_uuid IS NULL AND ?1 IS NULL))
				   AND attribute_type = ?2 AND value = ?3`,
			)
			.bind(input.sharing_group_uuid, attr.type, attr.value)
			.first<{ id: number }>();
		if (!row) continue;

		// Attempt contributor insert; if it's already there, INSERT OR IGNORE
		// is a no-op and we do not re-add their trust.
		const res = await db
			.prepare(
				`INSERT OR IGNORE INTO corroboration_contributors (corroboration_id, orgc_uuid)
				 VALUES (?1, ?2)`,
			)
			.bind(row.id, input.orgc_uuid)
			.run();

		const newlyAdded = (res.meta.changes ?? 0) > 0;
		if (newlyAdded) {
			await db
				.prepare(
					`UPDATE corroboration
					 SET contributor_count = contributor_count + 1,
					     score = score + ?1
					 WHERE id = ?2`,
				)
				.bind(trust, row.id)
				.run();
		}
	}
}

export interface PromotedEntry {
	attribute_type: string;
	value: string;
	score: number;
	contributor_count: number;
}

export async function getPromotedForSharingGroup(
	db: D1Database,
	sharingGroupUuid: string | null,
): Promise<PromotedEntry[]> {
	const res = await db
		.prepare(
			`SELECT attribute_type, value, score, contributor_count
			 FROM corroboration
			 WHERE (sharing_group_uuid IS ?1 OR (sharing_group_uuid IS NULL AND ?1 IS NULL))
			   AND score >= ?2
			   AND contributor_count >= ?3
			 ORDER BY score DESC
			 LIMIT 50000`,
		)
		.bind(sharingGroupUuid, PROMOTION_SCORE, PROMOTION_CONTRIBUTORS)
		.all<PromotedEntry>();
	return res.results ?? [];
}
