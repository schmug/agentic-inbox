// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

import { Hono } from "hono";
import { z } from "zod";
import { requireOrg, type HubContext } from "../lib/auth";

export const sharingGroupRoutes = new Hono<HubContext>();

sharingGroupRoutes.use("*", requireOrg);

sharingGroupRoutes.get("/", async (c) => {
	const rows = await c.env.DB
		.prepare(
			`SELECT sg.uuid, sg.name, sg.description, sgo.role
			 FROM sharing_groups sg
			 JOIN sharing_group_orgs sgo ON sgo.sharing_group_uuid = sg.uuid
			 WHERE sgo.org_uuid = ?1
			 ORDER BY sg.name ASC`,
		)
		.bind(c.var.org.uuid)
		.all();
	return c.json({ sharing_groups: rows.results ?? [] });
});

const CreateSchema = z.object({
	name: z.string().min(1).max(200),
	description: z.string().max(1000).optional(),
});

sharingGroupRoutes.post("/", async (c) => {
	const parsed = CreateSchema.safeParse(await c.req.json().catch(() => null));
	if (!parsed.success) return c.json({ error: parsed.error.flatten() }, 400);

	const uuid = crypto.randomUUID();
	await c.env.DB.batch([
		c.env.DB
			.prepare(`INSERT INTO sharing_groups (uuid, name, description) VALUES (?1, ?2, ?3)`)
			.bind(uuid, parsed.data.name, parsed.data.description ?? null),
		c.env.DB
			.prepare(
				`INSERT INTO sharing_group_orgs (sharing_group_uuid, org_uuid, role) VALUES (?1, ?2, 'owner')`,
			)
			.bind(uuid, c.var.org.uuid),
	]);
	return c.json({ sharing_group: { uuid, ...parsed.data } }, 201);
});
