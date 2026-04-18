// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

import { createMiddleware } from "hono/factory";
import type { Env, AuthedOrg } from "../types";
import { sha256 } from "./hash";

export type HubContext = {
	Bindings: Env;
	Variables: {
		org: AuthedOrg;
		apiKeyHash: string;
	};
};

/**
 * Auth middleware. Accepts either the MISP-native form
 * (`Authorization: <key>`) or standard `Authorization: Bearer <key>` — both
 * are common in the wild.
 */
export const requireOrg = createMiddleware<HubContext>(async (c, next) => {
	const header = c.req.header("authorization") ?? c.req.header("Authorization");
	if (!header) return c.json({ error: "missing authorization" }, 401);
	const token = header.startsWith("Bearer ") ? header.slice(7).trim() : header.trim();
	if (!token) return c.json({ error: "missing token" }, 401);

	const keyHash = await sha256(token);
	const row = await c.env.DB.prepare(
		`SELECT k.key_hash, k.org_uuid, k.revoked, o.name, o.trust
		 FROM api_keys k JOIN orgs o ON o.uuid = k.org_uuid
		 WHERE k.key_hash = ?1`,
	).bind(keyHash).first<{
		key_hash: string;
		org_uuid: string;
		revoked: number;
		name: string;
		trust: number;
	}>();

	if (!row || row.revoked) return c.json({ error: "invalid or revoked token" }, 401);

	c.set("org", { uuid: row.org_uuid, name: row.name, trust: row.trust });
	c.set("apiKeyHash", row.key_hash);

	// Best-effort last_used_at. Intentionally fire-and-forget — failures
	// here shouldn't break the request.
	c.env.DB
		.prepare(`UPDATE api_keys SET last_used_at = ?1 WHERE key_hash = ?2`)
		.bind(new Date().toISOString(), row.key_hash)
		.run()
		.catch(() => {});

	await next();
});
