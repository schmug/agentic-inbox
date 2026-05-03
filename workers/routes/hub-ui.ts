// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Read-only worker proxy for the threat-intel hub UI. The browser can't talk
 * to the hub directly because the hub API key lives as a worker secret —
 * these routes resolve the per-mailbox `intel.hub` config, read the secret
 * by name from `c.env`, and forward the call.
 *
 * Each endpoint follows the same shape: a 200 with `{ configured: false }`
 * when this mailbox has no hub config, otherwise the parsed payload.
 * Picking 200 (not 412) because a mailbox without hub credentials is the
 * normal idle state, not an error — the UI renders one empty-state panel
 * regardless of which call you made.
 *
 * Mounted under `/api/v1/mailboxes/:mailboxId/hub`. The shared `requireMailbox`
 * middleware applied at the parent path enforces the mailbox-id existence
 * check; visibility scoping is the same path-only check the rest of the
 * mailbox-scoped API uses today (see #27).
 */

import { Hono } from "hono";
import type { MailboxContext } from "../lib/mailbox";
import { MispClient } from "../intel/misp-client";
import { loadHubCredentials } from "../lib/hub-config";

export const hubUiRoutes = new Hono<MailboxContext>();

interface ConfiguredResponse<T> {
	configured: true;
	data: T;
}
interface UnconfiguredResponse {
	configured: false;
}

/**
 * Returns `{ configured: false }` for any of: missing mailboxId, no
 * `intel.hub` block in the mailbox JSON, or the named secret unset on
 * `c.env`. The UI renders one empty state regardless of which side is
 * missing, so the helper collapses all three into the same shape.
 */
async function withHubClient<T>(
	c: import("hono").Context<MailboxContext>,
	mailboxId: string | undefined,
	fn: (client: MispClient, orgUuid: string) => Promise<T>,
): Promise<ConfiguredResponse<T> | UnconfiguredResponse> {
	if (!mailboxId) return { configured: false };
	const creds = await loadHubCredentials(
		c.env as unknown as Record<string, unknown> & { BUCKET: R2Bucket },
		mailboxId,
	);
	if (!creds) return { configured: false };
	const client = new MispClient({ baseUrl: creds.cfg.url, apiKey: creds.apiKey });
	const data = await fn(client, creds.cfg.org_uuid);
	return { configured: true, data };
}

hubUiRoutes.get("/contributions", async (c) => {
	const mailboxId = c.req.param("mailboxId");
	const result = await withHubClient(c, mailboxId, async (client) => {
		const events = await client.searchEvents({ limit: 25 });
		// Project to a flat shape the UI can render without knowing about MISP.
		return events.map((e) => ({
			uuid: e.Event.uuid,
			info: e.Event.info,
			date: e.Event.date,
			timestamp: e.Event.timestamp,
			sharing_group_uuid: e.Event.sharing_group_uuid,
			attribute_count: e.Event.Attribute?.length ?? 0,
		}));
	});
	return c.json(result);
});

hubUiRoutes.get("/destroylist", async (c) => {
	const mailboxId = c.req.param("mailboxId");
	const sharingGroup = c.req.query("sharing_group") ?? undefined;
	const result = await withHubClient(c, mailboxId, async (client) => {
		const values = await client.fetchDestroyList({ sharingGroup });
		return { values, count: values.length };
	});
	return c.json(result);
});

hubUiRoutes.get("/sharing-groups", async (c) => {
	const mailboxId = c.req.param("mailboxId");
	const result = await withHubClient(c, mailboxId, async (client) => {
		const groups = await client.listSharingGroups();
		return { groups };
	});
	return c.json(result);
});

/**
 * Issue a one-time invite token via the hub `POST /orgs/invite` endpoint
 * (#74). The hub owns role gating: a non-member of the requested sharing
 * group gets a 403 from the hub, which we forward verbatim — we do NOT
 * substitute fallback behavior on hub error so the UI can show the real
 * reason. Body shape mirrors the hub: `{ sharing_group_uuid?, note?,
 * ttl_hours? }`. On success the hub returns `{ token, expires_at }` and
 * the token is shown ONCE in the modal.
 */
hubUiRoutes.post("/invites", async (c) => {
	const mailboxId = c.req.param("mailboxId");
	if (!mailboxId) return c.json({ error: "missing mailboxId" }, 400);
	const creds = await loadHubCredentials(
		c.env as unknown as Record<string, unknown> & { BUCKET: R2Bucket },
		mailboxId,
	);
	if (!creds) return c.json({ error: "hub not configured" }, 412);

	const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
	// Only forward the keys the hub expects — drops accidental extras
	// without rejecting the request locally (the hub validates with zod).
	const forwardBody: Record<string, unknown> = {};
	if (body.sharing_group_uuid !== undefined) forwardBody.sharing_group_uuid = body.sharing_group_uuid;
	if (body.note !== undefined) forwardBody.note = body.note;
	if (body.ttl_hours !== undefined) forwardBody.ttl_hours = body.ttl_hours;

	const url = `${creds.cfg.url.replace(/\/$/, "")}/orgs/invite`;
	const upstream = await fetch(url, {
		method: "POST",
		headers: {
			"Authorization": creds.apiKey,
			"Accept": "application/json",
			"Content-Type": "application/json",
		},
		body: JSON.stringify(forwardBody),
		signal: AbortSignal.timeout(10000),
	}).catch(() => null);

	if (!upstream) return c.json({ error: "hub unreachable" }, 502);

	// Forward the hub's response honestly — both 200/201 and 4xx (notably
	// 403 "not a member of that sharing group"). Returning JSON shape on
	// success means the UI never sees a stripped/mangled token.
	const text = await upstream.text();
	const contentType = upstream.headers.get("content-type") ?? "application/json";
	return new Response(text, {
		status: upstream.status,
		headers: { "content-type": contentType },
	});
});
