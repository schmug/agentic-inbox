// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

import { Hono } from "hono";
import { jwtVerify, createRemoteJWKSet } from "jose";
import { z } from "zod";
import { signConfirmationToken } from "../lib/confirm-token";
import type { Env } from "../types";

// Mirrors getAccessUrls in workers/app.ts — needed here for step-up JWKS resolution.
function getAccessUrls(teamDomain: string) {
	const certsPath = "/cdn-cgi/access/certs";
	const teamUrl = new URL(teamDomain);
	const issuer = teamUrl.origin;
	const certsUrl = teamUrl.pathname.endsWith(certsPath)
		? teamUrl
		: new URL(certsPath, issuer);
	return { issuer, certsUrl };
}

async function computePayloadHash(
	to: string | string[],
	subject: string,
	body: string,
	attachmentIds: string[],
): Promise<string> {
	const toArr = (Array.isArray(to) ? [...to] : [to]).sort();
	const canonical = JSON.stringify({
		to: toArr,
		subject,
		body,
		attachmentIds: [...attachmentIds].sort(),
	});
	const digest = await crypto.subtle.digest(
		"SHA-256",
		new TextEncoder().encode(canonical),
	);
	return Array.from(new Uint8Array(digest))
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
}

const ConfirmBodySchema = z.object({
	tier: z.number().int().min(0).max(2),
	mailboxId: z.string().min(1),
	to: z.union([z.string(), z.array(z.string())]),
	subject: z.string().optional().default(""),
	body: z.string().optional().default(""),
	attachmentIds: z.array(z.string()).optional().default([]),
});

export const confirmRoute = new Hono<{ Bindings: Env }>();

confirmRoute.post("/", async (c) => {
	const { STEP_UP_AUD, TEAM_DOMAIN, CONFIRMATION_TOKEN_SECRET, BLOOM_KV } = c.env;

	if (!STEP_UP_AUD || !CONFIRMATION_TOKEN_SECRET || !TEAM_DOMAIN) {
		return c.json({ error: "step-up auth not configured" }, 503);
	}

	const token = c.req.header("cf-access-jwt-assertion");
	if (!token) {
		return c.json({ error: "missing step-up JWT" }, 401);
	}

	try {
		const { issuer, certsUrl } = getAccessUrls(TEAM_DOMAIN);
		const JWKS = createRemoteJWKSet(certsUrl);
		await jwtVerify(token, JWKS, { issuer, audience: STEP_UP_AUD });
	} catch {
		return c.json({ error: "invalid step-up JWT" }, 401);
	}

	const parseResult = ConfirmBodySchema.safeParse(
		await c.req.json().catch(() => ({})),
	);
	if (!parseResult.success) {
		return c.json({ error: "invalid request body" }, 400);
	}

	const { tier, mailboxId, to, subject, body, attachmentIds } = parseResult.data;
	const payloadHash = await computePayloadHash(to, subject, body, attachmentIds);
	const jti = crypto.randomUUID();

	const confirmToken = await signConfirmationToken(
		{ tier: tier as 0 | 1 | 2, mailboxId, payloadHash, jti },
		CONFIRMATION_TOKEN_SECRET,
	);

	await BLOOM_KV.put(`confirm-jti:${jti}`, "1", { expirationTtl: 120 });

	return c.json({ token: confirmToken });
});
