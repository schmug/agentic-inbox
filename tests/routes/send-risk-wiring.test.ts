// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Route-level tests for send-risk classifier wiring (issue #262 — #15 slice 3).
 *
 * Tests that:
 *   - POST /api/v1/mailboxes/:id/emails calls classifySend and gates Tier ≥1
 *     sends behind x-confirmation-token.
 *   - POST /api/v1/mailboxes/:id/emails/preflight returns { tier, reasons }
 *     without sending.
 *
 * Strategy: build a minimal Hono app that wires `classifySend` directly
 * (not the full workers/index.ts graph) so the test stays pure and avoids
 * importing Durable Objects or Email bindings.  The handler mirrors the
 * relevant slice of the production POST /emails code path.
 *
 * URL mock note: all URL-based dispatch uses `new URL(url).hostname` per the
 * project CLAUDE.md convention — no `startsWith` / `includes` patterns.
 */

import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import { classifySend, type SendRisk } from "../../workers/security/send-risk";
import { SendEmailRequestSchema } from "../../workers/lib/schemas";

// ---------------------------------------------------------------------------
// Minimal test app that mirrors the relevant slice of index.ts
// ---------------------------------------------------------------------------

/**
 * Build a Hono app with:
 *   - POST /api/v1/mailboxes/:mailboxId/emails/preflight → { tier, reasons }
 *   - POST /api/v1/mailboxes/:mailboxId/emails          → gated send (stub)
 *
 * `onSend` is called when the send actually proceeds past the risk gate, so
 * tests can assert it was (or was not) invoked.
 */
function makeApp(onSend?: () => void) {
	const app = new Hono<{ Variables: { mailboxId: string } }>();

	// Preflight — same body shape as send, returns tier+reasons, never sends.
	app.post("/api/v1/mailboxes/:mailboxId/emails/preflight", async (c) => {
		const mailboxId = c.req.param("mailboxId")!;
		const body = SendEmailRequestSchema.parse(await c.req.json());
		const { to, cc, bcc, subject, html, text, attachments } = body;
		const risk = classifySend({
			to, cc, bcc,
			subject,
			body: html || text,
			attachments: attachments?.map((att) => ({ filename: att.filename })),
			mailboxId,
		});
		return c.json({ tier: risk.tier, reasons: risk.reasons });
	});

	// Send — classify then gate on token for Tier ≥1.
	app.post("/api/v1/mailboxes/:mailboxId/emails", async (c) => {
		const mailboxId = c.req.param("mailboxId")!;
		const body = SendEmailRequestSchema.parse(await c.req.json());
		const { to, cc, bcc, subject, html, text, attachments } = body;

		const risk: SendRisk = classifySend({
			to, cc, bcc,
			subject,
			body: html || text,
			attachments: attachments?.map((att) => ({ filename: att.filename })),
			mailboxId,
		});

		if (risk.tier >= 1) {
			const token = c.req.header("x-confirmation-token");
			if (!token) {
				return c.json({ error: "confirmation_required", risk }, 401);
			}
			// Placeholder validation (slice 2 / #264 wires real verify).
		}

		// Simulate successful send — in production this calls createEmail +
		// sendEmail; here we just record the call and return 202.
		onSend?.();
		return c.json({ id: "stub-msg-id", status: "sent" }, 202);
	});

	return app;
}

/** Minimal valid send body for an internal-only (Tier 0) send. */
const TIER0_BODY = {
	to: "colleague@internal.example",
	from: "operator@internal.example",
	subject: "Hello",
	text: "Hi there",
};

/** Tier 1 body — external recipient triggers Tier 1. */
const TIER1_BODY = {
	to: "vendor@external.com",
	from: "operator@internal.example",
	subject: "Hello",
	text: "Hi there",
};

/** Tier 2 body — BEC keyword triggers Tier 2. */
const TIER2_BODY = {
	to: "colleague@internal.example",
	from: "operator@internal.example",
	subject: "Hello",
	text: "Please send a wire transfer",
};

function jsonPost(body: unknown, extraHeaders: Record<string, string> = {}) {
	return {
		method: "POST",
		headers: { "Content-Type": "application/json", ...extraHeaders },
		body: JSON.stringify(body),
	};
}

// ---------------------------------------------------------------------------
// Tier 0 — send proceeds with no token required
// ---------------------------------------------------------------------------

describe("POST /emails — Tier 0 (internal-only send)", () => {
	it("returns 202 and invokes send with no x-confirmation-token header", async () => {
		let sent = false;
		const app = makeApp(() => { sent = true; });
		const res = await app.request(
			"/api/v1/mailboxes/operator@internal.example/emails",
			jsonPost(TIER0_BODY),
		);
		expect(res.status).toBe(202);
		expect(sent).toBe(true);
		const json = await res.json() as { status: string };
		expect(json.status).toBe("sent");
	});
});

// ---------------------------------------------------------------------------
// Tier 1 — external recipient requires token
// ---------------------------------------------------------------------------

describe("POST /emails — Tier 1 (external recipient)", () => {
	it("returns 401 with confirmation_required when token absent", async () => {
		let sent = false;
		const app = makeApp(() => { sent = true; });
		const res = await app.request(
			"/api/v1/mailboxes/operator@internal.example/emails",
			jsonPost(TIER1_BODY),
		);
		expect(res.status).toBe(401);
		expect(sent).toBe(false);
		const json = await res.json() as { error: string; risk: SendRisk };
		expect(json.error).toBe("confirmation_required");
		expect(json.risk.tier).toBe(1);
	});

	it("proceeds (202) when x-confirmation-token is present", async () => {
		let sent = false;
		const app = makeApp(() => { sent = true; });
		const res = await app.request(
			"/api/v1/mailboxes/operator@internal.example/emails",
			jsonPost(TIER1_BODY, { "x-confirmation-token": "placeholder-token" }),
		);
		expect(res.status).toBe(202);
		expect(sent).toBe(true);
	});
});

// ---------------------------------------------------------------------------
// Tier 2 — BEC keyword requires token
// ---------------------------------------------------------------------------

describe("POST /emails — Tier 2 (BEC keyword)", () => {
	it("returns 401 with confirmation_required when token absent", async () => {
		let sent = false;
		const app = makeApp(() => { sent = true; });
		const res = await app.request(
			"/api/v1/mailboxes/operator@internal.example/emails",
			jsonPost(TIER2_BODY),
		);
		expect(res.status).toBe(401);
		expect(sent).toBe(false);
		const json = await res.json() as { error: string; risk: SendRisk };
		expect(json.error).toBe("confirmation_required");
		expect(json.risk.tier).toBe(2);
	});
});

// ---------------------------------------------------------------------------
// Preflight — returns tier+reasons, never sends
// ---------------------------------------------------------------------------

describe("POST /emails/preflight", () => {
	it("returns tier and reasons for a Tier 0 (internal) send without sending", async () => {
		let sent = false;
		const app = makeApp(() => { sent = true; });
		const res = await app.request(
			"/api/v1/mailboxes/operator@internal.example/emails/preflight",
			jsonPost(TIER0_BODY),
		);
		expect(res.status).toBe(200);
		expect(sent).toBe(false);
		const json = await res.json() as { tier: number; reasons: string[] };
		expect(json.tier).toBe(0);
		expect(Array.isArray(json.reasons)).toBe(true);
	});

	it("returns tier 1 and reasons for an external recipient without sending", async () => {
		let sent = false;
		const app = makeApp(() => { sent = true; });
		const res = await app.request(
			"/api/v1/mailboxes/operator@internal.example/emails/preflight",
			jsonPost(TIER1_BODY),
		);
		expect(res.status).toBe(200);
		expect(sent).toBe(false);
		const json = await res.json() as { tier: number; reasons: string[] };
		expect(json.tier).toBe(1);
		expect(json.reasons.length).toBeGreaterThan(0);
		expect(json.reasons.some((r) => r.includes("External"))).toBe(true);
	});

	it("returns tier 2 and reasons for a BEC keyword body without sending", async () => {
		let sent = false;
		const app = makeApp(() => { sent = true; });
		const res = await app.request(
			"/api/v1/mailboxes/operator@internal.example/emails/preflight",
			jsonPost(TIER2_BODY),
		);
		expect(res.status).toBe(200);
		expect(sent).toBe(false);
		const json = await res.json() as { tier: number; reasons: string[] };
		expect(json.tier).toBe(2);
		expect(json.reasons.some((r) => r.includes("keyword"))).toBe(true);
	});
});
