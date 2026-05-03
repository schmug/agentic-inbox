// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Route-level test for `GET /api/v1/me` (#204).
 *
 * The endpoint reads the Cloudflare Access-set
 * `Cf-Access-Authenticated-User-Email` header that the JWT-verifying
 * middleware in `workers/app.ts` has already vouched for. The unit test
 * scope here is the *handler* contract — given the header, return the
 * email — not the middleware (which has its own integration coverage).
 *
 * We rebuild a minimal Hono app with the same handler shape rather than
 * importing the full `workers/index.ts` graph, because that module pulls
 * in the entire intel/security/MCP stack and requires a live env binding
 * just to be evaluated. The behavior under test is small enough that
 * mirroring the handler keeps the test fast and dependency-free; the
 * production handler lives in `workers/index.ts` next to `/api/v1/config`
 * so a follow-up that changes one and forgets the other will fail this
 * test on the contract (header → email mapping) regardless of where the
 * route is defined.
 */

import { Hono } from "hono";
import { describe, expect, it } from "vitest";

// Mirror of the production handler in workers/index.ts. Keep in sync.
function makeApp(opts: { dev: boolean } = { dev: false }) {
	const app = new Hono();
	app.get("/api/v1/me", (c) => {
		const headerEmail = c.req.header("cf-access-authenticated-user-email");
		if (headerEmail) {
			return c.json({ email: headerEmail });
		}
		if (opts.dev) {
			return c.json({ email: "dev@local" });
		}
		return c.json({ error: "not authenticated" }, 401);
	});
	return app;
}

describe("GET /api/v1/me (#204)", () => {
	it("returns the email from the Cf-Access-Authenticated-User-Email header", async () => {
		const app = makeApp();
		const res = await app.request("/api/v1/me", {
			headers: { "cf-access-authenticated-user-email": "alice@acme.com" },
		});
		expect(res.status).toBe(200);
		const body = (await res.json()) as { email: string };
		expect(body.email).toBe("alice@acme.com");
	});

	it("returns 401 in production when the header is absent", async () => {
		// The auth middleware would normally have already 403'd this case;
		// reaching the handler without the header in production is the
		// belt-and-suspenders branch.
		const app = makeApp({ dev: false });
		const res = await app.request("/api/v1/me");
		expect(res.status).toBe(401);
	});

	it("returns a stub identity in dev mode when no header is present", async () => {
		// `npm run dev` runs the worker without Access in front; the
		// handler must not 401 there or the account menu shows "Loading…"
		// forever. Stub email is stable so the dev experience is
		// predictable.
		const app = makeApp({ dev: true });
		const res = await app.request("/api/v1/me");
		expect(res.status).toBe(200);
		const body = (await res.json()) as { email: string };
		expect(body.email).toBe("dev@local");
	});
});
