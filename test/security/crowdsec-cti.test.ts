// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * CrowdSec CTI client tests.
 *
 * Covers the four user-visible behaviours that operators rely on:
 *   - missing API key → null (so unconfigured deploys no-op)
 *   - 200 → normalised summary, cached
 *   - 404 → null, miss sentinel cached briefly
 *   - 429 → null, NOT cached, warning logged
 *
 * Cache hit must avoid a second fetch; that's the load-bearing rate-limit
 * defence and we assert on it explicitly.
 */

import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";

import { lookupIp, normalize } from "../../workers/intel/crowdsec-cti";
import type { Env } from "../../workers/types";

const FIXTURE_DIR = join(__dirname, "..", "fixtures", "intel");

interface FakeKV {
	store: Map<string, { value: string; expiresAt: number | null }>;
	get: (key: string, type?: "text" | "arrayBuffer") => Promise<string | null>;
	put: (key: string, value: string, opts?: { expirationTtl?: number }) => Promise<void>;
}

function makeKv(): FakeKV {
	const store = new Map<string, { value: string; expiresAt: number | null }>();
	return {
		store,
		async get(key: string) {
			const row = store.get(key);
			if (!row) return null;
			if (row.expiresAt !== null && row.expiresAt < Date.now()) {
				store.delete(key);
				return null;
			}
			return row.value;
		},
		async put(key, value, opts) {
			const expiresAt = opts?.expirationTtl
				? Date.now() + opts.expirationTtl * 1000
				: null;
			store.set(key, { value, expiresAt });
		},
	};
}

function makeEnv(opts: { apiKey?: string; kv?: FakeKV } = {}): Env {
	return {
		CROWDSEC_CTI_API_KEY: opts.apiKey,
		BLOOM_KV: opts.kv as unknown as KVNamespace | undefined,
	} as unknown as Env;
}

function jsonResponse(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "content-type": "application/json" },
	});
}

describe("crowdsec-cti normalize()", () => {
	it("projects a representative payload to the documented shape", async () => {
		const raw = JSON.parse(
			await readFile(join(FIXTURE_DIR, "crowdsec-cti-malicious.json"), "utf8"),
		);
		const summary = normalize(raw);
		expect(summary).not.toBeNull();
		expect(summary?.reputation).toBe("malicious");
		expect(summary?.classifications).toContain("tor");
		expect(summary?.behaviors).toContain("http:phishing");
		expect(summary?.scores.threat).toBe(5);
	});

	it("returns 'unknown' reputation when the field is missing or unrecognised", () => {
		expect(normalize({})?.reputation).toBe("unknown");
		expect(normalize({ reputation: "weird-value" })?.reputation).toBe("unknown");
	});

	it("treats non-object input as null", () => {
		expect(normalize(null)).toBeNull();
		expect(normalize("string")).toBeNull();
	});
});

describe("crowdsec-cti lookupIp()", () => {
	it("returns null when CROWDSEC_CTI_API_KEY is not configured", async () => {
		const env = makeEnv({ kv: makeKv() });
		const fetcher = vi.fn();
		const out = await lookupIp(env, "203.0.113.42", fetcher as never);
		expect(out).toBeNull();
		expect(fetcher).not.toHaveBeenCalled();
	});

	it("on 200 returns the normalised summary AND caches it", async () => {
		const raw = JSON.parse(
			await readFile(join(FIXTURE_DIR, "crowdsec-cti-malicious.json"), "utf8"),
		);
		const kv = makeKv();
		const env = makeEnv({ apiKey: "test-key", kv });
		const fetcher = vi.fn(async () => jsonResponse(raw, 200));

		const first = await lookupIp(env, "203.0.113.42", fetcher);
		expect(first?.reputation).toBe("malicious");
		expect(fetcher).toHaveBeenCalledTimes(1);
		// Cache populated.
		expect(kv.store.get("cti:crowdsec:203.0.113.42")?.value).toBeDefined();
	});

	it("on 200 + cached entry, second call hits the cache (no second fetch)", async () => {
		const raw = JSON.parse(
			await readFile(join(FIXTURE_DIR, "crowdsec-cti-malicious.json"), "utf8"),
		);
		const kv = makeKv();
		const env = makeEnv({ apiKey: "test-key", kv });
		const fetcher = vi.fn(async () => jsonResponse(raw, 200));

		await lookupIp(env, "203.0.113.42", fetcher);
		const second = await lookupIp(env, "203.0.113.42", fetcher);

		expect(second?.reputation).toBe("malicious");
		expect(fetcher).toHaveBeenCalledTimes(1);
	});

	it("on 404 returns null and caches a miss sentinel briefly", async () => {
		const kv = makeKv();
		const env = makeEnv({ apiKey: "test-key", kv });
		const fetcher = vi.fn(async () => new Response("", { status: 404 }));

		const out = await lookupIp(env, "198.51.100.7", fetcher);
		expect(out).toBeNull();
		expect(fetcher).toHaveBeenCalledTimes(1);

		const cached = kv.store.get("cti:crowdsec:198.51.100.7");
		expect(cached).toBeDefined();
		expect(cached?.value).toMatch(/cti_miss/);

		// Second call must not re-fetch — sentinel short-circuits.
		const second = await lookupIp(env, "198.51.100.7", fetcher);
		expect(second).toBeNull();
		expect(fetcher).toHaveBeenCalledTimes(1);
	});

	it("on 429 returns null, logs a warning, and does NOT cache (no poisoning)", async () => {
		const kv = makeKv();
		const env = makeEnv({ apiKey: "test-key", kv });
		const fetcher = vi.fn(async () => new Response("rate limited", { status: 429 }));
		const warn = vi.spyOn(console, "warn").mockImplementation(() => {});

		try {
			const out = await lookupIp(env, "192.0.2.5", fetcher);
			expect(out).toBeNull();
			expect(warn).toHaveBeenCalled();
			// CRITICAL: no cache write on rate-limit, otherwise we'd poison the
			// cache with `null` and starve out future enrichment.
			expect(kv.store.has("cti:crowdsec:192.0.2.5")).toBe(false);
		} finally {
			warn.mockRestore();
		}
	});

	it("on network error returns null without caching", async () => {
		const kv = makeKv();
		const env = makeEnv({ apiKey: "test-key", kv });
		const fetcher = vi.fn(async () => {
			throw new Error("ECONNRESET");
		});

		const out = await lookupIp(env, "192.0.2.6", fetcher);
		expect(out).toBeNull();
		expect(kv.store.has("cti:crowdsec:192.0.2.6")).toBe(false);
	});

	it("sends the API key in the x-api-key header (CrowdSec convention)", async () => {
		const kv = makeKv();
		const env = makeEnv({ apiKey: "secret-token", kv });
		const fetcher = vi.fn(async (_url: string, init?: RequestInit) => {
			const headers = new Headers(init?.headers);
			expect(headers.get("x-api-key")).toBe("secret-token");
			return new Response("", { status: 404 });
		});
		await lookupIp(env, "203.0.113.99", fetcher);
		expect(fetcher).toHaveBeenCalledTimes(1);
	});
});
