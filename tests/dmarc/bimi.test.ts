// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Unit tests for `workers/dmarc/bimi.ts`.
 *
 * Coverage per issue #245 acceptance criteria:
 *   1. TXT record present with `a=` URL → hasVmc: true
 *   2. TXT record present without `a=`  → hasVmc: false
 *   3. NXDOMAIN / no record             → { configured: false }
 *   4. DoH timeout                      → { configured: false }
 *
 * URL host matching uses `new URL(url).hostname` throughout — never
 * `url.startsWith(...)` or `url.includes(...)`. This is a hard repo
 * invariant (CLAUDE.md) enforced by CodeQL.
 */

import { describe, expect, it } from "vitest";
import {
	emptyBimiPosture,
	fetchBimiPosture,
	parseBimiTxt,
	selectBimiRecord,
	type BimiKv,
} from "../../workers/dmarc/bimi";

// ── parseBimiTxt ────────────────────────────────────────────────────────────

describe("parseBimiTxt", () => {
	it("returns configured:true hasVmc:true when a= is present and non-empty", () => {
		const r = parseBimiTxt(
			"v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem",
		);
		expect(r).toEqual({ configured: true, hasVmc: true });
	});

	it("returns configured:true hasVmc:false when a= is absent", () => {
		const r = parseBimiTxt("v=BIMI1; l=https://example.com/logo.svg");
		expect(r).toEqual({ configured: true, hasVmc: false });
	});

	it("returns configured:true hasVmc:false when a= is present but empty", () => {
		const r = parseBimiTxt("v=BIMI1; l=https://example.com/logo.svg; a=");
		expect(r).toEqual({ configured: true, hasVmc: false });
	});

	it("returns null for non-BIMI1 records", () => {
		expect(parseBimiTxt("v=spf1 -all")).toBeNull();
		expect(parseBimiTxt("v=DMARC1; p=reject")).toBeNull();
		expect(parseBimiTxt("")).toBeNull();
	});

	it("is case-insensitive on tag names", () => {
		const r = parseBimiTxt("V=BIMI1; A=https://example.com/vmc.pem");
		expect(r?.hasVmc).toBe(true);
	});
});

// ── selectBimiRecord ────────────────────────────────────────────────────────

describe("selectBimiRecord", () => {
	it("picks the v=BIMI1-prefixed record from a mixed list", () => {
		const r = selectBimiRecord([
			"v=spf1 -all",
			"v=BIMI1; l=https://example.com/logo.svg",
		]);
		expect(r).toBe("v=BIMI1; l=https://example.com/logo.svg");
	});

	it("returns null when no BIMI1 record is present", () => {
		expect(selectBimiRecord(["v=spf1 -all"])).toBeNull();
		expect(selectBimiRecord([])).toBeNull();
	});
});

// ── fetchBimiPosture ─────────────────────────────────────────────────────────

/** Minimal KV fake for tests. */
function fakeKv(initial: Record<string, unknown> = {}): BimiKv & {
	store: Map<string, string>;
} {
	const store = new Map<string, string>();
	for (const [k, v] of Object.entries(initial)) {
		store.set(k, JSON.stringify(v));
	}
	return {
		store,
		async get(key: string, _type: "json") {
			const raw = store.get(key);
			return raw ? (JSON.parse(raw) as unknown) : null;
		},
		async put(key: string, value: string) {
			store.set(key, value);
		},
	};
}

/** Build a DoH JSON response containing the given TXT record strings. */
function dohTxtResponse(records: string[]): Response {
	return new Response(
		JSON.stringify({
			Status: 0,
			Answer: records.map((data) => ({
				name: "default._bimi.acme.com",
				type: 16,
				data,
			})),
		}),
		{ status: 200, headers: { "content-type": "application/dns-json" } },
	);
}

describe("fetchBimiPosture", () => {
	// ── Acceptance criterion 1: TXT with a= → hasVmc: true ────────────────

	it("returns { configured: true, hasVmc: true } when a= is present (VMC)", async () => {
		const fetchImpl = async (url: string) => {
			// Hostname-based dispatch — CodeQL CLAUDE.md invariant.
			expect(new URL(url).hostname).toBe("cloudflare-dns.com");
			return dohTxtResponse([
				'"v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem"',
			]);
		};
		const result = await fetchBimiPosture("acme.com", { fetchImpl });
		expect(result).toEqual({ configured: true, hasVmc: true });
	});

	// ── Acceptance criterion 2: TXT without a= → hasVmc: false ───────────

	it("returns { configured: true, hasVmc: false } when a= is absent (no VMC)", async () => {
		const fetchImpl = async () =>
			dohTxtResponse(['"v=BIMI1; l=https://example.com/logo.svg"']);
		const result = await fetchBimiPosture("acme.com", { fetchImpl });
		expect(result).toEqual({ configured: true, hasVmc: false });
	});

	// ── Acceptance criterion 3: NXDOMAIN → { configured: false } ─────────

	it("returns { configured: false } on NXDOMAIN (empty Answer array)", async () => {
		const fetchImpl = async () =>
			new Response(
				JSON.stringify({ Status: 3, Answer: [] }),
				{ status: 200, headers: { "content-type": "application/dns-json" } },
			);
		const result = await fetchBimiPosture("acme.com", { fetchImpl });
		expect(result).toEqual({ configured: false });
	});

	it("returns { configured: false } when Answer array is absent", async () => {
		const fetchImpl = async () =>
			new Response(
				JSON.stringify({ Status: 0 }),
				{ status: 200, headers: { "content-type": "application/dns-json" } },
			);
		const result = await fetchBimiPosture("acme.com", { fetchImpl });
		expect(result).toEqual({ configured: false });
	});

	// ── Acceptance criterion 4: DoH timeout → { configured: false } ───────

	it("returns { configured: false } when fetch rejects (timeout / network error)", async () => {
		const fetchImpl = async (): Promise<Response> => {
			throw new DOMException("The operation was aborted.", "AbortError");
		};
		const result = await fetchBimiPosture("acme.com", { fetchImpl });
		expect(result).toEqual({ configured: false });
	});

	it("returns { configured: false } on any fetch rejection (never throws)", async () => {
		const fetchImpl = async (): Promise<Response> => {
			throw new Error("network failure");
		};
		const result = await fetchBimiPosture("acme.com", { fetchImpl });
		expect(result).toEqual(emptyBimiPosture());
	});

	// ── URL correctness ────────────────────────────────────────────────────

	it("queries default._bimi.<domain> TXT via DoH on cloudflare-dns.com", async () => {
		let captured = "";
		const fetchImpl = async (url: string) => {
			captured = url;
			return dohTxtResponse(['"v=BIMI1; l=https://example.com/logo.svg"']);
		};
		await fetchBimiPosture("acme.com", { fetchImpl });
		const u = new URL(captured);
		// Hostname comparison only — CodeQL CLAUDE.md invariant.
		expect(u.hostname).toBe("cloudflare-dns.com");
		expect(u.pathname).toBe("/dns-query");
		expect(u.searchParams.get("name")).toBe("default._bimi.acme.com");
		expect(u.searchParams.get("type")).toBe("TXT");
	});

	// ── KV caching ────────────────────────────────────────────────────────

	it("reads from KV cache and skips DoH when a valid posture is stored", async () => {
		const kv = fakeKv({
			"dmarc-bimi:v1:acme.com": { configured: true, hasVmc: true },
		});
		let calls = 0;
		const fetchImpl = async () => {
			calls += 1;
			return dohTxtResponse(['"v=BIMI1; l=https://example.com/logo.svg"']);
		};
		const result = await fetchBimiPosture("acme.com", { fetchImpl, kv });
		expect(calls).toBe(0);
		expect(result).toEqual({ configured: true, hasVmc: true });
	});

	it("writes the resolved posture to KV after a DoH lookup", async () => {
		const kv = fakeKv();
		const fetchImpl = async () =>
			dohTxtResponse([
				'"v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem"',
			]);
		await fetchBimiPosture("acme.com", { fetchImpl, kv });
		// Fire-and-forget write: flush microtask queue.
		await new Promise((r) => setTimeout(r, 0));
		const cached = kv.store.get("dmarc-bimi:v1:acme.com");
		expect(cached).toBeDefined();
		expect(JSON.parse(cached!)).toEqual({ configured: true, hasVmc: true });
	});

	it("returns { configured: false } on non-200 DoH response", async () => {
		const fetchImpl = async () => new Response("error", { status: 503 });
		const result = await fetchBimiPosture("acme.com", { fetchImpl });
		expect(result).toEqual({ configured: false });
	});

	it("returns { configured: false } on malformed DoH JSON", async () => {
		const fetchImpl = async () =>
			new Response("<html>oops</html>", { status: 200 });
		const result = await fetchBimiPosture("acme.com", { fetchImpl });
		expect(result).toEqual({ configured: false });
	});
});
