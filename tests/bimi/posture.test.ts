// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { describe, expect, it } from "vitest";
import {
	emptyBimiPosture,
	fetchBimiPosture,
	normalizeDohTxtData,
	parseBimiTxt,
	selectBimiRecord,
	type BimiKv,
} from "../../workers/bimi/posture";

describe("parseBimiTxt", () => {
	it("parses a record with both logo and VMC URLs", () => {
		const r = parseBimiTxt(
			"v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem",
		);
		expect(r).toEqual({ configured: true, hasLogo: true, hasVmc: true });
	});

	it("parses a record with only a logo (no VMC)", () => {
		const r = parseBimiTxt("v=BIMI1; l=https://example.com/logo.svg");
		expect(r).toEqual({ configured: true, hasLogo: true, hasVmc: false });
	});

	it("treats empty l= as 'not present' (indicator-not-supported intent)", () => {
		const r = parseBimiTxt("v=BIMI1; l=");
		expect(r).toEqual({ configured: true, hasLogo: false, hasVmc: false });
	});

	it("returns null for non-BIMI1 records", () => {
		expect(parseBimiTxt("v=spf1 -all")).toBeNull();
		expect(parseBimiTxt("not even a tag list")).toBeNull();
		expect(parseBimiTxt("")).toBeNull();
	});

	it("is case-insensitive on tag names but not on values", () => {
		const r = parseBimiTxt("V=BIMI1; L=https://example.com/Logo.SVG");
		expect(r?.hasLogo).toBe(true);
	});

	it("ignores duplicate tags after the first occurrence", () => {
		const r = parseBimiTxt(
			"v=BIMI1; l=https://first.example/logo.svg; l=https://second.example/logo.svg",
		);
		expect(r?.hasLogo).toBe(true);
	});
});

describe("selectBimiRecord", () => {
	it("picks the v=BIMI1-prefixed record", () => {
		const r = selectBimiRecord([
			"google-site-verification=abc",
			"v=BIMI1; l=https://example.com/logo.svg",
			"v=spf1 -all",
		]);
		expect(r).toBe("v=BIMI1; l=https://example.com/logo.svg");
	});

	it("returns null when no BIMI1 record present", () => {
		expect(selectBimiRecord(["v=spf1 -all"])).toBeNull();
	});

	it("matches case-insensitively and tolerates whitespace around v=", () => {
		expect(selectBimiRecord(["V = BIMI1; l=https://x"])).toMatch(/BIMI1/);
	});
});

describe("normalizeDohTxtData", () => {
	it("concatenates multi-string TXT-record fragments without inserting whitespace", () => {
		expect(normalizeDohTxtData('"v=BIMI1; " "l=https://example.com/logo.svg"')).toBe(
			"v=BIMI1; l=https://example.com/logo.svg",
		);
	});

	it("strips surrounding quotes from a single-fragment string", () => {
		expect(normalizeDohTxtData('"v=BIMI1; l=https://x"')).toBe(
			"v=BIMI1; l=https://x",
		);
	});
});

// ── DoH integration tests ──────────────────────────────────────────────

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
	it("resolves a record with logo + VMC over DoH", async () => {
		const fetchImpl = async (url: string) => {
			// Hostname-based dispatch — substring matching on URLs is a CodeQL
			// `js/incomplete-url-substring-sanitization` trip wire (repo CLAUDE.md).
			expect(new URL(url).hostname).toBe("cloudflare-dns.com");
			return dohTxtResponse([
				'"v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem"',
			]);
		};
		const r = await fetchBimiPosture("acme.com", { fetchImpl });
		expect(r).toEqual({ configured: true, hasLogo: true, hasVmc: true });
	});

	it("distinguishes 'no record' (configured=false) from 'unavailable' (configured=null)", async () => {
		const fetchImpl = async () =>
			new Response(JSON.stringify({ Status: 0, Answer: [] }), { status: 200 });
		const r = await fetchBimiPosture("acme.com", { fetchImpl });
		expect(r).toEqual({ configured: false, hasLogo: false, hasVmc: false });
	});

	it("returns the empty sentinel when DoH returns non-200", async () => {
		const fetchImpl = async () => new Response("nope", { status: 500 });
		const r = await fetchBimiPosture("acme.com", { fetchImpl });
		expect(r).toEqual(emptyBimiPosture());
	});

	it("returns the empty sentinel when fetch rejects (timeout / network)", async () => {
		const fetchImpl = async () => {
			throw new Error("network");
		};
		const r = await fetchBimiPosture("acme.com", { fetchImpl });
		expect(r).toEqual(emptyBimiPosture());
	});

	it("returns the empty sentinel when DoH returns malformed JSON", async () => {
		const fetchImpl = async () => new Response("<html>", { status: 200 });
		const r = await fetchBimiPosture("acme.com", { fetchImpl });
		expect(r).toEqual(emptyBimiPosture());
	});

	it("returns the empty sentinel when TXT data isn't parseable as v=BIMI1", async () => {
		// Malformed `v=BIMI1` tag — the record exists but isn't a valid BIMI1.
		const fetchImpl = async () => dohTxtResponse(['"not a bimi record"']);
		const r = await fetchBimiPosture("acme.com", { fetchImpl });
		// `configured: false` — we did get a TXT response with no v=BIMI1 in it.
		expect(r).toEqual({ configured: false, hasLogo: false, hasVmc: false });
	});

	it("queries the default._bimi.<domain> label", async () => {
		let captured = "";
		const fetchImpl = async (url: string) => {
			captured = url;
			return dohTxtResponse(['"v=BIMI1; l=https://example.com/logo.svg"']);
		};
		await fetchBimiPosture("acme.com", { fetchImpl });
		const u = new URL(captured);
		expect(u.hostname).toBe("cloudflare-dns.com");
		expect(u.pathname).toBe("/dns-query");
		expect(u.searchParams.get("name")).toBe("default._bimi.acme.com");
		expect(u.searchParams.get("type")).toBe("TXT");
	});

	it("reads from KV cache when a parsed posture is stored", async () => {
		const kv = fakeKv({
			"bimi:v1:acme.com": {
				configured: true,
				hasLogo: true,
				hasVmc: false,
			},
		});
		let calls = 0;
		const fetchImpl = async () => {
			calls += 1;
			return dohTxtResponse(['"v=BIMI1; l=https://example.com/logo.svg"']);
		};
		const r = await fetchBimiPosture("acme.com", { fetchImpl, kv });
		expect(calls).toBe(0);
		expect(r).toEqual({ configured: true, hasLogo: true, hasVmc: false });
	});

	it("writes the resolved posture (including null sentinels) to KV", async () => {
		const kv = fakeKv();
		const fetchImpl = async () =>
			new Response(JSON.stringify({ Status: 0, Answer: [] }), { status: 200 });
		await fetchBimiPosture("acme.com", { fetchImpl, kv });
		await new Promise((r) => setTimeout(r, 0));
		const cached = kv.store.get("bimi:v1:acme.com");
		expect(cached).toBeDefined();
		// `configured: false` is what we store for "no record" (NOT the empty
		// sentinel) — it's a real, durable answer to the lookup.
		expect(JSON.parse(cached!)).toEqual({
			configured: false,
			hasLogo: false,
			hasVmc: false,
		});
	});
});
