// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { describe, expect, it } from "vitest";
import {
	emptyTlsRptPosture,
	fetchTlsRptPosture,
	normalizeDohTxtData,
	parseRuaList,
	parseTlsRptTxt,
	selectTlsRptRecord,
	type TlsRptKv,
} from "../../workers/tlsrpt/posture";

describe("parseTlsRptTxt", () => {
	it("parses a record with a single mailto rua endpoint", () => {
		const r = parseTlsRptTxt("v=TLSRPTv1; rua=mailto:tlsrpt@example.com");
		expect(r).toEqual({
			configured: true,
			endpoints: ["mailto:tlsrpt@example.com"],
		});
	});

	it("parses a record with a single https rua endpoint", () => {
		const r = parseTlsRptTxt(
			"v=TLSRPTv1; rua=https://reports.example.com/tlsrpt",
		);
		expect(r).toEqual({
			configured: true,
			endpoints: ["https://reports.example.com/tlsrpt"],
		});
	});

	it("parses a record with multiple comma-separated rua endpoints", () => {
		const r = parseTlsRptTxt(
			"v=TLSRPTv1; rua=mailto:tlsrpt@example.com,https://reports.example.com/tlsrpt",
		);
		expect(r).toEqual({
			configured: true,
			endpoints: [
				"mailto:tlsrpt@example.com",
				"https://reports.example.com/tlsrpt",
			],
		});
	});

	it("treats an empty rua= as 'configured but no endpoint published'", () => {
		const r = parseTlsRptTxt("v=TLSRPTv1; rua=");
		expect(r).toEqual({ configured: true, endpoints: [] });
	});

	it("treats a missing rua tag as configured-but-empty (defensive — not RFC compliant)", () => {
		// RFC 8460 §3 requires `rua=` on a TLSRPTv1 record, but we don't
		// gatekeep on that — surfacing "configured: true, endpoints: []"
		// matches what the operator actually published and lets the UI flag
		// the misconfig rather than swallowing it.
		const r = parseTlsRptTxt("v=TLSRPTv1");
		expect(r).toEqual({ configured: true, endpoints: [] });
	});

	it("returns null for non-TLSRPTv1 records", () => {
		expect(parseTlsRptTxt("v=spf1 -all")).toBeNull();
		expect(parseTlsRptTxt("not even a tag list")).toBeNull();
		expect(parseTlsRptTxt("")).toBeNull();
	});

	it("is case-insensitive on tag names", () => {
		const r = parseTlsRptTxt("V=TLSRPTv1; RUA=mailto:tlsrpt@example.com");
		expect(r?.endpoints).toEqual(["mailto:tlsrpt@example.com"]);
	});

	it("ignores duplicate rua tags after the first occurrence", () => {
		const r = parseTlsRptTxt(
			"v=TLSRPTv1; rua=mailto:first@example.com; rua=mailto:second@example.com",
		);
		expect(r?.endpoints).toEqual(["mailto:first@example.com"]);
	});

	it("trims whitespace around comma-separated endpoint URIs", () => {
		const r = parseTlsRptTxt(
			"v=TLSRPTv1; rua=mailto:tlsrpt@example.com , https://reports.example.com/tlsrpt",
		);
		expect(r?.endpoints).toEqual([
			"mailto:tlsrpt@example.com",
			"https://reports.example.com/tlsrpt",
		]);
	});
});

describe("parseRuaList", () => {
	it("returns [] for undefined / empty inputs", () => {
		expect(parseRuaList(undefined)).toEqual([]);
		expect(parseRuaList("")).toEqual([]);
		expect(parseRuaList("   ")).toEqual([]);
	});

	it("splits on commas and trims whitespace", () => {
		expect(parseRuaList("mailto:a@x, mailto:b@x  ,  https://r.example/t")).toEqual([
			"mailto:a@x",
			"mailto:b@x",
			"https://r.example/t",
		]);
	});

	it("drops empty items produced by trailing commas", () => {
		expect(parseRuaList("mailto:a@x,,mailto:b@x,")).toEqual([
			"mailto:a@x",
			"mailto:b@x",
		]);
	});
});

describe("selectTlsRptRecord", () => {
	it("picks the v=TLSRPTv1-prefixed record", () => {
		const r = selectTlsRptRecord([
			"google-site-verification=abc",
			"v=TLSRPTv1; rua=mailto:tlsrpt@example.com",
			"v=spf1 -all",
		]);
		expect(r).toBe("v=TLSRPTv1; rua=mailto:tlsrpt@example.com");
	});

	it("returns null when no TLSRPTv1 record present", () => {
		expect(selectTlsRptRecord(["v=spf1 -all"])).toBeNull();
		expect(selectTlsRptRecord([])).toBeNull();
	});

	it("matches case-insensitively and tolerates whitespace around v=", () => {
		expect(
			selectTlsRptRecord(["V = TLSRPTv1; rua=mailto:t@x"]),
		).toMatch(/TLSRPTv1/);
	});
});

describe("normalizeDohTxtData", () => {
	it("concatenates multi-string TXT-record fragments without inserting whitespace", () => {
		expect(
			normalizeDohTxtData(
				'"v=TLSRPTv1; " "rua=mailto:tlsrpt@example.com"',
			),
		).toBe("v=TLSRPTv1; rua=mailto:tlsrpt@example.com");
	});

	it("strips surrounding quotes from a single-fragment string", () => {
		expect(normalizeDohTxtData('"v=TLSRPTv1; rua=mailto:t@x"')).toBe(
			"v=TLSRPTv1; rua=mailto:t@x",
		);
	});
});

// ── DoH integration tests ──────────────────────────────────────────────

function fakeKv(initial: Record<string, unknown> = {}): TlsRptKv & {
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
				name: "_smtp._tls.acme.com",
				type: 16,
				data,
			})),
		}),
		{ status: 200, headers: { "content-type": "application/dns-json" } },
	);
}

describe("fetchTlsRptPosture", () => {
	it("resolves a configured record over DoH and returns the parsed endpoints", async () => {
		const fetchImpl = async (url: string) => {
			// Hostname-based dispatch — substring matching on URLs is a CodeQL
			// `js/incomplete-url-substring-sanitization` trip wire (repo CLAUDE.md).
			expect(new URL(url).hostname).toBe("cloudflare-dns.com");
			return dohTxtResponse([
				'"v=TLSRPTv1; rua=mailto:tlsrpt@example.com,https://reports.example.com/tlsrpt"',
			]);
		};
		const r = await fetchTlsRptPosture("acme.com", { fetchImpl });
		expect(r).toEqual({
			configured: true,
			endpoints: [
				"mailto:tlsrpt@example.com",
				"https://reports.example.com/tlsrpt",
			],
		});
	});

	it("distinguishes 'no record' (configured=false) from 'unavailable' (configured=null)", async () => {
		// Empty Answer array — durable "no TLSRPTv1 record at this label".
		const fetchImpl = async () =>
			new Response(JSON.stringify({ Status: 0, Answer: [] }), { status: 200 });
		const r = await fetchTlsRptPosture("acme.com", { fetchImpl });
		expect(r).toEqual({ configured: false, endpoints: [] });
	});

	it("treats DNS NXDOMAIN (Status 3, no Answer field) as the unavailable sentinel", async () => {
		// Real NXDOMAIN from Cloudflare DoH returns Status:3 with no Answer key.
		// This is distinct from Status:0 + empty Answer (NOERROR / no records),
		// which we map to the durable-negative { configured: false }. NXDOMAIN
		// signals the label itself doesn't exist — we treat that as transient
		// unavailability rather than caching "no record" for an hour.
		const fetchImpl = async (url: string) => {
			expect(new URL(url).hostname).toBe("cloudflare-dns.com");
			return new Response(
				JSON.stringify({ Status: 3, TC: false, RD: true, RA: true }),
				{ status: 200, headers: { "content-type": "application/dns-json" } },
			);
		};
		const r = await fetchTlsRptPosture("acme.com", { fetchImpl });
		expect(r).toEqual(emptyTlsRptPosture()); // configured: null
	});

	it("treats a TXT label with non-TLSRPT entries as 'no record'", async () => {
		const fetchImpl = async () =>
			dohTxtResponse(['"some other txt"', '"google-site-verification=abc"']);
		const r = await fetchTlsRptPosture("acme.com", { fetchImpl });
		expect(r).toEqual({ configured: false, endpoints: [] });
	});

	it("returns the empty sentinel when DoH returns non-200", async () => {
		const fetchImpl = async () => new Response("nope", { status: 500 });
		const r = await fetchTlsRptPosture("acme.com", { fetchImpl });
		expect(r).toEqual(emptyTlsRptPosture());
	});

	it("returns the empty sentinel when fetch rejects (timeout / network)", async () => {
		// `AbortSignal.timeout(1500)` hits this branch when the upstream is
		// slow — the caller doesn't differentiate "timed out" from "refused
		// connection"; both surface as the unavailable sentinel.
		const fetchImpl = async () => {
			throw new Error("network");
		};
		const r = await fetchTlsRptPosture("acme.com", { fetchImpl });
		expect(r).toEqual(emptyTlsRptPosture());
	});

	it("returns the empty sentinel when DoH returns malformed JSON", async () => {
		const fetchImpl = async () => new Response("<html>", { status: 200 });
		const r = await fetchTlsRptPosture("acme.com", { fetchImpl });
		expect(r).toEqual(emptyTlsRptPosture());
	});

	it("queries the _smtp._tls.<domain> label", async () => {
		let captured = "";
		const fetchImpl = async (url: string) => {
			captured = url;
			return dohTxtResponse(['"v=TLSRPTv1; rua=mailto:tlsrpt@example.com"']);
		};
		await fetchTlsRptPosture("acme.com", { fetchImpl });
		const u = new URL(captured);
		expect(u.hostname).toBe("cloudflare-dns.com");
		expect(u.pathname).toBe("/dns-query");
		expect(u.searchParams.get("name")).toBe("_smtp._tls.acme.com");
		expect(u.searchParams.get("type")).toBe("TXT");
	});

	it("reads from KV cache when a parsed posture is stored", async () => {
		const kv = fakeKv({
			"tlsrpt-txt:v1:acme.com": {
				configured: true,
				endpoints: ["mailto:tlsrpt@example.com"],
			},
		});
		let calls = 0;
		const fetchImpl = async () => {
			calls += 1;
			return dohTxtResponse(['"v=TLSRPTv1; rua=mailto:other@example.com"']);
		};
		const r = await fetchTlsRptPosture("acme.com", { fetchImpl, kv });
		expect(calls).toBe(0);
		expect(r).toEqual({
			configured: true,
			endpoints: ["mailto:tlsrpt@example.com"],
		});
	});

	it("writes the durable-negative posture (configured=false) to KV", async () => {
		const kv = fakeKv();
		const fetchImpl = async () =>
			new Response(JSON.stringify({ Status: 0, Answer: [] }), { status: 200 });
		await fetchTlsRptPosture("acme.com", { fetchImpl, kv });
		await new Promise((r) => setTimeout(r, 0));
		const cached = kv.store.get("tlsrpt-txt:v1:acme.com");
		expect(cached).toBeDefined();
		expect(JSON.parse(cached!)).toEqual({
			configured: false,
			endpoints: [],
		});
	});

	it("does NOT cache the unavailable sentinel (transient errors mustn't poison the cache)", async () => {
		const kv = fakeKv();
		const fetchImpl = async () => {
			throw new Error("network");
		};
		const r = await fetchTlsRptPosture("acme.com", { fetchImpl, kv });
		await new Promise((r) => setTimeout(r, 0));
		expect(r).toEqual(emptyTlsRptPosture());
		// A `configured: null` result is transient — caching it for an hour
		// would mean a one-off DoH blip locks the dashboard into "unavailable"
		// for every subsequent load. Verify the cache is empty after the call.
		expect(kv.store.has("tlsrpt-txt:v1:acme.com")).toBe(false);
	});

	it("writes the resolved posture to KV when configured=true", async () => {
		const kv = fakeKv();
		const fetchImpl = async () =>
			dohTxtResponse(['"v=TLSRPTv1; rua=mailto:tlsrpt@example.com"']);
		await fetchTlsRptPosture("acme.com", { fetchImpl, kv });
		await new Promise((r) => setTimeout(r, 0));
		const cached = kv.store.get("tlsrpt-txt:v1:acme.com");
		expect(cached).toBeDefined();
		expect(JSON.parse(cached!)).toEqual({
			configured: true,
			endpoints: ["mailto:tlsrpt@example.com"],
		});
	});

	it("coerces a malformed cached value back to the empty sentinel", async () => {
		// A cache poisoning would be cheap to recover from — the posture is
		// best-effort and re-fetched on KV miss — but coerce shape defensively.
		const kv = fakeKv({
			"tlsrpt-txt:v1:acme.com": { configured: "not-a-bool", endpoints: 42 },
		});
		let calls = 0;
		const fetchImpl = async () => {
			calls += 1;
			return dohTxtResponse(['"v=TLSRPTv1; rua=mailto:tlsrpt@example.com"']);
		};
		const r = await fetchTlsRptPosture("acme.com", { fetchImpl, kv });
		// Coerced — `configured: null`, `endpoints: null` because the cached
		// shape was wrong. We do NOT re-fetch in this branch (the cache is
		// authoritative for "this domain has been resolved recently").
		expect(calls).toBe(0);
		expect(r).toEqual({ configured: null, endpoints: null });
	});
});
