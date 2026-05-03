// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * SPF (RFC 7208) published-record posture lookup.
 *
 * Resolves `<domain>` TXT for `v=spf1 ...`, parses mechanism count + `all`
 * qualifier + the `include:` chain, then deep-resolves the include chain to
 * count total DNS lookups against RFC 7208 §4.6.4's 10-lookup limit. A
 * record over the limit fails permerror per the spec.
 *
 * The chain resolver is hard-bounded — `MAX_DEPTH=10`, `MAX_LOOKUPS=12` —
 * so a malicious record can't fan out unbounded DoH calls. The posture
 * surfaces "exceeds 10-lookup limit?" rather than re-implementing the full
 * SPF check semantics; rendering the actual SPF action belongs in the
 * inbound-classification path, not here.
 *
 * Mirrors the DoH + KV + 1500ms-cap pattern from `workers/dmarc/txt.ts`.
 *
 * Issue: #167 (carve-out from #156, item 5a).
 */

/** Parsed SPF posture (raw record + qualifier + lookup totals). */
export interface SpfPosture {
	record: string | null;
	allQualifier: "-" | "~" | "?" | "+" | null;
	mechanismCount: number | null;
	includes: number | null;
	totalLookups: number | null;
	exceedsLimit: boolean | null;
}

/** Sentinel for "lookup unavailable / no record / parse failure". */
export function emptySpfPosture(): SpfPosture {
	return {
		record: null,
		allQualifier: null,
		mechanismCount: null,
		includes: null,
		totalLookups: null,
		exceedsLimit: null,
	};
}

const KV_PREFIX = "spf:v1:";
/** Short TTL — SPF records change infrequently but operators do roll
 * include lists. 1h matches the BIMI cadence. */
const KV_TTL_S = 60 * 60;
/** DoH resolver host. Hostname-based mock matching is required by repo CLAUDE.md. */
const DOH_HOST = "cloudflare-dns.com";
const DOH_URL = `https://${DOH_HOST}/dns-query`;
/** Hard cap per upstream call. */
const DOH_TIMEOUT_MS = 1500;
/** Hard ceiling on chain recursion depth — RFC §4.6.4 caps at 10. */
const MAX_DEPTH = 10;
/** Hard ceiling on total DoH lookups per posture resolution. The spec limit
 * is 10 lookups — we resolve up to 12 so we can correctly say "this record
 * exceeds the limit at lookup 11" without short-circuiting before we know. */
const MAX_LOOKUPS = 12;
/** Cap raw record length to defend against TXT records padded with megabytes
 * of garbage. Real SPF records are well under 1 KiB. */
const RECORD_MAX_BYTES = 1024;

/** Minimal `KVNamespace` view we depend on; lets tests pass a fake. */
export interface SpfKv {
	get(key: string, type: "json"): Promise<unknown>;
	put(
		key: string,
		value: string,
		options?: { expirationTtl?: number },
	): Promise<void>;
}

/** Minimal `fetch` view we depend on; lets tests inject a stub. */
export type SpfFetch = (input: string, init?: RequestInit) => Promise<Response>;

/**
 * Parse an SPF record into mechanism count, includes, redirect=, and the
 * `all` qualifier. We only count lookup-issuing mechanisms (`include`, `a`,
 * `mx`, `ptr`, `exists`, `redirect=`); `ip4` / `ip6` / unknown mechanisms
 * don't count toward §4.6.4's 10-lookup ceiling. Returns null when the
 * record isn't a v=spf1 record at all.
 */
export function parseSpfRecord(record: string): {
	mechanismCount: number;
	includes: string[];
	otherLookupCount: number;
	redirect: string | null;
	allQualifier: "-" | "~" | "?" | "+" | null;
} | null {
	if (typeof record !== "string") return null;
	const trimmed = record.trim();
	if (!/^v\s*=\s*spf1\b/i.test(trimmed)) return null;
	const tokens = trimmed.split(/\s+/).slice(1); // drop the v=spf1 leader
	const includes: string[] = [];
	let otherLookupCount = 0;
	let redirect: string | null = null;
	let allQualifier: "-" | "~" | "?" | "+" | null = null;
	let mechanismCount = 0;
	for (const tok of tokens) {
		if (!tok) continue;
		mechanismCount += 1;
		// Strip the qualifier prefix (`+`, `-`, `~`, `?`) before mechanism match.
		const qualChar = tok[0];
		const hasQualifier =
			qualChar === "+" || qualChar === "-" || qualChar === "~" || qualChar === "?";
		const body = hasQualifier ? tok.slice(1) : tok;
		const lower = body.toLowerCase();
		if (lower === "all") {
			// Default qualifier per §4.6.2 is `+`. We surface what the operator
			// actually typed (or `+` when implicit) so the UI can flag a
			// missing qualifier on `all` as a posture concern.
			allQualifier = hasQualifier
				? (qualChar as "-" | "~" | "?" | "+")
				: "+";
			continue;
		}
		if (lower.startsWith("include:")) {
			const target = body.slice("include:".length);
			if (target) includes.push(target.toLowerCase());
		} else if (lower.startsWith("redirect=")) {
			const target = body.slice("redirect=".length);
			if (target) redirect = target.toLowerCase();
		} else if (
			lower === "a" ||
			lower.startsWith("a:") ||
			lower.startsWith("a/") ||
			lower === "mx" ||
			lower.startsWith("mx:") ||
			lower.startsWith("mx/") ||
			lower === "ptr" ||
			lower.startsWith("ptr:") ||
			lower.startsWith("exists:")
		) {
			otherLookupCount += 1;
		}
	}
	return {
		mechanismCount,
		includes,
		otherLookupCount,
		redirect,
		allQualifier,
	};
}

/** Pick the SPF record from a list of TXT strings. Per RFC 7208 §3.1 only
 * the v=spf1 record is authoritative; other TXT entries are skipped. First
 * v=spf1 wins (the spec says multiple v=spf1 records permerror — first-wins
 * matches what most validators report rather than masking the misconfig). */
export function selectSpfRecord(records: readonly string[]): string | null {
	for (const r of records) {
		if (typeof r !== "string") continue;
		const t = r.trim();
		if (/^v\s*=\s*spf1\b/i.test(t)) return t;
	}
	return null;
}

/** Strip surrounding quotes and concatenate multi-string TXT-record fragments
 * DoH returns. Same logic as `workers/dmarc/txt.ts:normalizeDohTxtData`. */
export function normalizeDohTxtData(data: string): string {
	if (typeof data !== "string") return "";
	const matches = [...data.matchAll(/"((?:[^"\\]|\\.)*)"/g)];
	if (matches.length === 0) {
		return data.replace(/^"|"$/g, "");
	}
	return matches.map((m) => m[1]).join("");
}

/** Fetch and parse the SPF posture for `<domain>`, with KV caching.
 *
 * Resolves the apex SPF record, then deep-resolves the include chain (and
 * any redirect=) to count total DNS lookups. Total lookups > 10 sets
 * `exceedsLimit: true` — the record fails permerror per §4.6.4.
 *
 * Bounded by `MAX_DEPTH` (chain recursion) and `MAX_LOOKUPS` (total DoH
 * calls per resolution) so a malicious record can't fan out unbounded. */
export async function fetchSpfPosture(
	domain: string,
	options: {
		kv?: SpfKv | null;
		fetchImpl?: SpfFetch;
	} = {},
): Promise<SpfPosture> {
	if (!domain || typeof domain !== "string") return emptySpfPosture();
	const fetchImpl = options.fetchImpl ?? (globalThis.fetch as SpfFetch);
	const kv = options.kv ?? null;
	const cacheKey = `${KV_PREFIX}${domain}`;

	if (kv) {
		try {
			const cached = await kv.get(cacheKey, "json");
			if (cached && typeof cached === "object") {
				return coerceSpfPosture(cached);
			}
		} catch {
			// KV read failure is non-fatal; fall through to a fresh DoH lookup.
		}
	}

	const posture = await resolveSpfPosture(domain, fetchImpl);

	if (kv) {
		void kv
			.put(cacheKey, JSON.stringify(posture), { expirationTtl: KV_TTL_S })
			.catch(() => {});
	}

	return posture;
}

async function resolveSpfPosture(
	domain: string,
	fetchImpl: SpfFetch,
): Promise<SpfPosture> {
	const apex = await fetchSpfTxt(domain, fetchImpl);
	if (!apex) return emptySpfPosture();
	const trimmedRecord =
		apex.length > RECORD_MAX_BYTES ? apex.slice(0, RECORD_MAX_BYTES) : apex;
	const parsed = parseSpfRecord(trimmedRecord);
	if (!parsed) return emptySpfPosture();

	// Per §4.6.4: include / a / mx / ptr / exists / redirect= each count as
	// one DNS lookup. The apex TXT fetch itself is the initial query and
	// does NOT count toward the 10-lookup ceiling.
	const counter = {
		total: 0,
		visited: new Set<string>([domain.toLowerCase()]),
	};
	counter.total += parsed.otherLookupCount;
	counter.total += parsed.includes.length;
	if (parsed.redirect) counter.total += 1;

	for (const inc of parsed.includes) {
		await accumulateChain(inc, counter, fetchImpl, 1);
	}
	if (parsed.redirect) {
		await accumulateChain(parsed.redirect, counter, fetchImpl, 1);
	}

	return {
		record: trimmedRecord,
		allQualifier: parsed.allQualifier,
		mechanismCount: parsed.mechanismCount,
		includes: parsed.includes.length,
		totalLookups: counter.total,
		exceedsLimit: counter.total > 10,
	};
}

async function accumulateChain(
	target: string,
	counter: { total: number; visited: Set<string> },
	fetchImpl: SpfFetch,
	depth: number,
): Promise<void> {
	if (depth > MAX_DEPTH) return;
	if (counter.total >= MAX_LOOKUPS) return;
	const key = target.toLowerCase();
	// A self-include or repeated include is a malformed record. Per §4.6.4
	// the limit makes this impossible in practice; defending against it
	// keeps a misconfigured chain from looping us.
	if (counter.visited.has(key)) return;
	counter.visited.add(key);
	const txt = await fetchSpfTxt(target, fetchImpl);
	if (!txt) return;
	const parsed = parseSpfRecord(txt);
	if (!parsed) return;
	counter.total += parsed.otherLookupCount;
	counter.total += parsed.includes.length;
	if (parsed.redirect) counter.total += 1;
	for (const inc of parsed.includes) {
		if (counter.total >= MAX_LOOKUPS) return;
		await accumulateChain(inc, counter, fetchImpl, depth + 1);
	}
	if (parsed.redirect && counter.total < MAX_LOOKUPS) {
		await accumulateChain(parsed.redirect, counter, fetchImpl, depth + 1);
	}
}

async function fetchSpfTxt(
	name: string,
	fetchImpl: SpfFetch,
): Promise<string | null> {
	let res: Response;
	try {
		res = await fetchImpl(
			`${DOH_URL}?name=${encodeURIComponent(name)}&type=TXT`,
			{
				headers: { accept: "application/dns-json" },
				signal: AbortSignal.timeout(DOH_TIMEOUT_MS),
			},
		);
	} catch {
		return null;
	}
	if (!res.ok) return null;
	let body: unknown;
	try {
		body = await res.json();
	} catch {
		return null;
	}
	const answer = (body as { Answer?: Array<{ type?: number; data?: unknown }> })
		.Answer;
	if (!Array.isArray(answer)) return null;
	const txts: string[] = [];
	for (const a of answer) {
		// TXT records are type=16 in DoH JSON.
		if (a.type !== 16) continue;
		if (typeof a.data !== "string") continue;
		txts.push(normalizeDohTxtData(a.data));
	}
	return selectSpfRecord(txts);
}

function coerceSpfPosture(value: unknown): SpfPosture {
	if (!value || typeof value !== "object") return emptySpfPosture();
	const v = value as {
		record?: unknown;
		allQualifier?: unknown;
		mechanismCount?: unknown;
		includes?: unknown;
		totalLookups?: unknown;
		exceedsLimit?: unknown;
	};
	const validQualifier =
		v.allQualifier === "-" ||
		v.allQualifier === "~" ||
		v.allQualifier === "?" ||
		v.allQualifier === "+"
			? v.allQualifier
			: null;
	return {
		record: typeof v.record === "string" ? v.record : null,
		allQualifier: validQualifier,
		mechanismCount:
			typeof v.mechanismCount === "number" ? v.mechanismCount : null,
		includes: typeof v.includes === "number" ? v.includes : null,
		totalLookups: typeof v.totalLookups === "number" ? v.totalLookups : null,
		exceedsLimit: typeof v.exceedsLimit === "boolean" ? v.exceedsLimit : null,
	};
}
