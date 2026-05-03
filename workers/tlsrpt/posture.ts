// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * TLS-RPT (RFC 8460) posture lookup.
 *
 * Resolves `_smtp._tls.<domain>` TXT and surfaces whether the domain
 * publishes a `v=TLSRPTv1` record advertising a TLS-RPT collector. The
 * dashboard renders "TLS reporting configured: yes / no" plus the parsed
 * `rua=` endpoint list when present.
 *
 * Posture-only — we deliberately do NOT POST anything to the published
 * collector and we do NOT ingest inbound TLS-RPT reports here. Inbound
 * ingestion is a separate sub-issue from #156.
 *
 * Mirrors the DoH + KV + 1500ms-cap pattern from `workers/dmarc/txt.ts`.
 *
 * Issue: #168 (carve-out from #156, item 1, posture half).
 */

/** Parsed `{configured, endpoints}` from `_smtp._tls.<domain>`.
 *
 * `configured: null` is the "unavailable / lookup failed" sentinel — same
 * affordance the rest of the posture cards use for transient DoH errors.
 * `configured: false` is the durable "no `v=TLSRPTv1` record published"
 * answer; we cache that under the same TTL as positive results so a
 * domain that hasn't published TLS-RPT doesn't re-hit DoH on every load.
 *
 * `endpoints` is the parsed `rua=` URI list — `mailto:tlsrpt@…` and/or
 * `https://…` collectors. Empty list (`[]`) when the record exists but
 * carried no `rua=` value; null when the lookup is unavailable. */
export interface TlsRptPosture {
	configured: boolean | null;
	endpoints: readonly string[] | null;
}

/** Sentinel for "unavailable / lookup failed". `configured: false` (a
 * durable "no record" answer) is a separate state and is NOT this sentinel. */
export function emptyTlsRptPosture(): TlsRptPosture {
	return { configured: null, endpoints: null };
}

const KV_PREFIX = "tlsrpt-txt:v1:";
/** Short TTL — TLS-RPT records change infrequently but operators do roll
 * collector endpoints. 1h matches the DMARC / BIMI cadence; negative cache
 * uses the same TTL so first-publish discovery isn't gated on a long miss. */
const KV_TTL_S = 60 * 60;
/** DoH resolver host. Hostname-based mock matching is required by repo CLAUDE.md. */
const DOH_HOST = "cloudflare-dns.com";
const DOH_URL = `https://${DOH_HOST}/dns-query`;
/** Hard cap matches `workers/dmarc/txt.ts`. */
const DOH_TIMEOUT_MS = 1500;

/** Minimal `KVNamespace` view we depend on; lets tests pass a fake. */
export interface TlsRptKv {
	get(key: string, type: "json"): Promise<unknown>;
	put(
		key: string,
		value: string,
		options?: { expirationTtl?: number },
	): Promise<void>;
}

/** Minimal `fetch` view we depend on; lets tests inject a stub. */
export type TlsRptFetch = (input: string, init?: RequestInit) => Promise<Response>;

/**
 * Parse a `_smtp._tls.<domain>` TXT-record string into `{configured,
 * endpoints}`. Only records starting with `v=TLSRPTv1` are considered.
 * Tags are `;`-separated `name=value` pairs per RFC 8460 §3.
 *
 * The `rua=` value is a comma-separated list of generic URIs. RFC 8460 §3
 * defines exactly two schemes today (`mailto:` and `https:`); we surface
 * the parsed URI list to the UI without filtering by scheme — operators
 * occasionally publish vendor-specific schemes and we'd rather show the
 * literal text than silently swallow it. Empty / missing `rua=` yields
 * `endpoints: []` — the record exists but no collector is published.
 *
 * Returns null when the record isn't a `v=TLSRPTv1` record at all, so the
 * caller can distinguish "malformed" from "configured-but-empty".
 */
export function parseTlsRptTxt(record: string): TlsRptPosture | null {
	if (typeof record !== "string") return null;
	const trimmed = record.trim();
	if (!trimmed) return null;
	const tags = new Map<string, string>();
	for (const part of trimmed.split(";")) {
		const eq = part.indexOf("=");
		if (eq < 0) continue;
		const name = part.slice(0, eq).trim().toLowerCase();
		const value = part.slice(eq + 1).trim();
		if (!name) continue;
		// First-wins, mirroring the DMARC and BIMI parsers — `v=TLSRPTv1;
		// rua=mailto:a@x; rua=mailto:b@x` reports the first endpoint rather
		// than silently overwriting it.
		if (!tags.has(name)) tags.set(name, value);
	}
	if (tags.get("v") !== "TLSRPTv1") return null;
	const ruaRaw = tags.get("rua");
	const endpoints = parseRuaList(ruaRaw);
	return { configured: true, endpoints };
}

/** Parse a comma-separated `rua=` URI list. Whitespace around items is
 * trimmed. An undefined / empty input yields `[]` (the record exists but
 * publishes no endpoint — valid per RFC 8460, just degenerate).
 *
 * Exported for tests; the production parser routes through `parseTlsRptTxt`. */
export function parseRuaList(raw: string | undefined): string[] {
	if (typeof raw !== "string") return [];
	const trimmed = raw.trim();
	if (!trimmed) return [];
	return trimmed
		.split(",")
		.map((s) => s.trim())
		.filter((s) => s.length > 0);
}

/**
 * Pick the TLS-RPT policy record from a list of TXT strings published at
 * `_smtp._tls.<domain>`. Returns null when no `v=TLSRPTv1` record exists.
 */
export function selectTlsRptRecord(records: readonly string[]): string | null {
	for (const r of records) {
		if (typeof r !== "string") continue;
		const t = r.trim();
		if (/^v\s*=\s*TLSRPTv1\b/i.test(t)) return t;
	}
	return null;
}

/**
 * Strip surrounding quotes and concatenate multi-string TXT-record fragments
 * DoH returns. Same logic as `workers/dmarc/txt.ts:normalizeDohTxtData` —
 * duplicated to keep the TLS-RPT module decoupled from the DMARC API surface.
 */
export function normalizeDohTxtData(data: string): string {
	if (typeof data !== "string") return "";
	const matches = [...data.matchAll(/"((?:[^"\\]|\\.)*)"/g)];
	if (matches.length === 0) {
		return data.replace(/^"|"$/g, "");
	}
	return matches.map((m) => m[1]).join("");
}

/**
 * Fetch and parse the TLS-RPT posture for `<domain>`, with KV caching.
 *
 * Cache holds positive (`configured: true`) and durable-negative
 * (`configured: false`) results under the same key with the same short TTL.
 * The `configured: null` sentinel is NEVER cached — a transient DoH error
 * shouldn't poison the cache for an hour.
 *
 * A failed upstream (timeout, non-200, malformed JSON) degrades to the
 * empty sentinel; the caller should treat this as best-effort and not fail
 * the surrounding request.
 */
export async function fetchTlsRptPosture(
	domain: string,
	options: {
		kv?: TlsRptKv | null;
		fetchImpl?: TlsRptFetch;
	} = {},
): Promise<TlsRptPosture> {
	if (!domain || typeof domain !== "string") return emptyTlsRptPosture();
	const fetchImpl = options.fetchImpl ?? (globalThis.fetch as TlsRptFetch);
	const kv = options.kv ?? null;
	const cacheKey = `${KV_PREFIX}${domain}`;

	if (kv) {
		try {
			const cached = await kv.get(cacheKey, "json");
			if (cached && typeof cached === "object") {
				return coerceTlsRptPosture(cached);
			}
		} catch {
			// KV read failure is non-fatal; fall through to a fresh DoH lookup.
		}
	}

	const posture = await resolveTlsRptTxt(domain, fetchImpl);

	// Only cache durable answers — `configured: null` is a transient signal
	// (DoH timed out, returned non-200, or the JSON didn't parse). Caching it
	// would mean an hour of unavailability after a single blip.
	if (kv && posture.configured !== null) {
		void kv
			.put(cacheKey, JSON.stringify(posture), { expirationTtl: KV_TTL_S })
			.catch(() => {});
	}

	return posture;
}

async function resolveTlsRptTxt(
	domain: string,
	fetchImpl: TlsRptFetch,
): Promise<TlsRptPosture> {
	const name = `_smtp._tls.${domain}`;
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
		return emptyTlsRptPosture();
	}
	if (!res.ok) return emptyTlsRptPosture();
	let body: unknown;
	try {
		body = await res.json();
	} catch {
		return emptyTlsRptPosture();
	}
	const answer = (body as { Answer?: Array<{ type?: number; data?: unknown }> })
		.Answer;
	// `Answer` absent is NOT the same as `Answer: []` — a missing field means
	// the resolver didn't even return the field shape we expect, which we treat
	// as a transient unavailability rather than a durable "no record".
	if (!Array.isArray(answer)) return emptyTlsRptPosture();
	const txts: string[] = [];
	for (const a of answer) {
		// TXT records are type=16 in DoH JSON.
		if (a.type !== 16) continue;
		if (typeof a.data !== "string") continue;
		txts.push(normalizeDohTxtData(a.data));
	}
	const record = selectTlsRptRecord(txts);
	if (!record) {
		// Distinguish "no TLSRPTv1 record" (durable answer, configured=false)
		// from "lookup unavailable" (configured=null). Empty Answer or non-TLSRPT
		// TXT entries land here.
		return { configured: false, endpoints: [] };
	}
	const parsed = parseTlsRptTxt(record);
	// `parseTlsRptTxt` returns null only when the record doesn't start with
	// `v=TLSRPTv1` — but we already filtered for that in `selectTlsRptRecord`,
	// so this branch is defensive. Treat a parse miss as "configured but
	// malformed", durable-negative for cache purposes.
	return parsed ?? { configured: false, endpoints: [] };
}

function coerceTlsRptPosture(value: unknown): TlsRptPosture {
	if (!value || typeof value !== "object") return emptyTlsRptPosture();
	const v = value as { configured?: unknown; endpoints?: unknown };
	const configured =
		typeof v.configured === "boolean" ? v.configured : null;
	let endpoints: readonly string[] | null = null;
	if (Array.isArray(v.endpoints)) {
		endpoints = v.endpoints.filter(
			(e): e is string => typeof e === "string",
		);
	}
	return { configured, endpoints };
}
