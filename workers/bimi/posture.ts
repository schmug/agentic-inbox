// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * BIMI (Brand Indicators for Message Identification) posture lookup.
 *
 * Resolves `default._bimi.<domain>` TXT and surfaces whether the domain
 * publishes a BIMI record, whether a logo URL (`l=`) is present, and
 * whether a Verified Mark Certificate URL (`a=`) is present. Posture-only
 * — we deliberately do NOT fetch the SVG logo or the VMC certificate; the
 * dashboard surfaces only "configured / configured-with-vmc / not configured /
 * unavailable".
 *
 * Mirrors the DoH + KV + 1500ms-cap pattern from `workers/dmarc/txt.ts`.
 *
 * Issue: #166 (carve-out from #156, item 4).
 */

/** Parsed `{configured, hasLogo, hasVmc}` from `default._bimi.<domain>`.
 * `null` fields signal "unavailable" — same affordance as the DMARC posture
 * sentinel, so a timeout / DNS error / NXDOMAIN all surface the same UI. */
export interface BimiPosture {
	configured: boolean | null;
	hasLogo: boolean | null;
	hasVmc: boolean | null;
}

/** Sentinel for "unavailable / lookup failed / no record". */
export function emptyBimiPosture(): BimiPosture {
	return { configured: null, hasLogo: null, hasVmc: null };
}

const KV_PREFIX = "bimi:v1:";
/** Short TTL — BIMI records change infrequently but there's no cache buster
 * (unlike MTA-STS's policy `id`), so we re-resolve every hour. Negative cache
 * uses the same TTL since BIMI publishing is uncommon and a longer negative
 * cache would slow first-publish discovery. */
const KV_TTL_S = 60 * 60;
/** DoH resolver host. Hostname-based mock matching is required by repo CLAUDE.md. */
const DOH_HOST = "cloudflare-dns.com";
const DOH_URL = `https://${DOH_HOST}/dns-query`;
/** Hard cap matches `workers/dmarc/txt.ts`. */
const DOH_TIMEOUT_MS = 1500;

/** Minimal `KVNamespace` view we depend on; lets tests pass a fake. */
export interface BimiKv {
	get(key: string, type: "json"): Promise<unknown>;
	put(
		key: string,
		value: string,
		options?: { expirationTtl?: number },
	): Promise<void>;
}

/** Minimal `fetch` view we depend on; lets tests inject a stub. */
export type BimiFetch = (input: string, init?: RequestInit) => Promise<Response>;

/**
 * Parse a `default._bimi.<domain>` TXT-record string into `{configured,
 * hasLogo, hasVmc}`. Only records starting with `v=BIMI1` are considered.
 * Tags are `;`-separated `name=value` pairs; we look for `l=` (logo URL)
 * and `a=` (VMC URL).
 *
 * BIMI Group's published spec calls these tags `l` (location) and `a`
 * (authority). An empty value (`l=`) is treated as "not present" — the
 * spec allows the operator to publish an "indicator-not-supported" record
 * with empty `l`, which is intent to NOT show a brand indicator.
 */
export function parseBimiTxt(record: string): BimiPosture | null {
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
		// First-wins, mirroring the DMARC and MTA-STS parsers.
		if (!tags.has(name)) tags.set(name, value);
	}
	if (tags.get("v") !== "BIMI1") return null;
	const lRaw = tags.get("l");
	const aRaw = tags.get("a");
	const hasLogo = typeof lRaw === "string" && lRaw.length > 0;
	const hasVmc = typeof aRaw === "string" && aRaw.length > 0;
	return { configured: true, hasLogo, hasVmc };
}

/**
 * Pick the BIMI policy record from a list of TXT strings published at
 * `default._bimi.<domain>`. Returns null when no `v=BIMI1` record exists.
 */
export function selectBimiRecord(records: readonly string[]): string | null {
	for (const r of records) {
		if (typeof r !== "string") continue;
		const t = r.trim();
		if (/^v\s*=\s*BIMI1\b/i.test(t)) return t;
	}
	return null;
}

/**
 * Strip surrounding quotes and concatenate multi-string TXT-record fragments
 * DoH returns. Same logic as `workers/dmarc/txt.ts:normalizeDohTxtData` —
 * duplicated to keep the BIMI module decoupled from the DMARC API surface.
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
 * Fetch and parse the BIMI posture for `<domain>`, with KV caching.
 *
 * Cache holds positive and negative results under the same key with the same
 * short TTL — there's no published cache buster like MTA-STS's `id`, so we
 * rely on the TTL alone. A failed upstream (timeout, non-200, malformed JSON,
 * no `v=BIMI1` record) degrades to the all-null sentinel; the caller should
 * treat this as best-effort and not fail the surrounding request.
 */
export async function fetchBimiPosture(
	domain: string,
	options: {
		kv?: BimiKv | null;
		fetchImpl?: BimiFetch;
	} = {},
): Promise<BimiPosture> {
	if (!domain || typeof domain !== "string") return emptyBimiPosture();
	const fetchImpl = options.fetchImpl ?? (globalThis.fetch as BimiFetch);
	const kv = options.kv ?? null;
	const cacheKey = `${KV_PREFIX}${domain}`;

	if (kv) {
		try {
			const cached = await kv.get(cacheKey, "json");
			if (cached && typeof cached === "object") {
				return coerceBimiPosture(cached);
			}
		} catch {
			// KV read failure is non-fatal; fall through to a fresh DoH lookup.
		}
	}

	const posture = await resolveBimiTxt(domain, fetchImpl);

	if (kv) {
		void kv
			.put(cacheKey, JSON.stringify(posture), { expirationTtl: KV_TTL_S })
			.catch(() => {});
	}

	return posture;
}

async function resolveBimiTxt(
	domain: string,
	fetchImpl: BimiFetch,
): Promise<BimiPosture> {
	const name = `default._bimi.${domain}`;
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
		return emptyBimiPosture();
	}
	if (!res.ok) return emptyBimiPosture();
	let body: unknown;
	try {
		body = await res.json();
	} catch {
		return emptyBimiPosture();
	}
	const answer = (body as { Answer?: Array<{ type?: number; data?: unknown }> })
		.Answer;
	if (!Array.isArray(answer)) return emptyBimiPosture();
	const txts: string[] = [];
	for (const a of answer) {
		// TXT records are type=16 in DoH JSON.
		if (a.type !== 16) continue;
		if (typeof a.data !== "string") continue;
		txts.push(normalizeDohTxtData(a.data));
	}
	const record = selectBimiRecord(txts);
	if (!record) {
		// Distinguish "no record" (configured=false) from "lookup unavailable"
		// (configured=null). The all-null sentinel is for the latter.
		return { configured: false, hasLogo: false, hasVmc: false };
	}
	const parsed = parseBimiTxt(record);
	return parsed ?? emptyBimiPosture();
}

function coerceBimiPosture(value: unknown): BimiPosture {
	if (!value || typeof value !== "object") return emptyBimiPosture();
	const v = value as { configured?: unknown; hasLogo?: unknown; hasVmc?: unknown };
	return {
		configured: typeof v.configured === "boolean" ? v.configured : null,
		hasLogo: typeof v.hasLogo === "boolean" ? v.hasLogo : null,
		hasVmc: typeof v.hasVmc === "boolean" ? v.hasVmc : null,
	};
}
