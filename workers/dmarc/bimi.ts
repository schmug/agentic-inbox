// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * BIMI (Brand Indicators for Message Identification) posture lookup.
 *
 * Resolves `default._bimi.<domain>` TXT via DNS-over-HTTPS and surfaces
 * whether the domain publishes a BIMI record and whether a Verified Mark
 * Certificate (`a=`) is present. Posture-only — we do NOT fetch the SVG
 * logo or the VMC certificate.
 *
 * Mirrors the DoH + KV + 1500ms-cap pattern from `workers/dmarc/txt.ts`
 * verbatim: same resolver host, same AbortSignal.timeout cap, same
 * fire-and-forget KV write, same empty-sentinel on any failure path.
 *
 * SECURITY_SPEC.md Rule 5: a DoH timeout (or any other failure) returns the
 * not-configured sentinel `{ configured: false }` and never throws — same
 * invariant as the apex-DMARC lookup. Not editing SECURITY_SPEC.md from this
 * PR; the behavioral note lives here.
 *
 * Issue: #245 (part of #156).
 */

/**
 * BIMI posture returned by `fetchBimiPosture`.
 *
 * `{ configured: false }` — lookup succeeded but no `v=BIMI1` record was
 * found at `default._bimi.<domain>` (NXDOMAIN, NOERROR-no-data, TXT with a
 * different version tag, DoH timeout). This is the "not configured" state.
 *
 * `{ configured: true, hasVmc: boolean }` — a valid `v=BIMI1` record was
 * found. `hasVmc` is `true` when the `a=` tag is present and non-empty (the
 * operator has published a VMC URL); `false` when `a=` is absent or empty.
 */
export type BimiPosture =
	| { configured: false }
	| { configured: true; hasVmc: boolean };

/** Sentinel returned when no BIMI record exists or any failure occurred. */
export function emptyBimiPosture(): BimiPosture {
	return { configured: false };
}

const KV_PREFIX = "dmarc-bimi:v1:";
/** 1h TTL — matches the apex-DMARC KV TTL in `workers/dmarc/txt.ts`. */
const KV_TTL_S = 60 * 60;
/** DoH resolver host. Hostname-based mock matching is required by repo CLAUDE.md. */
const DOH_HOST = "cloudflare-dns.com";
const DOH_URL = `https://${DOH_HOST}/dns-query`;
/** Hard-cap the upstream — slow lookup must not block dashboard rendering.
 * Matches the 1500ms cap in `workers/dmarc/txt.ts`. */
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
 * Parse a `default._bimi.<domain>` TXT-record string into a `BimiPosture`.
 * Only records starting with `v=BIMI1` are considered; other TXT entries at
 * `default._bimi` are skipped. Tags are `;`-separated `name=value` pairs;
 * we look for `a=` (VMC / authority URL).
 *
 * Returns `null` when the record is not a valid `v=BIMI1` record.
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
		// First-wins — mirrors the DMARC parser convention.
		if (!tags.has(name)) tags.set(name, value);
	}
	if (tags.get("v") !== "BIMI1") return null;
	const aRaw = tags.get("a");
	const hasVmc = typeof aRaw === "string" && aRaw.length > 0;
	return { configured: true, hasVmc };
}

/**
 * Pick the BIMI record from a list of TXT strings at `default._bimi.<domain>`.
 * Returns null when no `v=BIMI1` record is found.
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
 * DoH returns. Mirrors `normalizeDohTxtData` from `workers/dmarc/txt.ts`.
 */
function normalizeDohTxtData(data: string): string {
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
 * The lookup is hard-capped at `DOH_TIMEOUT_MS` (1500ms) and degrades to
 * the not-configured sentinel on any failure (timeout, non-200, malformed
 * JSON, NXDOMAIN). Per SECURITY_SPEC.md Rule 5, no error is ever thrown —
 * the caller should treat this as best-effort.
 *
 * Negative results are cached — a domain with no `default._bimi` record is
 * the common case, and we don't want to re-resolve on every dashboard hit.
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
			const cached = (await kv.get(cacheKey, "json")) as BimiPosture | null;
			if (cached && typeof cached === "object" && "configured" in cached) {
				// Coerce to ensure shape matches the union type.
				if (cached.configured === false) return { configured: false };
				if (cached.configured === true) {
					const hasVmc = typeof (cached as { configured: true; hasVmc?: unknown }).hasVmc === "boolean"
						? (cached as { configured: true; hasVmc: boolean }).hasVmc
						: false;
					return { configured: true, hasVmc };
				}
			}
		} catch {
			// KV read failure is non-fatal; fall through to DoH.
		}
	}

	const posture = await resolveBimiTxt(domain, fetchImpl);

	if (kv) {
		// Fire-and-forget — matches the txt.ts pattern.
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
		// Timeout or network error → not-configured sentinel (Rule 5).
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
	if (!record) return emptyBimiPosture();
	const parsed = parseBimiTxt(record);
	return parsed ?? emptyBimiPosture();
}
