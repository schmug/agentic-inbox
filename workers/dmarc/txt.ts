// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Apex-domain DMARC TXT-record fetch + parse.
 *
 * The Workers runtime has no `dns` module, so policy lookup goes over
 * DNS-over-HTTPS (Cloudflare's `cloudflare-dns.com` JSON resolver). The result
 * is cached in KV under `dmarc-txt:v1:<domain>` with a short TTL — apex
 * DMARC policies don't churn, and negative caching matters so a domain with
 * no `_dmarc` record doesn't re-hammer DoH on every dashboard request.
 *
 * Issue: #138 (real apex-domain DMARC posture ingestion).
 */

/**
 * Parsed `{p, sp, pct, ruaConfigured}` extracted from a `_dmarc.<domain>`
 * TXT record. Fields are independent: a policy with `p=reject` but no `sp`
 * tag is reported as `{p: "reject", sp: null, ...}`. `pct` defaults to 100
 * per RFC 7489 §6.3 if the tag is absent (the published spec semantic, not
 * a guess), but only when a `v=DMARC1` record was found at all — otherwise
 * every field is null and the caller should surface "unavailable".
 */
export interface DmarcTxtPosture {
	p: string | null;
	sp: string | null;
	pct: number | null;
	ruaConfigured: boolean | null;
}

/**
 * Sentinel returned when no DMARC record exists at the apex. All four fields
 * null lets the dashboard render the same "unavailable" affordance as a
 * lookup failure — the operator's takeaway is the same: "no policy on file".
 */
export function emptyDmarcTxtPosture(): DmarcTxtPosture {
	return { p: null, sp: null, pct: null, ruaConfigured: null };
}

const TXT_KV_PREFIX = "dmarc-txt:v1:";
/** 1h TTL: apex DMARC policies don't change often. */
const TXT_KV_TTL_S = 60 * 60;
/** DoH resolver host. Hostname-based mock matching is required by repo CLAUDE.md. */
const DOH_HOST = "cloudflare-dns.com";
const DOH_URL = `https://${DOH_HOST}/dns-query`;
/** Hard-cap the upstream — slow lookup must not block dashboard rendering. */
const DOH_TIMEOUT_MS = 1500;

/** Minimal `KVNamespace` view we depend on; lets tests pass a fake. */
export interface DmarcTxtKv {
	get(key: string, type: "json"): Promise<unknown>;
	put(
		key: string,
		value: string,
		options?: { expirationTtl?: number },
	): Promise<void>;
}

/** Minimal `fetch` view we depend on; lets tests inject a stub. */
export type DmarcTxtFetch = (input: string, init?: RequestInit) => Promise<Response>;

/**
 * Parse a `_dmarc.<domain>` TXT-record string into a posture. Only records
 * starting with `v=DMARC1` are considered (other TXT entries at `_dmarc`,
 * e.g. orphaned legacy values, are skipped by the caller).
 *
 * Tags are `;`-separated `name=value` pairs per RFC 7489 §6.3. We tolerate:
 *   - Surrounding whitespace.
 *   - Missing optional tags (`sp`, `pct`, `rua`).
 *   - Malformed `pct` values (return null rather than NaN).
 *   - Empty `rua=` (treated as not configured — the tag exists but no URI
 *     is published, so reports go nowhere).
 */
export function parseDmarcTxt(record: string): DmarcTxtPosture {
	const empty = emptyDmarcTxtPosture();
	if (typeof record !== "string") return empty;
	const trimmed = record.trim();
	if (!trimmed) return empty;
	// Tag names are case-insensitive in DMARC; values are not.
	const tags = new Map<string, string>();
	for (const part of trimmed.split(";")) {
		const eq = part.indexOf("=");
		if (eq < 0) continue;
		const name = part.slice(0, eq).trim().toLowerCase();
		const value = part.slice(eq + 1).trim();
		if (!name) continue;
		// First occurrence wins — RFC 7489 doesn't define dup-tag semantics
		// and most parsers treat a record with duplicates as malformed; we
		// chose first-wins so a record like `v=DMARC1;p=reject;p=none` still
		// reports the stricter policy rather than silently downgrading.
		if (!tags.has(name)) tags.set(name, value);
	}
	if (tags.get("v") !== "DMARC1") return empty;

	const p = tags.get("p") ?? null;
	const sp = tags.get("sp") ?? null;

	let pct: number | null = null;
	const pctRaw = tags.get("pct");
	if (pctRaw === undefined) {
		// Per RFC 7489 §6.3, absent `pct` defaults to 100. Only apply that
		// default when we actually parsed a v=DMARC1 record (i.e. `p` is
		// likely set); a record with `v=DMARC1` and no other tags is still
		// malformed in practice but defaulting pct here matches every other
		// implementation's behavior.
		pct = 100;
	} else {
		const n = Number.parseInt(pctRaw, 10);
		if (Number.isFinite(n) && n >= 0 && n <= 100) pct = n;
	}

	// `rua=mailto:dmarc@example.com[,mailto:...]`. Empty / missing → not
	// configured. We don't validate the URI list — it's enough for the
	// dashboard to know "the operator is collecting reports somewhere".
	const ruaRaw = tags.get("rua");
	const ruaConfigured = typeof ruaRaw === "string" && ruaRaw.length > 0;

	return { p, sp, pct, ruaConfigured };
}

/**
 * Pick the DMARC policy record from a list of TXT strings published at
 * `_dmarc.<domain>`. Multiple TXT entries at that label are common (e.g. an
 * old DMARC value left next to a new one); the spec says only the
 * `v=DMARC1`-prefixed record is authoritative. Returns null when none match.
 */
export function selectDmarcRecord(records: readonly string[]): string | null {
	for (const r of records) {
		if (typeof r !== "string") continue;
		const t = r.trim();
		if (/^v\s*=\s*DMARC1\b/i.test(t)) return t;
	}
	return null;
}

/**
 * Strip the surrounding quotes and concatenate multi-string TXT-record
 * fragments DoH returns. Cloudflare's resolver hands TXT data back as
 * `"v=DMARC1; p=reject" "rua=mailto:..."` for records that exceed 255 bytes;
 * we want one logical string with the quote-pair boundary erased.
 */
export function normalizeDohTxtData(data: string): string {
	if (typeof data !== "string") return "";
	// Match all `"..."` fragments and concatenate their contents. If no
	// quoted fragments are present (some resolvers return raw text), fall
	// back to the original string with leading/trailing quotes stripped.
	const matches = [...data.matchAll(/"((?:[^"\\]|\\.)*)"/g)];
	if (matches.length === 0) {
		return data.replace(/^"|"$/g, "");
	}
	return matches.map((m) => m[1]).join("");
}

/**
 * Fetch and parse the DMARC TXT record for `<domain>`, with KV caching.
 *
 * The lookup is hard-capped at `DOH_TIMEOUT_MS` and degrades to an all-null
 * posture on any failure (timeout, non-200, malformed JSON, no `v=DMARC1`
 * record found). The caller should treat this as best-effort and not fail
 * the surrounding request when this returns the sentinel.
 *
 * Negative results are cached too — a domain with no `_dmarc` record is
 * the common case for unmanaged inboxes, and we don't want to re-resolve
 * on every dashboard hit.
 */
export async function fetchDmarcTxtPosture(
	domain: string,
	options: {
		kv?: DmarcTxtKv | null;
		fetchImpl?: DmarcTxtFetch;
		now?: number;
	} = {},
): Promise<DmarcTxtPosture> {
	const fetchImpl = options.fetchImpl ?? (globalThis.fetch as DmarcTxtFetch);
	const kv = options.kv ?? null;
	const cacheKey = `${TXT_KV_PREFIX}${domain}`;

	if (kv) {
		try {
			const cached = (await kv.get(cacheKey, "json")) as
				| DmarcTxtPosture
				| null;
			if (cached && typeof cached === "object") {
				// Defensive: a cache poisoning would be cheap to recover from
				// because the posture is best-effort, but coerce shape anyway.
				return {
					p: typeof cached.p === "string" ? cached.p : null,
					sp: typeof cached.sp === "string" ? cached.sp : null,
					pct: typeof cached.pct === "number" ? cached.pct : null,
					ruaConfigured:
						typeof cached.ruaConfigured === "boolean"
							? cached.ruaConfigured
							: null,
				};
			}
		} catch {
			// KV read failure is non-fatal; just fall through to DoH.
		}
	}

	const posture = await resolveDmarcTxt(domain, fetchImpl);

	if (kv) {
		// Don't `await` the put — caching is opportunistic; a slow KV write
		// shouldn't block the dashboard response. Callers that need the
		// write to complete before the worker terminates should pass the
		// returned promise to `ctx.waitUntil`. We chose to keep this helper
		// pure-by-default and let the route handler own that decision.
		void kv
			.put(cacheKey, JSON.stringify(posture), { expirationTtl: TXT_KV_TTL_S })
			.catch(() => {});
	}

	return posture;
}

async function resolveDmarcTxt(
	domain: string,
	fetchImpl: DmarcTxtFetch,
): Promise<DmarcTxtPosture> {
	if (!domain || typeof domain !== "string") return emptyDmarcTxtPosture();
	const name = `_dmarc.${domain}`;
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
		return emptyDmarcTxtPosture();
	}
	if (!res.ok) return emptyDmarcTxtPosture();
	let body: unknown;
	try {
		body = await res.json();
	} catch {
		return emptyDmarcTxtPosture();
	}
	const answer = (body as { Answer?: Array<{ type?: number; data?: unknown }> })
		.Answer;
	if (!Array.isArray(answer)) return emptyDmarcTxtPosture();
	const txts: string[] = [];
	for (const a of answer) {
		// TXT records are type=16 in DoH JSON.
		if (a.type !== 16) continue;
		if (typeof a.data !== "string") continue;
		txts.push(normalizeDohTxtData(a.data));
	}
	const record = selectDmarcRecord(txts);
	if (!record) return emptyDmarcTxtPosture();
	return parseDmarcTxt(record);
}
