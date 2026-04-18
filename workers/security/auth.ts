// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * SPF/DKIM/DMARC verdict extraction from `Authentication-Results` headers.
 *
 * Cloudflare Email Routing preserves upstream auth headers and adds its own.
 * This parser handles the IANA-standard `Authentication-Results` format plus
 * the common Gmail and Microsoft variants.
 *
 * THREAT MODEL: An attacker who controls their own mail server can inject
 * an `Authentication-Results` header claiming pass results for their own
 * forged From address. Per RFC 8601 §5, receivers MUST validate the
 * authserv-id against a trusted list before acting on the reported
 * results. When `trusted_authserv_ids` is configured on the mailbox, only
 * headers whose authserv-id appears in that list contribute to the verdict;
 * all others are ignored.
 *
 * When no trusted list is configured we fall back to first-header-wins,
 * which matches the behaviour pre-hardening. That's still exploitable if
 * a forged header precedes the authentic one in the array, so operators
 * are strongly encouraged to set the trusted list.
 */

export type AuthResult =
	| "pass"
	| "fail"
	| "neutral"
	| "none"
	| "softfail"
	| "temperror"
	| "permerror";

export interface AuthVerdict {
	spf: AuthResult;
	dkim: AuthResult;
	dmarc: AuthResult;
	/** The `authserv-id` that produced the verdict, if captured. */
	authservId?: string;
	/**
	 * True when at least one header with a trusted authserv-id was found.
	 * When `trusted_authserv_ids` is configured and no header matched, this
	 * stays false and the verdict remains all-none — the aggregator treats
	 * that as a strong suspicion signal.
	 */
	trusted?: boolean;
}

export function emptyVerdict(): AuthVerdict {
	return { spf: "none", dkim: "none", dmarc: "none" };
}

/**
 * Extract `Authentication-Results` header value(s) from the raw-headers JSON
 * that PostalMime produces. Each header entry is `{ key, value }`; the key
 * casing varies across senders so we compare lowercased.
 */
function findAuthHeaders(rawHeaders: unknown): string[] {
	if (!Array.isArray(rawHeaders)) return [];
	const out: string[] = [];
	for (const h of rawHeaders) {
		if (!h || typeof h !== "object") continue;
		const rec = h as { key?: unknown; name?: unknown; value?: unknown };
		const key = rec.key ?? rec.name;
		const value = rec.value;
		if (typeof key !== "string" || typeof value !== "string") continue;
		if (key.toLowerCase() === "authentication-results") out.push(value);
	}
	return out;
}

const RESULT_RE = /(spf|dkim|dmarc)\s*=\s*(pass|fail|neutral|none|softfail|temperror|permerror)/gi;

function extractAuthservId(raw: string): string | undefined {
	const firstToken = raw.split(";")[0]?.trim();
	if (!firstToken || firstToken.includes("=")) return undefined;
	return firstToken.toLowerCase();
}

export interface ParseAuthOptions {
	/**
	 * Lowercased list of trusted authserv-id values. When non-empty, only
	 * `Authentication-Results` headers whose authserv-id is on this list
	 * contribute to the verdict. Empty/unset means "trust any".
	 */
	trustedAuthservIds?: readonly string[];
}

/** Suffix-aware authserv-id match. `google.com` matches `mx.google.com`. */
function matchesTrusted(authservId: string, trusted: readonly string[]): boolean {
	for (const t of trusted) {
		if (authservId === t) return true;
		if (authservId.endsWith("." + t)) return true;
	}
	return false;
}

export function parseAuthResults(rawHeaders: unknown, options: ParseAuthOptions = {}): AuthVerdict {
	const verdict = emptyVerdict();
	const headerValues = findAuthHeaders(rawHeaders);
	if (headerValues.length === 0) return verdict;

	const trusted = options.trustedAuthservIds ?? [];
	const gating = trusted.length > 0;

	// Track which methods are already set so a legitimate `dkim=none` result
	// doesn't leave the state indistinguishable from "not set" — which would
	// otherwise let a subsequent (possibly forged) header overwrite it.
	const set = { spf: false, dkim: false, dmarc: false };

	for (const raw of headerValues) {
		const authservId = extractAuthservId(raw);
		if (gating) {
			if (!authservId) continue;
			if (!matchesTrusted(authservId, trusted)) continue;
		}
		if (!verdict.authservId && authservId) verdict.authservId = authservId;
		if (!verdict.trusted) verdict.trusted = true;

		for (const match of raw.matchAll(RESULT_RE)) {
			const method = match[1].toLowerCase() as "spf" | "dkim" | "dmarc";
			const result = match[2].toLowerCase() as AuthResult;
			if (!set[method]) {
				verdict[method] = result;
				set[method] = true;
			}
		}
	}
	return verdict;
}

/** Auth-signal score contribution (positive = suspicious). */
export function scoreAuth(verdict: AuthVerdict): { score: number; reasons: string[] } {
	const reasons: string[] = [];
	let score = 0;
	if (verdict.dmarc === "fail") { score += 20; reasons.push("DMARC failed"); }
	if (verdict.spf === "fail" || verdict.spf === "softfail") { score += 10; reasons.push("SPF failed"); }
	if (verdict.dkim === "fail") { score += 10; reasons.push("DKIM failed"); }
	if (score > 30) score = 30;
	if (verdict.dmarc === "pass") score -= 10;
	return { score, reasons };
}
