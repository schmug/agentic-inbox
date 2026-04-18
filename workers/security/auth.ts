// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * SPF/DKIM/DMARC verdict extraction from `Authentication-Results` headers.
 *
 * Cloudflare Email Routing preserves upstream auth headers and adds its own.
 * This parser handles the IANA-standard `Authentication-Results` format plus
 * the common Gmail and Microsoft variants.
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

export function parseAuthResults(rawHeaders: unknown): AuthVerdict {
	const verdict = emptyVerdict();
	const headerValues = findAuthHeaders(rawHeaders);
	if (headerValues.length === 0) return verdict;

	for (const raw of headerValues) {
		if (!verdict.authservId) {
			const firstToken = raw.split(";")[0]?.trim();
			if (firstToken && !firstToken.includes("=")) verdict.authservId = firstToken;
		}
		for (const match of raw.matchAll(RESULT_RE)) {
			const method = match[1].toLowerCase() as "spf" | "dkim" | "dmarc";
			const result = match[2].toLowerCase() as AuthResult;
			// First verdict wins if multiple Authentication-Results headers
			// disagree — we trust the innermost (first-listed) authserv-id.
			if (verdict[method] === "none") verdict[method] = result;
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
