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

/**
 * Pull all `Received:` header values out of the PostalMime raw-headers array.
 * Header order is preserved — most-recent hop first, originating hop last.
 */
function findReceivedHeaders(rawHeaders: unknown): string[] {
	if (!Array.isArray(rawHeaders)) return [];
	const out: string[] = [];
	for (const h of rawHeaders) {
		if (!h || typeof h !== "object") continue;
		const rec = h as { key?: unknown; name?: unknown; value?: unknown };
		const key = rec.key ?? rec.name;
		const value = rec.value;
		if (typeof key !== "string" || typeof value !== "string") continue;
		if (key.toLowerCase() === "received") out.push(value);
	}
	return out;
}

// `Received: from <host> ([<ip>])` is the canonical RFC 5321 form, but the
// shape varies wildly across senders — the IP may be inside `[brackets]`,
// `(parens)`, or bare; the hostname may be missing/quoted/duplicated. Rather
// than try to parse every variant precisely, we walk all IP-shaped tokens in
// the header value and let the public/private filter pick the right one.
//
// The regex is run with `matchAll` against each header value; the helper
// returns the first match whose IP isn't private/loopback. IPv4 is matched
// first (cheaper and far more common); IPv6 (any token containing two
// or more colons) is matched separately.
const RECEIVED_IPV4_RE = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g;
const RECEIVED_IPV6_RE = /(?:IPv6:)?([0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7})/gi;

/**
 * Return true for IPs we should skip when walking `Received:` headers in
 * search of the originating external hop:
 *
 *   - RFC1918 private space (10/8, 172.16/12, 192.168/16)
 *   - Loopback (127/8, ::1)
 *   - Link-local (169.254/16, fe80::/10)
 *   - Unique-local IPv6 (fc00::/7)
 *   - Cloudflare Email Routing's own internal hops (no public range to
 *     enumerate, so we lean on the private-range check above plus the
 *     fact that Email Routing's outermost `Received:` line records the
 *     real client IP).
 */
function isPrivateOrLoopbackIp(ip: string): boolean {
	const lower = ip.toLowerCase().replace(/^ipv6:/, "");
	// IPv4
	if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(lower)) {
		const parts = lower.split(".").map((p) => parseInt(p, 10));
		if (parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return true;
		const [a, b] = parts;
		if (a === 10) return true;
		if (a === 127) return true;
		if (a === 172 && b >= 16 && b <= 31) return true;
		if (a === 192 && b === 168) return true;
		if (a === 169 && b === 254) return true;
		if (a === 0) return true;
		return false;
	}
	// IPv6
	if (lower === "::1") return true;
	if (lower.startsWith("fe8") || lower.startsWith("fe9") || lower.startsWith("fea") || lower.startsWith("feb")) return true;
	if (lower.startsWith("fc") || lower.startsWith("fd")) return true;
	// Treat anything that's not a recognisable IP as "skip" rather than "use".
	if (!/[0-9]/.test(lower)) return true;
	return false;
}

/**
 * Extract the originating external IP from `Received:` headers.
 *
 * PostalMime preserves header order; `Received:` lines run most-recent hop
 * first → originating hop last. We walk in array order and return the first
 * `from <host> [ip]` whose IP is public — that's the outermost externally-
 * controlled hop. Returns `undefined` when no usable IP is found (malformed
 * trace, internal-only chain, or no `Received:` headers at all).
 *
 * Threat-model note: `Received:` headers from outside our infra are
 * untrusted and forge-able. The CTI lookup that consumes this IP is treated
 * as a *signal*, not as ground truth — a forged "from 8.8.8.8" doesn't get
 * us a free pass, it just shifts the prior up or down within a bounded
 * range. The aggressive private-range filter below is the main defence: an
 * attacker can't mask as a private hop to suppress the lookup.
 */
export function extractReceivedFromIp(rawHeaders: unknown): string | undefined {
	const headers = findReceivedHeaders(rawHeaders);
	for (const raw of headers) {
		// Try IPv4 first — cheap, and the overwhelming common case for a
		// `Received: from` clause.
		for (const m of raw.matchAll(RECEIVED_IPV4_RE)) {
			const ip = m[1];
			if (!isPrivateOrLoopbackIp(ip)) return ip;
		}
		for (const m of raw.matchAll(RECEIVED_IPV6_RE)) {
			const ip = m[1];
			if (!ip) continue;
			if (!isPrivateOrLoopbackIp(ip)) return ip;
		}
	}
	return undefined;
}
