// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Tiny IPv4-only CIDR helpers for IP-vs-feed membership testing.
 *
 * Why hand-rolled: `ipaddr.js`/`netmask` are not in deps and we don't need
 * IPv6 — Spamhaus DROP/EDROP and the deep-scan A-record lookups are IPv4
 * only. Keeping this in workers code avoids a runtime dependency for a few
 * dozen lines of bit math.
 *
 * Strategy: an IPv4 address is encoded as an unsigned 32-bit integer; a CIDR
 * is `{ network, mask }` where membership is `(ip & mask) === network`.
 * Operators using `>>> 0` ensure unsigned semantics on V8 (JS bit-ops are
 * normally signed-32). Parsers reject anything malformed and return `null`
 * so callers can warn-and-skip rather than throw.
 */

/** Parse a dotted-quad IPv4 string to an unsigned 32-bit integer. */
export function parseIpv4(s: string): number | null {
	if (typeof s !== "string") return null;
	const parts = s.split(".");
	if (parts.length !== 4) return null;
	let out = 0;
	for (const p of parts) {
		// Reject empty, non-digit, leading whitespace, or out-of-range octets.
		if (p.length === 0 || p.length > 3) return null;
		if (!/^\d+$/.test(p)) return null;
		const n = Number(p);
		if (!Number.isFinite(n) || n < 0 || n > 255) return null;
		out = ((out << 8) | n) >>> 0;
	}
	return out;
}

export interface Ipv4Cidr {
	/** Masked network address as uint32. */
	network: number;
	/** Subnet mask as uint32 (e.g. /24 → 0xFFFFFF00). */
	mask: number;
	/** Prefix length, 0..32. */
	prefix: number;
}

/**
 * Parse a `<ip>/<prefix>` (or bare `<ip>` treated as `/32`) into a normalized
 * `Ipv4Cidr`. Network address is masked, so callers don't have to worry about
 * "1.2.3.4/24" vs "1.2.3.0/24" — both end up with `network = 1.2.3.0`.
 */
export function parseCidr(s: string): Ipv4Cidr | null {
	if (typeof s !== "string") return null;
	const trimmed = s.trim();
	if (!trimmed) return null;
	const slash = trimmed.indexOf("/");
	const ipPart = slash === -1 ? trimmed : trimmed.slice(0, slash);
	const prefixPart = slash === -1 ? "32" : trimmed.slice(slash + 1);

	const ip = parseIpv4(ipPart);
	if (ip === null) return null;

	if (!/^\d+$/.test(prefixPart)) return null;
	const prefix = Number(prefixPart);
	if (!Number.isFinite(prefix) || prefix < 0 || prefix > 32) return null;

	// Build the mask. `prefix === 0` requires special-casing because
	// `(0xFFFFFFFF << 32) >>> 0` is implementation-defined (and on V8 is a
	// no-op shift by 0).
	const mask = prefix === 0 ? 0 : ((0xffffffff << (32 - prefix)) >>> 0);
	const network = (ip & mask) >>> 0;
	return { network, mask, prefix };
}

/** Is `ip` (uint32) inside the given CIDR? */
export function ipInCidr(ip: number, cidr: Ipv4Cidr): boolean {
	return ((ip & cidr.mask) >>> 0) === cidr.network;
}

/**
 * Linear-scan an IP against a list of CIDRs. Returns the first matching CIDR,
 * or `null`. For the feed sizes we care about (a few thousand CIDRs) the
 * linear scan is microseconds — no index needed.
 */
export function findCidrMatch(ip: number, cidrs: Ipv4Cidr[]): Ipv4Cidr | null {
	for (const c of cidrs) {
		if (ipInCidr(ip, c)) return c;
	}
	return null;
}
