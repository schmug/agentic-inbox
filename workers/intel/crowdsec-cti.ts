// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * CrowdSec CTI (Cyber Threat Intelligence) client.
 *
 * Hits the `smoke` endpoint at `cti.api.crowdsec.net/v2/smoke/{ip}` and
 * normalises the response into a small `CtiSummary` shape that downstream
 * scoring can map onto verdict-score deltas without re-parsing the upstream
 * payload.
 *
 * Free-tier CTI is rate-limited, so callers MUST stay on the async deep-scan
 * path — never on the synchronous mail-receive path. Responses are cached in
 * BLOOM_KV under `cti:crowdsec:{ip}` for ~12h to keep us under the per-day
 * ceiling. 404s (clean residential IPs not in CrowdSec's dataset) are cached
 * briefly with a sentinel so we don't re-query the same dead IP on every
 * email; 429s and network errors are NEVER cached — they're transient.
 *
 * The client is also designed for reuse from the (future) sync first-time-
 * sender prior path (issue #79); that path will need more aggressive caching
 * and stricter timeouts but the lookup surface stays the same.
 */

import type { Env } from "../types";

export interface CtiSummary {
	classifications: string[];
	behaviors: string[];
	scores: { threat: number; aggressiveness: number; trust: number };
	reputation: "malicious" | "suspicious" | "known" | "benign" | "safe" | "unknown";
}

/**
 * Cache TTL for positive (200) lookups. 12h chosen within the 12–24h range
 * called for in the issue: long enough to keep us comfortably under the free-
 * tier ceiling for repeat IPs, short enough that a freshly-blocked IP shows
 * up in our enrichment within half a day.
 */
const CACHE_TTL_POSITIVE_S = 12 * 3600;

/**
 * Cache TTL for 404s (IP not in CrowdSec's dataset). Much shorter — clean
 * residential IPs may pick up a reputation as campaigns rotate, and the
 * sentinel is cheap to refresh. 1h is the recommended floor.
 */
const CACHE_TTL_MISS_S = 3600;

/**
 * Per-request CTI fetch timeout. Comfortably under workerd's overall fetch
 * budget so a single slow CTI response can't dominate the deep-scan stage.
 */
const CTI_REQUEST_TIMEOUT_MS = 4000;

const CACHE_PREFIX = "cti:crowdsec:";
/** Sentinel JSON for "we asked, IP not in dataset" — distinguishes from KV miss. */
const MISS_SENTINEL = "__cti_miss__";

export type CtiTransport = (url: string, init?: RequestInit) => Promise<Response>;

/**
 * Look up an IP in CrowdSec CTI. Returns `null` for any of:
 *
 *   - `CROWDSEC_CTI_API_KEY` not configured (no-op for unconfigured deploys)
 *   - 404 (IP not in dataset; common for clean residential IPs)
 *   - 429 rate-limit (logged warning; no retry; cache NOT poisoned)
 *   - Network error / timeout / unparseable body
 *
 * Never throws; deep-scan treats `null` as "no CTI signal", not "fail closed".
 */
export async function lookupIp(
	env: Env,
	ip: string,
	fetchImpl: CtiTransport = fetch,
): Promise<CtiSummary | null> {
	const apiKey = env.CROWDSEC_CTI_API_KEY;
	if (!apiKey) return null;
	if (!ip) return null;

	const cacheKey = CACHE_PREFIX + ip;
	if (env.BLOOM_KV) {
		const cached = await env.BLOOM_KV.get(cacheKey, "text").catch(() => null);
		if (cached === MISS_SENTINEL) return null;
		if (cached) {
			try {
				return JSON.parse(cached) as CtiSummary;
			} catch {
				// Corrupt cache entry — fall through and re-fetch.
			}
		}
	}

	let res: Response;
	try {
		res = await fetchImpl(`https://cti.api.crowdsec.net/v2/smoke/${encodeURIComponent(ip)}`, {
			headers: {
				"x-api-key": apiKey,
				"accept": "application/json",
			},
			signal: AbortSignal.timeout(CTI_REQUEST_TIMEOUT_MS),
		});
	} catch {
		// Network or timeout — don't poison cache; transient errors should
		// recover on the next email.
		return null;
	}

	if (res.status === 404) {
		// IP not in CrowdSec's dataset. Cache the miss briefly so we don't
		// re-query for every email mentioning the same clean IP.
		if (env.BLOOM_KV) {
			await env.BLOOM_KV
				.put(cacheKey, MISS_SENTINEL, { expirationTtl: CACHE_TTL_MISS_S })
				.catch(() => {});
		}
		return null;
	}
	if (res.status === 429) {
		// Rate-limited. Don't cache, don't retry — surface a warning so
		// operators can monitor free-tier headroom.
		console.warn(`crowdsec CTI rate-limited (429) on ${ip}`);
		return null;
	}
	if (!res.ok) {
		// Other 4xx/5xx — treat as transient, don't cache.
		console.warn(`crowdsec CTI ${res.status} on ${ip}`);
		return null;
	}

	let body: unknown;
	try {
		body = await res.json();
	} catch {
		return null;
	}
	const summary = normalize(body);
	if (!summary) return null;

	if (env.BLOOM_KV) {
		await env.BLOOM_KV
			.put(cacheKey, JSON.stringify(summary), { expirationTtl: CACHE_TTL_POSITIVE_S })
			.catch(() => {});
	}
	return summary;
}

/**
 * Project the full CrowdSec CTI smoke payload down to the small slice we
 * actually use for scoring. Resilient to missing fields — CTI's response
 * shape varies depending on what they know about an IP.
 *
 * Exported for tests; production callers should prefer `lookupIp`.
 */
export function normalize(body: unknown): CtiSummary | null {
	if (!body || typeof body !== "object") return null;
	const b = body as Record<string, unknown>;

	const classifications = collectClassifications(b.classifications);
	const behaviors = collectLabeledList(b.behaviors, "label");
	const scores = collectScores(b.scores);
	const reputation = collectReputation(b.reputation);

	return { classifications, behaviors, scores, reputation };
}

function collectClassifications(raw: unknown): string[] {
	// CrowdSec returns `classifications` as `{ classifications: [{name, label, ...}], false_positives: [...] }`
	// or sometimes as a bare array. Be liberal in what we accept.
	if (!raw) return [];
	const list = Array.isArray(raw)
		? raw
		: Array.isArray((raw as { classifications?: unknown }).classifications)
			? ((raw as { classifications: unknown[] }).classifications)
			: [];
	const out: string[] = [];
	for (const item of list) {
		if (typeof item === "string") {
			out.push(item);
			continue;
		}
		if (item && typeof item === "object") {
			const name = (item as { name?: unknown }).name;
			if (typeof name === "string" && name) out.push(name);
		}
	}
	return out;
}

function collectLabeledList(raw: unknown, primaryKey: "label" | "name"): string[] {
	if (!Array.isArray(raw)) return [];
	const out: string[] = [];
	for (const item of raw) {
		if (typeof item === "string") {
			out.push(item);
			continue;
		}
		if (item && typeof item === "object") {
			const obj = item as Record<string, unknown>;
			const v = obj[primaryKey] ?? obj.name ?? obj.label;
			if (typeof v === "string" && v) out.push(v);
		}
	}
	return out;
}

function collectScores(raw: unknown): { threat: number; aggressiveness: number; trust: number } {
	const empty = { threat: 0, aggressiveness: 0, trust: 0 };
	if (!raw || typeof raw !== "object") return empty;
	const overall = (raw as { overall?: unknown }).overall;
	if (!overall || typeof overall !== "object") return empty;
	const o = overall as Record<string, unknown>;
	return {
		threat: numericOr(o.threat, 0),
		aggressiveness: numericOr(o.aggressiveness, 0),
		trust: numericOr(o.trust, 0),
	};
}

function collectReputation(raw: unknown): CtiSummary["reputation"] {
	if (typeof raw !== "string") return "unknown";
	const lower = raw.toLowerCase();
	switch (lower) {
		case "malicious":
		case "suspicious":
		case "known":
		case "benign":
		case "safe":
			return lower;
		default:
			return "unknown";
	}
}

function numericOr(v: unknown, fallback: number): number {
	if (typeof v === "number" && Number.isFinite(v)) return v;
	return fallback;
}
