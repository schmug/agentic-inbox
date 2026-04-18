// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Threat-intel feed refresh and lookup.
 *
 * Refresh flow (runs on cron, see workers/app.ts scheduled handler):
 *   1. Read mailbox list from R2.
 *   2. For each mailbox with `intel.feeds`, fetch each feed (If-None-Match).
 *   3. Parse entries (domain or URL, ignore `#` comments).
 *   4. Build a bloom filter and store under KV key `intel:{feedId}:bloom`.
 *   5. Also write an `intel:{feedId}:exact:<value>` marker for a subset of
 *      high-confidence entries so we can confirm a bloom hit without false
 *      positives. (Bounded to prevent runaway KV writes.)
 *   6. Update `intel_feed_state` row on the mailbox DO.
 *
 * Lookup flow:
 *   - `checkUrlAgainstFeeds(env, mailboxId, url)` — called by the security
 *     pipeline. Returns `{ matched: true, feed: string }` on confirmed hit,
 *     `null` otherwise.
 */

import type { Env } from "../types";
import { DEFAULT_FEEDS, type FeedDefinition } from "./defaults";
import {
	addToBloom,
	checkBloom,
	createBloom,
	deserializeBloom,
	serializeBloom,
} from "./bloom";
import { getMailboxStub, listMailboxes } from "../lib/email-helpers";

const EXACT_KEY_CAP = 2000; // per-feed cap — we only fast-path confirm up to this many

function bloomKey(feedId: string) { return `intel:${feedId}:bloom`; }
function exactKey(feedId: string, value: string) { return `intel:${feedId}:exact:${value}`; }

export interface MailboxIntelSettings {
	feeds?: Array<{
		id: string;
		url?: string;
		kind?: "domain" | "url";
		refresh_hours?: number;
		headers?: Record<string, string>;
		/** If set, reads header value from a Worker secret of this name at refresh time. */
		auth_secret?: string;
	}>;
	hub?: {
		url: string;
		org_uuid: string;
		api_key_secret_name: string;
		auto_report: boolean;
		default_sharing_group_uuid?: string;
	};
}

async function loadMailboxIntelSettings(env: Env, mailboxId: string): Promise<MailboxIntelSettings> {
	const obj = await env.BUCKET.get(`mailboxes/${mailboxId}.json`);
	if (!obj) return {};
	try {
		const json = (await obj.json()) as { intel?: MailboxIntelSettings } | null;
		return json?.intel ?? {};
	} catch {
		return {};
	}
}

function resolveFeeds(env: Env, settings: MailboxIntelSettings): FeedDefinition[] {
	const defaults = settings.feeds && settings.feeds.length > 0 ? [] : DEFAULT_FEEDS;
	const byId = new Map<string, FeedDefinition>(DEFAULT_FEEDS.map((f) => [f.id, f]));
	const user: FeedDefinition[] = [];
	for (const f of settings.feeds ?? []) {
		const base = byId.get(f.id);
		const headers: Record<string, string> = { ...(f.headers ?? {}) };
		if (f.auth_secret) {
			const secretValue = (env as unknown as Record<string, string>)[f.auth_secret];
			if (secretValue) headers["Authorization"] = secretValue;
		}
		user.push({
			id: f.id,
			url: f.url ?? base?.url ?? "",
			kind: f.kind ?? base?.kind ?? "url",
			refreshHours: f.refresh_hours ?? base?.refreshHours ?? 6,
			description: base?.description ?? "User-configured feed",
			headers: Object.keys(headers).length > 0 ? headers : undefined,
		});
	}
	return [...defaults, ...user].filter((f) => f.url);
}

function parseFeedBody(body: string, kind: "domain" | "url"): string[] {
	const lines = body.split(/\r?\n/);
	const out: string[] = [];
	for (const raw of lines) {
		const line = raw.trim();
		if (!line || line.startsWith("#")) continue;
		if (kind === "domain") {
			out.push(normalizeDomain(line));
		} else {
			out.push(line);
			const host = safeHostname(line);
			if (host) out.push(normalizeDomain(host));
		}
	}
	return out;
}

function normalizeDomain(s: string): string {
	return s.toLowerCase().replace(/^https?:\/\//, "").split(/[\/?#]/)[0];
}

function safeHostname(url: string): string | null {
	try { return new URL(url).hostname.toLowerCase(); } catch { return null; }
}

/** Refresh all feeds across all mailboxes. Called from the cron handler. */
export async function refreshAllFeeds(env: Env): Promise<{ feeds: number; entries: number }> {
	if (!env.BLOOM_KV) {
		console.warn("BLOOM_KV binding not configured — skipping intel feed refresh");
		return { feeds: 0, entries: 0 };
	}
	const mailboxes = await listMailboxes(env.BUCKET);
	const handled = new Set<string>();
	let feeds = 0;
	let entries = 0;
	for (const { id: mailboxId } of mailboxes) {
		const settings = await loadMailboxIntelSettings(env, mailboxId);
		const resolved = resolveFeeds(env, settings);
		for (const feed of resolved) {
			if (handled.has(feed.id)) continue; // global, not per-mailbox, to avoid duplicate work
			handled.add(feed.id);
			try {
				const refreshed = await refreshFeed(env, mailboxId, feed);
				feeds++;
				entries += refreshed.entries;
			} catch (e) {
				console.error(`feed refresh ${feed.id} failed:`, (e as Error).message);
			}
		}
	}
	return { feeds, entries };
}

async function refreshFeed(
	env: Env,
	mailboxId: string,
	feed: FeedDefinition,
): Promise<{ entries: number }> {
	const stub = getMailboxStub(env, mailboxId);
	const state = await stub.getIntelFeedState(feed.id);

	const headers: Record<string, string> = { ...(feed.headers ?? {}) };
	if (state?.etag) headers["If-None-Match"] = state.etag;

	const res = await fetch(feed.url, { headers, signal: AbortSignal.timeout(15000) });
	if (res.status === 304) return { entries: state?.entry_count ?? 0 };
	if (!res.ok) throw new Error(`${feed.url} returned ${res.status}`);

	const body = await res.text();
	const values = parseFeedBody(body, feed.kind);
	if (values.length === 0) return { entries: 0 };

	const bloom = createBloom(values.length);
	for (const v of values) addToBloom(bloom, v);
	await env.BLOOM_KV.put(bloomKey(feed.id), serializeBloom(bloom), {
		// Bounded TTL — a dead cron should eventually stop consulting stale data.
		expirationTtl: Math.max(feed.refreshHours * 3600 * 4, 86400),
	});

	// Write a bounded subset of exact-match markers for secondary confirmation.
	const exactSlice = values.slice(0, EXACT_KEY_CAP);
	const writes: Promise<void>[] = [];
	for (const v of exactSlice) {
		writes.push(
			env.BLOOM_KV
				.put(exactKey(feed.id, v), "1", {
					expirationTtl: feed.refreshHours * 3600 * 4,
				})
				.catch(() => {}), // isolated; individual failures shouldn't abort refresh
		);
	}
	await Promise.all(writes);

	await stub.upsertIntelFeedState(feed.id, {
		url: feed.url,
		last_fetched_at: new Date().toISOString(),
		etag: res.headers.get("ETag") ?? null,
		entry_count: values.length,
		bloom_kv_key: bloomKey(feed.id),
	});

	return { entries: values.length };
}

export interface FeedMatch {
	matched: true;
	feedId: string;
	value: string;
	confirmed: boolean;
}

/**
 * Check a URL's hostname and full URL against all configured feeds.
 * Returns the first confirmed match, or the first bloom-only hit if no
 * exact confirmations are available.
 */
export async function checkUrlAgainstFeeds(
	env: Env,
	mailboxId: string,
	fullUrl: string,
): Promise<FeedMatch | null> {
	if (!env.BLOOM_KV) return null;
	const host = safeHostname(fullUrl);
	if (!host) return null;
	const settings = await loadMailboxIntelSettings(env, mailboxId);
	const feeds = resolveFeeds(env, settings);
	let bloomOnly: FeedMatch | null = null;

	for (const feed of feeds) {
		const serialized = await env.BLOOM_KV.get(bloomKey(feed.id), "arrayBuffer");
		if (!serialized) continue;
		const filter = deserializeBloom(serialized);
		if (!filter) continue;
		const candidates = feed.kind === "domain" ? [host] : [fullUrl, host];
		for (const v of candidates) {
			if (!checkBloom(filter, v)) continue;
			const exact = await env.BLOOM_KV.get(exactKey(feed.id, v), "text");
			if (exact === "1") return { matched: true, feedId: feed.id, value: v, confirmed: true };
			if (!bloomOnly) bloomOnly = { matched: true, feedId: feed.id, value: v, confirmed: false };
		}
	}
	return bloomOnly;
}
