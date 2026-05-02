// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Default threat-intel feeds shipped with the project.
 *
 * Each feed is a newline-delimited list of domains or URLs. The refresh
 * worker tolerates comments (lines starting with `#`) and blank lines.
 *
 * Licensing notes for redistribution:
 * - URLhaus is public-domain (CC0) — safe to mirror.
 * - PhishTank requires an API key + attribution — ship as opt-in config only.
 * - PhishDestroy / DestroyList publish plain text feeds; check their current
 *   terms before redistributing aggregated copies from the hub.
 * Consumers are free to add their own feeds via mailbox settings.
 */

export interface FeedDefinition {
	id: string;
	url: string;
	/**
	 * Content type of the feed:
	 *   - `domain` — registrable hostnames, one per line
	 *   - `url`    — full URLs, one per line
	 *   - `ip-cidr` — IPv4 CIDRs (or single IPs treated as `/32`), one per line.
	 *     Stored differently from `domain`/`url` feeds: bloom filters don't fit
	 *     CIDR membership, so the refresher writes the parsed CIDR list as a
	 *     single KV blob and lookup does a linear scan with IPv4-as-uint32
	 *     masking. See `workers/intel/feeds.ts` for details.
	 */
	kind: "domain" | "url" | "ip-cidr";
	refreshHours: number;
	/** One-line human description. */
	description: string;
	/**
	 * Optional per-feed extra request headers. Used for authenticated pulls
	 * (e.g. hub destroylist with `Authorization: <api-key>`).
	 */
	headers?: Record<string, string>;
}

export const DEFAULT_FEEDS: FeedDefinition[] = [
	{
		id: "urlhaus",
		url: "https://urlhaus.abuse.ch/downloads/text_online/",
		kind: "url",
		refreshHours: 1,
		description: "abuse.ch URLhaus — active malicious URL feed (CC0).",
	},
	{
		id: "openphish",
		url: "https://openphish.com/feed.txt",
		kind: "url",
		refreshHours: 6,
		description: "OpenPhish community phishing URL feed.",
	},
	{
		id: "spamhaus-drop",
		url: "https://www.spamhaus.org/drop/drop.txt",
		kind: "ip-cidr",
		refreshHours: 12,
		description:
			"Spamhaus DROP — hijacked netblocks and known spam operations (no auth).",
	},
	{
		id: "spamhaus-edrop",
		url: "https://www.spamhaus.org/drop/edrop.txt",
		kind: "ip-cidr",
		refreshHours: 12,
		description:
			"Spamhaus EDROP — extended DROP list of additional spammer netblocks (no auth).",
	},
];
