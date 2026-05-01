// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Pure helpers for the operations dashboard. Live outside the Durable Object
 * so the bucketing + JSON-parsing logic is unit-testable without a
 * runtime SQL surface — the DO `getDashboardSummary` method composes these
 * with the SQL it owns.
 */

export type ThreatAction = "tag" | "quarantine" | "block";

export interface VerdictBucketRow {
	/** ISO 8601 timestamp from `emails.date`. */
	date: string | null;
	/** Raw `emails.security_verdict` cell — JSON-encoded `VerdictResult`. */
	security_verdict: string | null;
}

/**
 * Roll up recent emails into N equal-width time buckets, counting only
 * threat-actioned verdicts (tag/quarantine/block — `allow` is dropped).
 *
 * Buckets are oldest-first, so `result[0]` is the oldest window and
 * `result[N-1]` is the most recent. Rows outside the window or with
 * unparseable verdict JSON are silently dropped.
 */
export function bucketThreatPressure(
	rows: VerdictBucketRow[],
	options: { now?: Date; bucketCount?: number; windowHours?: number } = {},
): number[] {
	const now = options.now ?? new Date();
	const bucketCount = options.bucketCount ?? 12;
	const windowHours = options.windowHours ?? 24;

	const windowMs = windowHours * 60 * 60 * 1000;
	const windowStart = now.getTime() - windowMs;
	const bucketMs = windowMs / bucketCount;
	const buckets = new Array<number>(bucketCount).fill(0);

	for (const row of rows) {
		if (!row.date || !row.security_verdict) continue;

		const action = parseVerdictAction(row.security_verdict);
		if (action !== "tag" && action !== "quarantine" && action !== "block") continue;

		const t = Date.parse(row.date);
		if (Number.isNaN(t)) continue;
		if (t < windowStart || t > now.getTime()) continue;

		const idx = Math.min(
			Math.floor((t - windowStart) / bucketMs),
			bucketCount - 1,
		);
		buckets[idx] += 1;
	}

	return buckets;
}

function parseVerdictAction(json: string): string | null {
	try {
		const parsed = JSON.parse(json) as { action?: unknown };
		return typeof parsed.action === "string" ? parsed.action : null;
	} catch {
		return null;
	}
}

interface ParsedVerdict {
	action?: string;
	classification?: { label?: string };
}

function parseVerdict(json: string): ParsedVerdict | null {
	try {
		return JSON.parse(json) as ParsedVerdict;
	} catch {
		return null;
	}
}

export interface PipelineSuccessInput {
	completed: number;
	failed: number;
}

/**
 * Compute the pipeline-success ratio over the deep-scan-status counts. Returns
 * `null` when there's no data to report (UI surfaces an "—" placeholder rather
 * than a misleading 0%).
 */
export function pipelineSuccessRate(input: PipelineSuccessInput): number | null {
	const total = input.completed + input.failed;
	if (total === 0) return null;
	return input.completed / total;
}

/**
 * Compute the 95th-percentile value of a sample of durations using linear
 * interpolation between adjacent ranks. Returns `null` for an empty sample so
 * the dashboard can render a neutral placeholder rather than a misleading 0.
 *
 * Negative or non-finite inputs are dropped — they only show up if a clock
 * jumped backwards mid-run, and counting them would understate p95.
 */
export function computeP95(durationsMs: number[]): number | null {
	const sample = durationsMs
		.filter((d) => Number.isFinite(d) && d >= 0)
		.sort((a, b) => a - b);
	if (sample.length === 0) return null;
	if (sample.length === 1) return sample[0]!;
	const rank = 0.95 * (sample.length - 1);
	const lo = Math.floor(rank);
	const hi = Math.ceil(rank);
	if (lo === hi) return sample[lo]!;
	const weight = rank - lo;
	return sample[lo]! * (1 - weight) + sample[hi]! * weight;
}

// ── Org overview aggregation ─────────────────────────────────────────

/** Subset of the per-mailbox DO summary the org aggregator consumes. */
export interface OrgMailboxSummary {
	threatsBlocked: number;
	threatsBlocked7d: number;
	openCases: number;
	hubContributions: number;
	pipelineScan: PipelineSuccessInput;
	verdictRows: VerdictBucketRow[];
	/**
	 * Pre-aggregated 7d verdict mix from the DO (#103). Pre-aggregating
	 * server-side keeps the org-overview wire payload from doubling — only
	 * the five-key counts cross the boundary, not the raw 7d rows. Optional
	 * so older DO replicas mid-deploy degrade gracefully (counted as zero).
	 */
	verdictMix7d?: VerdictMix;
	/**
	 * Pre-aggregated representative emails per actioned classification
	 * label (#101). Each label maps to up to N most-recent samples from
	 * this mailbox; the org aggregator unions across mailboxes, dedupes
	 * by emailId, and slices to top-N per category. Optional so older DO
	 * replicas mid-deploy degrade gracefully.
	 */
	topThreatSamples?: Record<string, OrgTopThreatSample[]>;
	/**
	 * Per-pipeline-run durations from `pipeline_runs` (#71). Unioned across
	 * mailboxes to compute an org-wide p95. Optional so older DO replicas
	 * mid-deploy degrade gracefully (treated as no samples).
	 */
	pipelineDurationsMs?: number[];
}

export interface OrgMailboxRef {
	id: string;
	email: string;
}

export interface VerdictMix {
	safe: number;
	suspicious: number;
	phishing: number;
	spam: number;
	bec: number;
}

/** Representative email surfaced for a top-threats category (#101). */
export interface OrgTopThreatSample {
	emailId: string;
	subject: string;
	sender: string;
}

export interface OrgTopThreat {
	category: string;
	count: number;
	/**
	 * Up to N representative emails for this category, deduped by emailId
	 * across mailboxes (#101). Optional so older DO replicas mid-deploy
	 * (which don't ship `topThreatSamples`) gracefully omit the panel.
	 */
	samples?: OrgTopThreatSample[];
}

export interface OrgPipelineHealth {
	successRate24h: number | null;
	/** Org-wide p95 latency in ms — unioned per-mailbox samples (#71). */
	p95Ms: number | null;
	runs24h: number;
}

export interface OrgOverview {
	now: string;
	threatsBlocked24h: number;
	threatsBlocked7d: number;
	openCasesTotal: number;
	mailboxesCount: number;
	domainsCount: number;
	verdictMix: VerdictMix;
	/**
	 * 7-day verdict mix (#103). Sums each mailbox's pre-aggregated 7d mix.
	 * Mailboxes with no `verdictMix7d` (older DO replicas mid-deploy)
	 * contribute zero, so the field is always present.
	 */
	verdictMix7d: VerdictMix;
	topThreats: OrgTopThreat[];
	pipelineHealth: OrgPipelineHealth;
	hubContributions24h: number;
}

/** Verdict-mix labels we surface; unknown labels (e.g. malformed JSON) drop. */
const VERDICT_MIX_KEYS: ReadonlyArray<keyof VerdictMix> = [
	"safe",
	"suspicious",
	"phishing",
	"spam",
	"bec",
];

function emptyVerdictMix(): VerdictMix {
	return { safe: 0, suspicious: 0, phishing: 0, spam: 0, bec: 0 };
}

/**
 * Pure helper: tally verdict-mix labels from a list of `(date,
 * security_verdict)` rows. Used by the DO to pre-aggregate the 7-day
 * window server-side so the org-overview payload doesn't have to ship
 * raw 7d rows over the wire.
 */
export function computeVerdictMix(rows: VerdictBucketRow[]): VerdictMix {
	const mix = emptyVerdictMix();
	for (const row of rows) {
		if (!row.security_verdict) continue;
		const parsed = parseVerdict(row.security_verdict);
		if (!parsed) continue;
		const label = parsed.classification?.label;
		if (
			typeof label === "string" &&
			(VERDICT_MIX_KEYS as readonly string[]).includes(label)
		) {
			mix[label as keyof VerdictMix] += 1;
		}
	}
	return mix;
}

interface AggregateOrgOverviewInput {
	mailboxes: OrgMailboxRef[];
	/**
	 * Per-mailbox summaries. Indices align with `mailboxes`. `null` slots are
	 * mailboxes whose DO call failed — they contribute 0 to all counts but
	 * still count toward `mailboxesCount` (the operator paid to provision them
	 * regardless of whether the DO answered today).
	 */
	summaries: Array<OrgMailboxSummary | null>;
	now?: string;
	/** How many top-threats to surface. Default 5. */
	topN?: number;
	/** How many representative samples per top-threat to keep. Default 3. */
	samplesPerThreat?: number;
}

/**
 * Reduce a fan-out of per-mailbox summaries into the single org-overview
 * payload the / dashboard renders. Pure function — accepts plain objects so
 * it's exercisable in unit tests without a runtime SQL surface.
 */
export function aggregateOrgOverview(
	input: AggregateOrgOverviewInput,
): OrgOverview {
	const { mailboxes, summaries } = input;
	const now = input.now ?? new Date().toISOString();
	const topN = input.topN ?? 5;
	const samplesPerThreat = input.samplesPerThreat ?? 3;

	let threatsBlocked24h = 0;
	let threatsBlocked7d = 0;
	let openCasesTotal = 0;
	let hubContributions24h = 0;
	let pipelineCompleted = 0;
	let pipelineFailed = 0;
	const allDurationsMs: number[] = [];

	const verdictMix = emptyVerdictMix();
	const verdictMix7d = emptyVerdictMix();
	const threatCounts = new Map<string, number>();
	// Per-category collected samples, deduped by emailId across mailboxes.
	const samplesByCategory = new Map<string, Map<string, OrgTopThreatSample>>();

	for (const summary of summaries) {
		if (!summary) continue;
		threatsBlocked24h += summary.threatsBlocked;
		threatsBlocked7d += summary.threatsBlocked7d;
		openCasesTotal += summary.openCases;
		hubContributions24h += summary.hubContributions;
		pipelineCompleted += summary.pipelineScan.completed;
		pipelineFailed += summary.pipelineScan.failed;
		if (summary.pipelineDurationsMs?.length) {
			allDurationsMs.push(...summary.pipelineDurationsMs);
		}

		// Pre-aggregated 7d mix per mailbox — sum into the org-wide tally.
		// Optional on the wire so older DO replicas degrade as zeros.
		if (summary.verdictMix7d) {
			for (const k of VERDICT_MIX_KEYS) {
				verdictMix7d[k] += summary.verdictMix7d[k];
			}
		}

		for (const row of summary.verdictRows) {
			if (!row.security_verdict) continue;
			const parsed = parseVerdict(row.security_verdict);
			if (!parsed) continue;
			const label = parsed.classification?.label;
			if (typeof label === "string" && (VERDICT_MIX_KEYS as readonly string[]).includes(label)) {
				verdictMix[label as keyof VerdictMix] += 1;
			}
			// Top-threats: count tag/quarantine/block by classification label.
			// `allow` is excluded because it's not a threat — surfacing "safe"
			// as a top threat would be misleading.
			if (
				(parsed.action === "tag" ||
					parsed.action === "quarantine" ||
					parsed.action === "block") &&
				typeof label === "string" &&
				label !== "safe"
			) {
				threatCounts.set(label, (threatCounts.get(label) ?? 0) + 1);
			}
		}

		// Pre-aggregated samples per category from this mailbox (#101).
		// Dedup across mailboxes by emailId — first-seen wins, matching
		// the DO's "most-recent" ordering since DOs ship samples sorted.
		if (summary.topThreatSamples) {
			for (const [category, list] of Object.entries(summary.topThreatSamples)) {
				if (!Array.isArray(list)) continue;
				let bucket = samplesByCategory.get(category);
				if (!bucket) {
					bucket = new Map<string, OrgTopThreatSample>();
					samplesByCategory.set(category, bucket);
				}
				for (const sample of list) {
					if (!sample?.emailId) continue;
					if (!bucket.has(sample.emailId)) {
						bucket.set(sample.emailId, {
							emailId: sample.emailId,
							subject: sample.subject ?? "",
							sender: sample.sender ?? "",
						});
					}
				}
			}
		}
	}

	const topThreats: OrgTopThreat[] = [...threatCounts.entries()]
		.map(([category, count]) => {
			const bucket = samplesByCategory.get(category);
			const samples = bucket
				? [...bucket.values()].slice(0, samplesPerThreat)
				: undefined;
			return samples && samples.length > 0
				? { category, count, samples }
				: { category, count };
		})
		.sort((a, b) => b.count - a.count || a.category.localeCompare(b.category))
		.slice(0, topN);

	const pipelineHealth: OrgPipelineHealth = {
		successRate24h: pipelineSuccessRate({
			completed: pipelineCompleted,
			failed: pipelineFailed,
		}),
		p95Ms: computeP95(allDurationsMs),
		runs24h: pipelineCompleted + pipelineFailed,
	};

	const domains = new Set<string>();
	for (const m of mailboxes) {
		const domain = m.email.split("@")[1]?.toLowerCase();
		if (domain) domains.add(domain);
	}

	return {
		now,
		threatsBlocked24h,
		threatsBlocked7d,
		openCasesTotal,
		mailboxesCount: mailboxes.length,
		domainsCount: domains.size,
		verdictMix,
		verdictMix7d,
		topThreats,
		pipelineHealth,
		hubContributions24h,
	};
}
