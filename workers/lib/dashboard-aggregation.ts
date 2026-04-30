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

// ── Org overview aggregation ─────────────────────────────────────────

/** Subset of the per-mailbox DO summary the org aggregator consumes. */
export interface OrgMailboxSummary {
	threatsBlocked: number;
	threatsBlocked7d: number;
	openCases: number;
	hubContributions: number;
	pipelineScan: PipelineSuccessInput;
	verdictRows: VerdictBucketRow[];
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

export interface OrgTopThreat {
	category: string;
	count: number;
}

export interface OrgPipelineHealth {
	successRate24h: number | null;
	/** p95 latency in ms; null until #71 lands a per-run latency log. */
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

	let threatsBlocked24h = 0;
	let threatsBlocked7d = 0;
	let openCasesTotal = 0;
	let hubContributions24h = 0;
	let pipelineCompleted = 0;
	let pipelineFailed = 0;

	const verdictMix = emptyVerdictMix();
	const threatCounts = new Map<string, number>();

	for (const summary of summaries) {
		if (!summary) continue;
		threatsBlocked24h += summary.threatsBlocked;
		threatsBlocked7d += summary.threatsBlocked7d;
		openCasesTotal += summary.openCases;
		hubContributions24h += summary.hubContributions;
		pipelineCompleted += summary.pipelineScan.completed;
		pipelineFailed += summary.pipelineScan.failed;

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
	}

	const topThreats: OrgTopThreat[] = [...threatCounts.entries()]
		.map(([category, count]) => ({ category, count }))
		.sort((a, b) => b.count - a.count || a.category.localeCompare(b.category))
		.slice(0, topN);

	const pipelineHealth: OrgPipelineHealth = {
		successRate24h: pipelineSuccessRate({
			completed: pipelineCompleted,
			failed: pipelineFailed,
		}),
		p95Ms: null,
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
		topThreats,
		pipelineHealth,
		hubContributions24h,
	};
}
