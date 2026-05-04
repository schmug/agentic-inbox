// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Per-stage pipeline trace types for issue #128.
 *
 * `runSecurityPipeline` measures wall-clock duration around each stage,
 * captures the score contribution of that stage, and emits a
 * `StageRecord[]` alongside the `FinalVerdict`. The trace is persisted
 * on the originating email row (`emails.stage_trace`) and copied to
 * `cases.stage_trace` at case-creation time, where the case-detail
 * timeline renders it as a vertical card.
 *
 * The taxonomy is a closed set so the frontend can render all 7 rows
 * uniformly (skipped/short-circuited stages still show, just with 0
 * contribution and a status badge). Adding a new stage means: extend
 * `StageId`, emit a record from the pipeline, and update the timeline
 * UI's stage-label table.
 */

export const STAGE_IDS = [
	"auth",
	"url",
	"reputation",
	"intel",
	"triage",
	"llm",
	"verdict",
] as const;

export type StageId = (typeof STAGE_IDS)[number];

export type StageStatus = "ok" | "skipped" | "failed" | "short_circuited";

export interface StageRecord {
	stage: StageId;
	status: StageStatus;
	/**
	 * Score contribution from this stage to the final verdict. For the
	 * five aggregation stages (auth/url/reputation/llm) this is the
	 * `score` returned by the corresponding `score*` helper; for the
	 * `intel` stage it's the post-aggregation boost (0/5/20); for
	 * `triage` it's 0 on the passed path, or the synthesised verdict's
	 * full score on the short-circuited path; for `verdict` it's the
	 * final post-boost total. Skipped/failed stages report 0.
	 */
	score_contrib: number;
	/** Wall-clock time spent inside this stage, milliseconds. */
	duration_ms: number;
	/**
	 * Optional one-line annotation. Used to convey *why* a stage was
	 * skipped/short-circuited or to surface the dominant signal
	 * (e.g. "triage hard_block: confirmed-intel match").
	 */
	reason?: string;
}

/**
 * JSON parser used by the case-detail API and the `getCase` DO method.
 *
 * Safe-by-default: any malformed payload (non-JSON, non-array, items
 * missing required keys, unknown stage id, unknown status) returns
 * `null` so the frontend hides the timeline card rather than render
 * partially. Trace rows are persisted by the same pipeline that owns
 * the schema, so a failed parse means the row was corrupted out-of-
 * band — there's no upgrade path that warrants surfacing fragments.
 */
export function parseStageTrace(raw: unknown): StageRecord[] | null {
	if (typeof raw !== "string" || raw.length === 0) return null;
	let parsed: unknown;
	try {
		parsed = JSON.parse(raw);
	} catch {
		return null;
	}
	if (!Array.isArray(parsed)) return null;
	const valid: StageRecord[] = [];
	const stageSet = new Set<StageId>(STAGE_IDS);
	const statusSet = new Set<StageStatus>([
		"ok",
		"skipped",
		"failed",
		"short_circuited",
	]);
	for (const item of parsed) {
		if (!item || typeof item !== "object") return null;
		const r = item as Record<string, unknown>;
		if (typeof r.stage !== "string" || !stageSet.has(r.stage as StageId)) return null;
		if (typeof r.status !== "string" || !statusSet.has(r.status as StageStatus)) return null;
		if (typeof r.score_contrib !== "number") return null;
		if (typeof r.duration_ms !== "number") return null;
		const record: StageRecord = {
			stage: r.stage as StageId,
			status: r.status as StageStatus,
			score_contrib: r.score_contrib,
			duration_ms: r.duration_ms,
		};
		if (typeof r.reason === "string" && r.reason.length > 0) {
			record.reason = r.reason;
		}
		valid.push(record);
	}
	return valid;
}
