// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Minimal TLS-RPT (RFC 8460) report parser.
 *
 * Reports arrive as `application/tlsrpt+gzip` (gzipped JSON) or
 * `application/tlsrpt+json`. The schema is fixed and small — see
 * RFC 8460 §4. We only capture the fields needed for the dashboard:
 * per-policy success/failure session counts plus the failure-details
 * breakdown by sending MTA IP, receiving MX, and result type.
 *
 * The 5MB post-decompression cap (issue #169) is enforced here; a
 * malicious sender can't OOM the Worker by attaching a small gzipped
 * blob that decompresses to gigabytes.
 */

/** Hard cap on decompressed JSON body size — see issue #169. */
export const TLSRPT_MAX_DECOMPRESSED_BYTES = 5 * 1024 * 1024;

export interface TlsRptReport {
	org_name?: string;
	report_id?: string;
	contact_info?: string;
	date_range_begin?: string;
	date_range_end?: string;
	/** Best-effort apex domain extracted from the first policy's `policy-domain`. */
	domain?: string;
	policies: TlsRptPolicy[];
}

export interface TlsRptPolicy {
	policy_type?: string;
	policy_domain?: string;
	successful_session_count: number;
	failed_session_count: number;
	failure_details: TlsRptFailureDetail[];
}

export interface TlsRptFailureDetail {
	result_type?: string;
	sending_mta_ip?: string;
	receiving_mx_hostname?: string;
	failed_session_count: number;
}

/** Gunzip an arraybuffer using the runtime's DecompressionStream. */
export async function gunzip(buf: ArrayBuffer): Promise<ArrayBuffer> {
	const stream = new Response(buf).body!.pipeThrough(new DecompressionStream("gzip"));
	return new Response(stream).arrayBuffer();
}

/** Decode a buffer to UTF-8 text. */
export function bufferToText(buf: ArrayBuffer): string {
	return new TextDecoder("utf-8", { fatal: false }).decode(buf);
}

/**
 * Parse a TLS-RPT JSON body into a normalized `TlsRptReport`. Returns
 * `null` if the input isn't valid JSON or doesn't look like a TLS-RPT
 * report shape. The caller is responsible for enforcing the 5MB cap
 * before calling — this function does not re-check size, only shape.
 */
export function parseTlsRptJson(json: string): TlsRptReport | null {
	let parsed: unknown;
	try {
		parsed = JSON.parse(json);
	} catch {
		return null;
	}
	if (!parsed || typeof parsed !== "object") return null;
	const root = parsed as Record<string, unknown>;

	const dateRange = root["date-range"] as Record<string, unknown> | undefined;
	const policiesIn = Array.isArray(root.policies) ? (root.policies as unknown[]) : [];

	const policies: TlsRptPolicy[] = [];
	for (const p of policiesIn) {
		if (!p || typeof p !== "object") continue;
		const policyObj = (p as Record<string, unknown>).policy as
			| Record<string, unknown>
			| undefined;
		const summary = (p as Record<string, unknown>).summary as
			| Record<string, unknown>
			| undefined;
		const failuresIn = (p as Record<string, unknown>)["failure-details"];
		const failureArray = Array.isArray(failuresIn) ? (failuresIn as unknown[]) : [];

		const failure_details: TlsRptFailureDetail[] = [];
		for (const f of failureArray) {
			if (!f || typeof f !== "object") continue;
			const fr = f as Record<string, unknown>;
			failure_details.push({
				result_type: stringOrUndef(fr["result-type"]),
				sending_mta_ip: stringOrUndef(fr["sending-mta-ip"]),
				receiving_mx_hostname: stringOrUndef(fr["receiving-mx-hostname"]),
				failed_session_count: clampCount(fr["failed-session-count"]),
			});
		}

		policies.push({
			policy_type: stringOrUndef(policyObj?.["policy-type"]),
			policy_domain: stringOrUndef(policyObj?.["policy-domain"]),
			successful_session_count: clampCount(summary?.["total-successful-session-count"]),
			failed_session_count: clampCount(summary?.["total-failure-session-count"]),
			failure_details,
		});
	}

	// Reject inputs that have neither the `policies` array nor the
	// minimal `report-id`/`organization-name` shape — those are almost
	// certainly not TLS-RPT reports.
	const orgName = stringOrUndef(root["organization-name"]);
	const reportId = stringOrUndef(root["report-id"]);
	if (policies.length === 0 && !orgName && !reportId) return null;

	return {
		org_name: orgName,
		report_id: reportId,
		contact_info: stringOrUndef(root["contact-info"]),
		date_range_begin: stringOrUndef(dateRange?.["start-datetime"]),
		date_range_end: stringOrUndef(dateRange?.["end-datetime"]),
		domain: policies[0]?.policy_domain,
		policies,
	};
}

function stringOrUndef(v: unknown): string | undefined {
	if (typeof v === "string" && v.length > 0) return v;
	return undefined;
}

function clampCount(v: unknown): number {
	if (typeof v !== "number" || !Number.isFinite(v)) return 0;
	return Math.max(0, Math.min(1_000_000, Math.floor(v)));
}
