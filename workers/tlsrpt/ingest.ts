// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * TLS-RPT (RFC 8460) inbound report ingestion.
 *
 * Reports arrive as email with `application/tlsrpt+gzip` (gzipped
 * JSON) or `application/tlsrpt+json` attachments. We divert them out
 * of the security pipeline (machine reports must never be classified
 * as phish) and feed them into the per-mailbox dashboard DB. Mirrors
 * `workers/dmarc/ingest.ts` — see its docs for the divert pattern.
 */

import type { Email } from "postal-mime";
import type { Env } from "../types";
import { getMailboxStub } from "../lib/email-helpers";
import {
	bufferToText,
	gunzip,
	parseTlsRptJson,
	TLSRPT_MAX_DECOMPRESSED_BYTES,
} from "./parser";

const TLSRPT_GZIP_MIME = "application/tlsrpt+gzip";
const TLSRPT_JSON_MIME = "application/tlsrpt+json";

/** Heuristic: does this parsed email look like a TLS-RPT report? */
export function isTlsRptReport(parsed: Email): boolean {
	const subject = (parsed.subject ?? "").toLowerCase();
	// RFC 8460 §3 RECOMMENDS subject `Report Domain: <domain> Submitter:
	// <submitter> Report-ID: <id>`; some senders use lowercase `tls report`.
	if (subject.includes("tls report") || subject.includes("tlsrpt")) return true;
	for (const a of parsed.attachments ?? []) {
		const mt = (a.mimeType ?? "").toLowerCase();
		if (mt === TLSRPT_GZIP_MIME || mt === TLSRPT_JSON_MIME) return true;
		const fn = (a.filename ?? "").toLowerCase();
		if (fn.endsWith(".tlsrpt.gz") || fn.endsWith(".tlsrpt.json") || fn.endsWith(".tlsrpt")) {
			return true;
		}
	}
	return false;
}

export async function ingestTlsRptReport(
	env: Env,
	mailboxId: string,
	messageId: string,
	parsed: Email,
): Promise<{ ingested: boolean; reason?: string }> {
	const attachments = parsed.attachments ?? [];
	let jsonText: string | null = null;

	for (const att of attachments) {
		const fn = (att.filename ?? "").toLowerCase();
		const mt = (att.mimeType ?? "").toLowerCase();
		const raw = normalizeContent(att.content);
		if (!raw) continue;
		const looksGz = mt === TLSRPT_GZIP_MIME || fn.endsWith(".tlsrpt.gz");
		const looksJson =
			mt === TLSRPT_JSON_MIME || fn.endsWith(".tlsrpt.json") || fn.endsWith(".tlsrpt");
		if (looksGz) {
			try {
				const decompressed = await gunzip(raw);
				if (decompressed.byteLength > TLSRPT_MAX_DECOMPRESSED_BYTES) {
					return { ingested: false, reason: "decompressed payload exceeds 5MB cap" };
				}
				jsonText = bufferToText(decompressed);
				break;
			} catch (e) {
				console.error("tlsrpt gunzip failed:", (e as Error).message);
			}
		} else if (looksJson) {
			if (raw.byteLength > TLSRPT_MAX_DECOMPRESSED_BYTES) {
				return { ingested: false, reason: "payload exceeds 5MB cap" };
			}
			jsonText = bufferToText(raw);
			break;
		}
	}

	if (!jsonText) return { ingested: false, reason: "no decodable TLS-RPT payload" };

	const report = parseTlsRptJson(jsonText);
	if (!report) return { ingested: false, reason: "could not parse TLS-RPT JSON" };
	if (!report.domain) return { ingested: false, reason: "no policy_domain in report" };

	const stub = getMailboxStub(env, mailboxId);
	const records: Array<{
		id: string;
		policy_type: string | null;
		policy_domain: string | null;
		sending_mta_ip: string | null;
		receiving_mx_hostname: string | null;
		result_type: string | null;
		successful_session_count: number;
		failed_session_count: number;
	}> = [];

	for (const policy of report.policies) {
		records.push({
			id: crypto.randomUUID(),
			policy_type: policy.policy_type ?? null,
			policy_domain: policy.policy_domain ?? null,
			sending_mta_ip: null,
			receiving_mx_hostname: null,
			result_type: null,
			successful_session_count: policy.successful_session_count,
			failed_session_count: policy.failed_session_count,
		});
		for (const failure of policy.failure_details) {
			records.push({
				id: crypto.randomUUID(),
				policy_type: policy.policy_type ?? null,
				policy_domain: policy.policy_domain ?? null,
				sending_mta_ip: failure.sending_mta_ip ?? null,
				receiving_mx_hostname: failure.receiving_mx_hostname ?? null,
				result_type: failure.result_type ?? null,
				successful_session_count: 0,
				failed_session_count: failure.failed_session_count,
			});
		}
	}

	await stub.insertTlsRptReport(
		{
			id: messageId,
			received_at: new Date().toISOString(),
			org_name: report.org_name ?? null,
			report_id: report.report_id ?? null,
			domain: report.domain,
			date_range_begin: report.date_range_begin ?? null,
			date_range_end: report.date_range_end ?? null,
			contact_info: report.contact_info ?? null,
			raw_r2_key: null,
		},
		records,
	);

	return { ingested: true };
}

function normalizeContent(content: unknown): ArrayBuffer | null {
	if (!content) return null;
	if (content instanceof ArrayBuffer) return content;
	if (ArrayBuffer.isView(content)) {
		return (content.buffer as ArrayBuffer).slice(
			content.byteOffset,
			content.byteOffset + content.byteLength,
		);
	}
	if (typeof content === "string") {
		return new TextEncoder().encode(content).buffer as ArrayBuffer;
	}
	return null;
}
