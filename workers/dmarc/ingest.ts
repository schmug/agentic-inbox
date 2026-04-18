// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * DMARC aggregate-report ingestion.
 *
 * DMARC reports arrive as email with a gzipped XML attachment. We divert
 * them out of the normal security pipeline (no sense classifying machine
 * reports as phish) and feed them into the per-mailbox dashboard DB.
 */

import type { Email } from "postal-mime";
import type { Env } from "../types";
import { getMailboxStub } from "../lib/email-helpers";
import { bufferToXmlText, gunzip, parseDmarcXml } from "./parser";

/** Heuristic: does this parsed email look like a DMARC aggregate report? */
export function isDmarcReport(parsed: Email): boolean {
	const from = parsed.from?.address?.toLowerCase() ?? "";
	const subject = (parsed.subject ?? "").toLowerCase();
	if (from.includes("dmarc") || from.includes("noreply-dmarc")) return true;
	if (subject.startsWith("report domain:") || subject.includes("dmarc aggregate report")) return true;
	for (const a of parsed.attachments ?? []) {
		const fn = (a.filename ?? "").toLowerCase();
		if (fn.endsWith(".xml.gz") || fn.endsWith(".xml.zip")) return true;
		const mt = (a.mimeType ?? "").toLowerCase();
		if (mt === "application/gzip" || mt === "application/zip" || mt === "application/xml") {
			if (fn.includes("!")) return true; // DMARC RUA conventionally names `example.com!google.com!start!end.xml.gz`
		}
	}
	return false;
}

export async function ingestDmarcReport(
	env: Env,
	mailboxId: string,
	messageId: string,
	parsed: Email,
): Promise<{ ingested: boolean; reason?: string }> {
	const attachments = parsed.attachments ?? [];
	let xmlText: string | null = null;

	for (const att of attachments) {
		const fn = (att.filename ?? "").toLowerCase();
		const raw = normalizeContent(att.content);
		if (!raw) continue;
		if (fn.endsWith(".xml.gz") || (att.mimeType ?? "").toLowerCase() === "application/gzip") {
			try {
				const decompressed = await gunzip(raw);
				xmlText = bufferToXmlText(decompressed);
				break;
			} catch (e) {
				console.error("dmarc gunzip failed:", (e as Error).message);
			}
		} else if (fn.endsWith(".xml")) {
			xmlText = bufferToXmlText(raw);
			break;
		}
		// .xml.zip: deferred — zip needs a proper parser. See plan M4 notes.
	}

	if (!xmlText) return { ingested: false, reason: "no decodable XML attachment" };

	const report = parseDmarcXml(xmlText);
	if (!report.policy_domain) return { ingested: false, reason: "no policy_domain in XML" };

	const stub = getMailboxStub(env, mailboxId);
	await stub.insertDmarcReport({
		id: messageId,
		received_at: new Date().toISOString(),
		org_name: report.org_name ?? null,
		report_id: report.report_id ?? null,
		domain: report.policy_domain,
		date_range_begin: report.date_range_begin ?? null,
		date_range_end: report.date_range_end ?? null,
		policy_p: report.policy_p ?? null,
		raw_r2_key: null,
	}, report.records.map((r) => ({
		id: crypto.randomUUID(),
		source_ip: r.source_ip,
		count: r.count,
		disposition: r.disposition ?? null,
		dkim_result: r.dkim_result ?? null,
		spf_result: r.spf_result ?? null,
		header_from: r.header_from ?? null,
	})));

	return { ingested: true };
}

function normalizeContent(content: unknown): ArrayBuffer | null {
	if (!content) return null;
	if (content instanceof ArrayBuffer) return content;
	if (ArrayBuffer.isView(content)) {
		return (content.buffer as ArrayBuffer).slice(content.byteOffset, content.byteOffset + content.byteLength);
	}
	if (typeof content === "string") {
		return new TextEncoder().encode(content).buffer as ArrayBuffer;
	}
	return null;
}
