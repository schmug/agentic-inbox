// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import type { Email } from "postal-mime";
import {
	TLSRPT_MAX_DECOMPRESSED_BYTES,
} from "../../workers/tlsrpt/parser";
import {
	ingestTlsRptReport,
	isTlsRptReport,
} from "../../workers/tlsrpt/ingest";

const FIXTURE_PATH = join(__dirname, "../../test/fixtures/tlsrpt-report.json");
const FIXTURE_BUFFER = readFileSync(FIXTURE_PATH);

function makeEmail(overrides: Partial<Email> = {}): Email {
	return {
		from: { address: "tlsrpt@reporter.example", name: "" },
		subject: "Report Domain: example.com Submitter: reporter.example",
		attachments: [],
		headers: [],
		...overrides,
	} as unknown as Email;
}

describe("isTlsRptReport", () => {
	it("matches an attachment with application/tlsrpt+gzip mime", () => {
		const e = makeEmail({
			subject: "ignore",
			attachments: [
				{ filename: "report.gz", mimeType: "application/tlsrpt+gzip", content: new Uint8Array() } as never,
			],
		});
		expect(isTlsRptReport(e)).toBe(true);
	});

	it("matches an attachment with application/tlsrpt+json mime", () => {
		const e = makeEmail({
			subject: "ignore",
			attachments: [
				{ filename: "x.json", mimeType: "application/tlsrpt+json", content: new Uint8Array() } as never,
			],
		});
		expect(isTlsRptReport(e)).toBe(true);
	});

	it("matches a `.tlsrpt.json` filename even when mime is generic", () => {
		const e = makeEmail({
			subject: "ignore",
			attachments: [
				{ filename: "example.com!1.tlsrpt.json", mimeType: "application/octet-stream", content: new Uint8Array() } as never,
			],
		});
		expect(isTlsRptReport(e)).toBe(true);
	});

	it("matches the RFC 8460 'TLS Report' subject convention", () => {
		const e = makeEmail({
			subject: "Report Domain: example.com Submitter: reporter.example Report-ID: <abc> -- TLS Report",
			attachments: [],
		});
		expect(isTlsRptReport(e)).toBe(true);
	});

	it("does NOT match a DMARC RUA aggregate report (`.xml.gz`)", () => {
		// Regression guard: TLS-RPT detection must not steal DMARC reports
		// from `isDmarcReport`.
		const e = makeEmail({
			subject: "Report Domain: example.com Submitter: google.com",
			attachments: [
				{ filename: "google.com!example.com!1.xml.gz", mimeType: "application/gzip", content: new Uint8Array() } as never,
			],
		});
		expect(isTlsRptReport(e)).toBe(false);
	});

	it("does NOT match plain mail with no TLS-RPT signals", () => {
		const e = makeEmail({
			subject: "hello there",
			attachments: [
				{ filename: "report.pdf", mimeType: "application/pdf", content: new Uint8Array() } as never,
			],
		});
		expect(isTlsRptReport(e)).toBe(false);
	});
});

describe("ingestTlsRptReport", () => {
	it("rejects a JSON payload above the 5MB cap before persisting", async () => {
		const oversized = new Uint8Array(TLSRPT_MAX_DECOMPRESSED_BYTES + 1);
		const insertSpy = vi.fn();
		const stub = mailboxStubMock(insertSpy);
		const e = makeEmail({
			attachments: [
				{ filename: "huge.tlsrpt.json", mimeType: "application/tlsrpt+json", content: oversized } as never,
			],
		});

		const result = await ingestTlsRptReport(envWith(stub), "mb-1", "msg-1", e);
		expect(result.ingested).toBe(false);
		expect(result.reason).toMatch(/5MB cap/);
		expect(insertSpy).not.toHaveBeenCalled();
	});

	it("returns ingested=false when no TLS-RPT payload is decodable", async () => {
		const insertSpy = vi.fn();
		const stub = mailboxStubMock(insertSpy);
		const e = makeEmail({
			attachments: [
				{ filename: "irrelevant.txt", mimeType: "text/plain", content: new Uint8Array([1, 2, 3]) } as never,
			],
		});

		const result = await ingestTlsRptReport(envWith(stub), "mb-1", "msg-1", e);
		expect(result.ingested).toBe(false);
		expect(insertSpy).not.toHaveBeenCalled();
	});

	it("persists per-policy summary plus per-failure-detail rows", async () => {
		const insertSpy = vi.fn();
		const stub = mailboxStubMock(insertSpy);
		const e = makeEmail({
			attachments: [
				{
					filename: "example.com.tlsrpt.json",
					mimeType: "application/tlsrpt+json",
					content: new Uint8Array(FIXTURE_BUFFER),
				} as never,
			],
		});

		const result = await ingestTlsRptReport(envWith(stub), "mb-1", "msg-1", e);
		expect(result.ingested).toBe(true);
		expect(insertSpy).toHaveBeenCalledTimes(1);
		const [report, records] = insertSpy.mock.calls[0];
		expect(report.id).toBe("msg-1");
		expect(report.domain).toBe("example.com");
		expect(report.org_name).toBe("Example Reporter Inc.");
		// 1 policy-summary row + 2 failure-detail rows
		expect(records).toHaveLength(3);
		const summary = records.find((r: { sending_mta_ip: string | null }) => r.sending_mta_ip === null);
		expect(summary).toMatchObject({
			policy_domain: "example.com",
			policy_type: "sts",
			successful_session_count: 142,
			failed_session_count: 3,
		});
		const failureRows = records.filter((r: { sending_mta_ip: string | null }) => r.sending_mta_ip !== null);
		expect(failureRows.map((r: { sending_mta_ip: string | null }) => r.sending_mta_ip).sort()).toEqual([
			"198.51.100.42",
			"203.0.113.10",
		]);
	});
});

function mailboxStubMock(insertSpy: ReturnType<typeof vi.fn>) {
	return {
		insertTlsRptReport: insertSpy,
	};
}

function envWith(stub: { insertTlsRptReport: ReturnType<typeof vi.fn> }) {
	return {
		MAILBOX: {
			idFromName: () => "id",
			get: () => stub,
		},
	} as never;
}
