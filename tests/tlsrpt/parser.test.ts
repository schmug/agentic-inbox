// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
	parseTlsRptJson,
	TLSRPT_MAX_DECOMPRESSED_BYTES,
} from "../../workers/tlsrpt/parser";

const FIXTURE_PATH = join(__dirname, "../../test/fixtures/tlsrpt-report.json");
const FIXTURE_TEXT = readFileSync(FIXTURE_PATH, "utf-8");

describe("parseTlsRptJson", () => {
	it("parses a well-formed RFC 8460 report", () => {
		const r = parseTlsRptJson(FIXTURE_TEXT);
		expect(r).not.toBeNull();
		expect(r!.org_name).toBe("Example Reporter Inc.");
		expect(r!.report_id).toBe("2026-04-01T00:00:00Z_example.com");
		expect(r!.contact_info).toBe("tlsrpt-noreply@reporter.example");
		expect(r!.date_range_begin).toBe("2026-04-01T00:00:00Z");
		expect(r!.date_range_end).toBe("2026-04-02T00:00:00Z");
		expect(r!.domain).toBe("example.com");
	});

	it("extracts per-policy summary counts", () => {
		const r = parseTlsRptJson(FIXTURE_TEXT)!;
		expect(r.policies).toHaveLength(1);
		expect(r.policies[0]).toMatchObject({
			policy_type: "sts",
			policy_domain: "example.com",
			successful_session_count: 142,
			failed_session_count: 3,
		});
	});

	it("extracts per-failure-detail entries", () => {
		const r = parseTlsRptJson(FIXTURE_TEXT)!;
		const failures = r.policies[0].failure_details;
		expect(failures).toHaveLength(2);
		expect(failures[0]).toMatchObject({
			result_type: "starttls-not-supported",
			sending_mta_ip: "203.0.113.10",
			receiving_mx_hostname: "mail.example.com",
			failed_session_count: 2,
		});
		expect(failures[1]).toMatchObject({
			result_type: "certificate-expired",
			sending_mta_ip: "198.51.100.42",
			failed_session_count: 1,
		});
	});

	it("returns null for invalid JSON", () => {
		expect(parseTlsRptJson("not json")).toBeNull();
		expect(parseTlsRptJson("{ unterminated")).toBeNull();
	});

	it("returns null for JSON that doesn't look like a TLS-RPT report", () => {
		expect(parseTlsRptJson("{}")).toBeNull();
		expect(parseTlsRptJson("[]")).toBeNull();
		expect(parseTlsRptJson('"a string"')).toBeNull();
		expect(parseTlsRptJson('{"some-other-shape": true}')).toBeNull();
	});

	it("accepts a sparse report with only top-level metadata", () => {
		const r = parseTlsRptJson('{"organization-name": "x", "report-id": "y"}');
		expect(r).not.toBeNull();
		expect(r!.org_name).toBe("x");
		expect(r!.policies).toEqual([]);
	});

	it("clamps absurd session counts at 1,000,000", () => {
		const r = parseTlsRptJson(JSON.stringify({
			"organization-name": "x",
			policies: [
				{
					policy: { "policy-type": "sts", "policy-domain": "example.com" },
					summary: {
						"total-successful-session-count": 99_999_999,
						"total-failure-session-count": 1,
					},
					"failure-details": [],
				},
			],
		}))!;
		expect(r.policies[0].successful_session_count).toBeLessThanOrEqual(1_000_000);
	});

	it("treats negative or non-numeric counts as 0", () => {
		const r = parseTlsRptJson(JSON.stringify({
			"organization-name": "x",
			policies: [
				{
					policy: { "policy-type": "sts", "policy-domain": "example.com" },
					summary: {
						"total-successful-session-count": -5,
						"total-failure-session-count": "abc",
					},
				},
			],
		}))!;
		expect(r.policies[0].successful_session_count).toBe(0);
		expect(r.policies[0].failed_session_count).toBe(0);
	});

	it("ignores non-object policy entries", () => {
		const r = parseTlsRptJson(JSON.stringify({
			"organization-name": "x",
			policies: ["string-not-policy", null, 42, {
				policy: { "policy-type": "sts", "policy-domain": "ok.com" },
				summary: {
					"total-successful-session-count": 1,
					"total-failure-session-count": 0,
				},
			}],
		}))!;
		expect(r.policies).toHaveLength(1);
		expect(r.policies[0].policy_domain).toBe("ok.com");
	});
});

describe("TLSRPT_MAX_DECOMPRESSED_BYTES", () => {
	it("is set to 5 MiB", () => {
		expect(TLSRPT_MAX_DECOMPRESSED_BYTES).toBe(5 * 1024 * 1024);
	});
});
