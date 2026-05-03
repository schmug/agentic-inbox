// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { describe, expect, it } from "vitest";
import {
	aggregateDomainStats,
	aggregateDomainsList,
	domainOf,
	emptyDmarcPosture,
	reduceDmarcAlignmentRate,
	type DmarcAlignmentTotals,
	type DomainMailboxSummary,
	type OrgMailboxSummary,
} from "../../workers/lib/dashboard-aggregation";

const NOW = new Date("2026-04-29T12:00:00Z");

function verdictRow(action: string, label: string, date = NOW.toISOString()) {
	return {
		date,
		security_verdict: JSON.stringify({
			action,
			classification: { label },
		}),
	};
}

function summary(partial: Partial<OrgMailboxSummary> = {}): OrgMailboxSummary {
	return {
		threatsBlocked: 0,
		threatsBlocked7d: 0,
		openCases: 0,
		hubContributions: 0,
		pipelineScan: { completed: 0, failed: 0 },
		verdictRows: [],
		...partial,
	};
}

function domainSummary(
	partial: Partial<DomainMailboxSummary> = {},
): DomainMailboxSummary {
	return {
		threatsBlocked: 0,
		threatsBlocked7d: 0,
		openCases: 0,
		hubContributions: 0,
		pipelineScan: { completed: 0, failed: 0 },
		verdictRows: [],
		...partial,
	};
}

describe("domainOf", () => {
	it("lowercases the part after the last @", () => {
		expect(domainOf("Alice@Acme.COM")).toBe("acme.com");
	});

	it("returns null for malformed input", () => {
		expect(domainOf("noatsymbol")).toBeNull();
		expect(domainOf("trailing@")).toBeNull();
		// Empty local part is also rejected — `@nopart` is not a valid address.
		expect(domainOf("@nopart")).toBeNull();
		expect(domainOf("")).toBeNull();
	});
});

describe("emptyDmarcPosture", () => {
	it("returns an all-null posture sentinel", () => {
		expect(emptyDmarcPosture()).toEqual({
			p: null,
			sp: null,
			pct: null,
			ruaConfigured: null,
			alignmentRate: null,
		});
	});
});

describe("aggregateDomainsList", () => {
	it("returns empty list when no mailboxes are provisioned", () => {
		expect(aggregateDomainsList({ mailboxes: [], summaries: [] })).toEqual([]);
	});

	it("groups mailboxes by lower-cased domain and sums counts", () => {
		const list = aggregateDomainsList({
			mailboxes: [
				{ id: "alice@ACME.com", email: "alice@ACME.com" },
				{ id: "bob@acme.com", email: "bob@acme.com" },
				{ id: "carol@example.org", email: "carol@example.org" },
			],
			summaries: [
				summary({
					threatsBlocked: 3,
					openCases: 2,
					verdictRows: [
						verdictRow("block", "phishing"),
						verdictRow("tag", "spam"),
					],
				}),
				summary({
					threatsBlocked: 1,
					openCases: 1,
					verdictRows: [verdictRow("quarantine", "phishing")],
				}),
				summary({
					threatsBlocked: 0,
					openCases: 0,
					verdictRows: [verdictRow("allow", "safe")],
				}),
			],
		});

		expect(list).toHaveLength(2);

		// Sorted alphabetically by domain.
		const acme = list.find((d) => d.domain === "acme.com")!;
		expect(acme).toMatchObject({
			domain: "acme.com",
			mailboxesCount: 2,
			threatsBlocked24h: 4,
			openCases: 3,
		});
		expect(acme.verdictMix).toEqual({
			safe: 0,
			suspicious: 0,
			phishing: 2,
			spam: 1,
			bec: 0,
		});

		const example = list.find((d) => d.domain === "example.org")!;
		expect(example).toMatchObject({
			domain: "example.org",
			mailboxesCount: 1,
			threatsBlocked24h: 0,
			openCases: 0,
		});
		expect(example.verdictMix).toEqual({
			safe: 1,
			suspicious: 0,
			phishing: 0,
			spam: 0,
			bec: 0,
		});
	});

	it("treats null (failed) summaries as zero contributions but still counts the mailbox", () => {
		const list = aggregateDomainsList({
			mailboxes: [
				{ id: "a@x.com", email: "a@x.com" },
				{ id: "b@x.com", email: "b@x.com" },
			],
			summaries: [
				summary({ threatsBlocked: 5, openCases: 1 }),
				null, // DO call failed
			],
		});
		expect(list).toHaveLength(1);
		expect(list[0]).toMatchObject({
			domain: "x.com",
			mailboxesCount: 2,
			threatsBlocked24h: 5,
			openCases: 1,
		});
	});

	it("skips mailboxes whose email has no domain part", () => {
		const list = aggregateDomainsList({
			mailboxes: [{ id: "malformed", email: "malformed" }],
			summaries: [summary({ threatsBlocked: 99 })],
		});
		expect(list).toEqual([]);
	});
});

describe("aggregateDomainStats", () => {
	it("returns null when no mailboxes match the domain", () => {
		expect(
			aggregateDomainStats({
				domain: "acme.com",
				mailboxes: [],
				summaries: [],
				now: NOW.toISOString(),
			}),
		).toBeNull();
	});

	it("sums per-mailbox counters and includes the mailbox roster", () => {
		const result = aggregateDomainStats({
			domain: "acme.com",
			mailboxes: [
				{ id: "alice@acme.com", email: "alice@acme.com", name: "Alice" },
				{ id: "bob@acme.com", email: "bob@acme.com", name: "Bob" },
			],
			summaries: [
				domainSummary({
					threatsBlocked: 3,
					threatsBlocked7d: 21,
					openCases: 2,
					verdictRows: [
						verdictRow("block", "phishing"),
						verdictRow("tag", "spam"),
					],
					recentCases: [
						{
							id: "C2",
							title: "Newer case",
							status: "open",
							updated_at: "2026-04-29T10:00:00Z",
						},
					],
				}),
				domainSummary({
					threatsBlocked: 1,
					threatsBlocked7d: 7,
					openCases: 0,
					verdictRows: [verdictRow("quarantine", "phishing")],
					recentCases: [
						{
							id: "C1",
							title: "Older case",
							status: "open",
							updated_at: "2026-04-28T10:00:00Z",
						},
					],
				}),
			],
			now: NOW.toISOString(),
		});

		expect(result).not.toBeNull();
		expect(result!.domain).toBe("acme.com");
		expect(result!.mailboxes).toHaveLength(2);
		expect(result!.threatsBlocked24h).toBe(4);
		expect(result!.threatsBlocked7d).toBe(28);
		expect(result!.openCases).toBe(2);
		expect(result!.verdictMix).toEqual({
			safe: 0,
			suspicious: 0,
			phishing: 2,
			spam: 1,
			bec: 0,
		});
		// Recent cases are merged across mailboxes and sorted newest-first.
		expect(result!.recentCases.map((c) => c.id)).toEqual(["C2", "C1"]);
	});

	it("falls back to the all-null DMARC posture when the handler doesn't supply one", () => {
		const result = aggregateDomainStats({
			domain: "acme.com",
			mailboxes: [
				{ id: "alice@acme.com", email: "alice@acme.com", name: "Alice" },
			],
			summaries: [domainSummary()],
			now: NOW.toISOString(),
		});
		expect(result!.dmarcPosture).toEqual({
			p: null,
			sp: null,
			pct: null,
			ruaConfigured: null,
			alignmentRate: null,
		});
	});

	it("threads a real DMARC posture through unchanged when supplied", () => {
		const result = aggregateDomainStats({
			domain: "acme.com",
			mailboxes: [
				{ id: "alice@acme.com", email: "alice@acme.com", name: "Alice" },
			],
			summaries: [domainSummary()],
			now: NOW.toISOString(),
			dmarcPosture: {
				p: "reject",
				sp: "quarantine",
				pct: 50,
				ruaConfigured: true,
				alignmentRate: 0.97,
			},
		});
		expect(result!.dmarcPosture).toEqual({
			p: "reject",
			sp: "quarantine",
			pct: 50,
			ruaConfigured: true,
			alignmentRate: 0.97,
		});
	});

	it("falls back to the all-null MTA-STS posture when the handler doesn't supply one (#165)", () => {
		const result = aggregateDomainStats({
			domain: "acme.com",
			mailboxes: [
				{ id: "alice@acme.com", email: "alice@acme.com", name: "Alice" },
			],
			summaries: [domainSummary()],
			now: NOW.toISOString(),
		});
		expect(result!.mtaStsPosture).toEqual({
			mode: null,
			mx: null,
			maxAge: null,
			id: null,
		});
	});

	it("threads a real MTA-STS posture through unchanged when supplied (#165)", () => {
		const result = aggregateDomainStats({
			domain: "acme.com",
			mailboxes: [
				{ id: "alice@acme.com", email: "alice@acme.com", name: "Alice" },
			],
			summaries: [domainSummary()],
			now: NOW.toISOString(),
			mtaStsPosture: {
				mode: "enforce",
				mx: ["mail.acme.com"],
				maxAge: 604800,
				id: "20251102",
			},
		});
		expect(result!.mtaStsPosture).toEqual({
			mode: "enforce",
			mx: ["mail.acme.com"],
			maxAge: 604800,
			id: "20251102",
		});
	});

	it("falls back to the all-null BIMI posture when the handler doesn't supply one (#166)", () => {
		const result = aggregateDomainStats({
			domain: "acme.com",
			mailboxes: [
				{ id: "alice@acme.com", email: "alice@acme.com", name: "Alice" },
			],
			summaries: [domainSummary()],
			now: NOW.toISOString(),
		});
		expect(result!.bimiPosture).toEqual({
			configured: null,
			hasLogo: null,
			hasVmc: null,
		});
	});

	it("threads a real BIMI posture through unchanged when supplied (#166)", () => {
		const result = aggregateDomainStats({
			domain: "acme.com",
			mailboxes: [
				{ id: "alice@acme.com", email: "alice@acme.com", name: "Alice" },
			],
			summaries: [domainSummary()],
			now: NOW.toISOString(),
			bimiPosture: {
				configured: true,
				hasLogo: true,
				hasVmc: true,
			},
		});
		expect(result!.bimiPosture).toEqual({
			configured: true,
			hasLogo: true,
			hasVmc: true,
		});
	});

	it("falls back to the all-null SPF posture when the handler doesn't supply one (#167)", () => {
		const result = aggregateDomainStats({
			domain: "acme.com",
			mailboxes: [
				{ id: "alice@acme.com", email: "alice@acme.com", name: "Alice" },
			],
			summaries: [domainSummary()],
			now: NOW.toISOString(),
		});
		expect(result!.spfPosture).toEqual({
			record: null,
			allQualifier: null,
			mechanismCount: null,
			includes: null,
			totalLookups: null,
			exceedsLimit: null,
		});
	});

	it("threads a real SPF posture through unchanged when supplied (#167)", () => {
		const result = aggregateDomainStats({
			domain: "acme.com",
			mailboxes: [
				{ id: "alice@acme.com", email: "alice@acme.com", name: "Alice" },
			],
			summaries: [domainSummary()],
			now: NOW.toISOString(),
			spfPosture: {
				record: "v=spf1 include:_spf.google.com -all",
				allQualifier: "-",
				mechanismCount: 2,
				includes: 1,
				totalLookups: 1,
				exceedsLimit: false,
			},
		});
		expect(result!.spfPosture.allQualifier).toBe("-");
		expect(result!.spfPosture.exceedsLimit).toBe(false);
	});

	it("falls back to the all-null TLS-RPT posture when the handler doesn't supply one (#168)", () => {
		const result = aggregateDomainStats({
			domain: "acme.com",
			mailboxes: [
				{ id: "alice@acme.com", email: "alice@acme.com", name: "Alice" },
			],
			summaries: [domainSummary()],
			now: NOW.toISOString(),
		});
		expect(result!.tlsRptPosture).toEqual({
			configured: null,
			endpoints: null,
		});
	});

	it("threads a real TLS-RPT posture through unchanged when supplied (#168)", () => {
		const result = aggregateDomainStats({
			domain: "acme.com",
			mailboxes: [
				{ id: "alice@acme.com", email: "alice@acme.com", name: "Alice" },
			],
			summaries: [domainSummary()],
			now: NOW.toISOString(),
			tlsRptPosture: {
				configured: true,
				endpoints: [
					"mailto:tlsrpt@acme.com",
					"https://reports.acme.com/tlsrpt",
				],
			},
		});
		expect(result!.tlsRptPosture).toEqual({
			configured: true,
			endpoints: [
				"mailto:tlsrpt@acme.com",
				"https://reports.acme.com/tlsrpt",
			],
		});
	});

	it("tolerates null (failed) summaries as zero contributions", () => {
		const result = aggregateDomainStats({
			domain: "acme.com",
			mailboxes: [
				{ id: "alice@acme.com", email: "alice@acme.com", name: "Alice" },
				{ id: "bob@acme.com", email: "bob@acme.com", name: "Bob" },
			],
			summaries: [
				domainSummary({ threatsBlocked: 7, openCases: 4 }),
				null,
			],
			now: NOW.toISOString(),
		});
		expect(result!.threatsBlocked24h).toBe(7);
		expect(result!.openCases).toBe(4);
		expect(result!.mailboxes).toHaveLength(2);
	});

	it("caps recentCases at 5", () => {
		const cases = Array.from({ length: 10 }, (_, i) => ({
			id: `C${i}`,
			title: `Case ${i}`,
			status: "open",
			updated_at: `2026-04-${String(20 + i).padStart(2, "0")}T10:00:00Z`,
		}));
		const result = aggregateDomainStats({
			domain: "acme.com",
			mailboxes: [
				{ id: "alice@acme.com", email: "alice@acme.com", name: "Alice" },
			],
			summaries: [domainSummary({ recentCases: cases })],
			now: NOW.toISOString(),
		});
		expect(result!.recentCases).toHaveLength(5);
		// Newest five (C9..C5).
		expect(result!.recentCases.map((c) => c.id)).toEqual([
			"C9",
			"C8",
			"C7",
			"C6",
			"C5",
		]);
	});
});

describe("reduceDmarcAlignmentRate", () => {
	function totals(aligned: number, total: number): DmarcAlignmentTotals {
		return { aligned, total };
	}

	it("returns null for an empty input", () => {
		expect(reduceDmarcAlignmentRate([])).toBeNull();
	});

	it("returns null when total is zero across the fan-out", () => {
		// No DMARC reports landed in the window — UI should surface
		// "unavailable" rather than a misleading 0%.
		expect(reduceDmarcAlignmentRate([totals(0, 0), totals(0, 0)])).toBeNull();
	});

	it("returns the sum-of-numerators / sum-of-denominators rate", () => {
		const rate = reduceDmarcAlignmentRate([
			totals(90, 100),
			totals(70, 100),
		]);
		expect(rate).toBeCloseTo(0.8);
	});

	it("skips null slots (failed DO calls) without skewing the rate", () => {
		const rate = reduceDmarcAlignmentRate([
			totals(95, 100),
			null,
			totals(90, 100),
		]);
		expect(rate).toBeCloseTo(0.925);
	});

	it("clamps a misbehaving DO that returns aligned > total to 1.0", () => {
		const rate = reduceDmarcAlignmentRate([totals(150, 100)]);
		expect(rate).toBe(1);
	});

	it("ignores totals with non-finite or negative components", () => {
		const rate = reduceDmarcAlignmentRate([
			totals(95, 100),
			{ aligned: Number.NaN, total: 100 },
			{ aligned: -1, total: 50 },
		]);
		expect(rate).toBeCloseTo(0.95);
	});
});
