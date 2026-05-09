// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { describe, expect, it } from "vitest";
import { fetchOrgSummaries, createOrgTools } from "../../workers/agent/org-tools";
import type { OrgMailboxSummary } from "../../workers/lib/dashboard-aggregation";

// ── Shared fixtures ──────────────────────────────────────────────────────────

function makeSummary(overrides: Partial<OrgMailboxSummary> = {}): OrgMailboxSummary {
	return {
		mailboxId: "test@example.com",
		threatsBlocked: 5,
		threatsBlocked7d: 12,
		openCases: 3,
		hubContributions: 1,
		pipelineScan: { completed: 10, failed: 0 },
		pipelineDurationsMs: [120, 140, 160],
		verdictRows: [],
		verdictMix7d: { safe: 5, spam: 1, suspicious: 2, phishing: 2, bec: 0 },
		...overrides,
	};
}

function makeEnv(summaries: Array<OrgMailboxSummary | null>, mailboxIds = ["a@test.com", "b@test.com"]) {
	const mailboxObjects = mailboxIds.map((id) => ({
		key: `mailboxes/${id}.json`,
	}));

	const stubs = mailboxIds.map((_, i) => ({
		getDashboardSummary: () =>
			summaries[i] === null
				? Promise.reject(new Error("mailbox unavailable"))
				: Promise.resolve(summaries[i]),
		searchEmails: ({ query, limit }: { query: string; limit: number }) => {
			if (summaries[i] === null) return Promise.reject(new Error("mailbox unavailable"));
			return Promise.resolve(
				query === "phishing"
					? [
							{
								id: `email-${i}-1`,
								date: new Date(Date.now() - i * 1000).toISOString(),
								sender: `attacker${i}@evil.com`,
								subject: `Phishing attempt ${i}`,
								security_action: "quarantine",
								security_score: 82,
							},
					  ]
					: [],
			);
		},
	}));

	const env = {
		BUCKET: {
			list: () =>
				Promise.resolve({ objects: mailboxObjects }),
		},
		MAILBOX: {
			idFromName: (id: string) => id,
			get: (id: string) => stubs[mailboxIds.indexOf(id)] ?? stubs[0],
		},
	};

	return env as unknown as import("../../workers/types").Env;
}

// ── fetchOrgSummaries ────────────────────────────────────────────────────────

describe("fetchOrgSummaries", () => {
	it("returns summaries for all mailboxes when all succeed", async () => {
		const s0 = makeSummary({ mailboxId: "a@test.com", threatsBlocked: 3 });
		const s1 = makeSummary({ mailboxId: "b@test.com", threatsBlocked: 7 });
		const env = makeEnv([s0, s1]);

		const { mailboxes, summaries } = await fetchOrgSummaries(env);

		expect(mailboxes).toHaveLength(2);
		expect(summaries).toHaveLength(2);
		expect(summaries[0]?.threatsBlocked).toBe(3);
		expect(summaries[1]?.threatsBlocked).toBe(7);
	});

	it("returns null for a failed mailbox and keeps the rest", async () => {
		const s0 = makeSummary({ mailboxId: "a@test.com" });
		// second mailbox stub intentionally returns null (simulate DO error)
		const env = makeEnv([s0, null]);

		const { summaries } = await fetchOrgSummaries(env);

		expect(summaries[0]).not.toBeNull();
		expect(summaries[1]).toBeNull();
	});

	it("defaults threatsBlocked7d to 0 when absent from the DO response", async () => {
		const raw = makeSummary({ mailboxId: "a@test.com" }) as any;
		delete raw.threatsBlocked7d;
		const env = makeEnv([raw, null]);

		const { summaries } = await fetchOrgSummaries(env);

		expect(summaries[0]?.threatsBlocked7d).toBe(0);
	});
});

// ── get_org_overview tool ────────────────────────────────────────────────────

describe("get_org_overview tool — tool-call round-trip", () => {
	it("aggregates threat counts across all mailboxes", async () => {
		const s0 = makeSummary({ threatsBlocked: 4, threatsBlocked7d: 10 });
		const s1 = makeSummary({ threatsBlocked: 6, threatsBlocked7d: 14 });
		const env = makeEnv([s0, s1]);
		const tools = createOrgTools(env);

		const result = (await tools.get_org_overview.execute()) as any;

		expect(result.threatsBlocked24h).toBe(10);
		expect(result.threatsBlocked7d).toBe(24);
		expect(result.mailboxesCount).toBe(2);
	});

	it("sums open cases across mailboxes", async () => {
		const s0 = makeSummary({ openCases: 2 });
		const s1 = makeSummary({ openCases: 5 });
		const env = makeEnv([s0, s1]);
		const tools = createOrgTools(env);

		const result = (await tools.get_org_overview.execute()) as any;

		expect(result.openCasesTotal).toBe(7);
	});

	it("returns pipelineHealth shape", async () => {
		const env = makeEnv([makeSummary(), makeSummary()]);
		const tools = createOrgTools(env);

		const result = (await tools.get_org_overview.execute()) as any;

		expect(result).toHaveProperty("pipelineHealth");
		expect(result.pipelineHealth).toHaveProperty("runs24h");
	});
});

// ── list_top_threats tool ────────────────────────────────────────────────────

describe("list_top_threats tool", () => {
	it("returns at most `limit` entries", async () => {
		// Supply verdictRows with multiple threat labels to generate topThreats
		const rows = Array.from({ length: 20 }, (_, i) => ({
			date: new Date().toISOString(),
			security_verdict: JSON.stringify({
				action: "quarantine",
				score: 75,
				classification: { label: i % 2 === 0 ? "phishing" : "bec" },
			}),
		}));
		const summary = makeSummary({ verdictRows: rows });
		const env = makeEnv([summary, summary]);
		const tools = createOrgTools(env);

		const result = (await tools.list_top_threats.execute({ limit: 2 })) as any[];

		expect(result.length).toBeLessThanOrEqual(2);
	});

	it("returns an array", async () => {
		const env = makeEnv([makeSummary(), makeSummary()]);
		const tools = createOrgTools(env);

		const result = await tools.list_top_threats.execute({ limit: 5 });

		expect(Array.isArray(result)).toBe(true);
	});
});

// ── search_cases_across_mailboxes tool ───────────────────────────────────────

describe("search_cases_across_mailboxes tool", () => {
	it("merges results from all mailboxes, sorted newest-first", async () => {
		const env = makeEnv([makeSummary(), makeSummary()]);
		const tools = createOrgTools(env);

		const result = (await tools.search_cases_across_mailboxes.execute({
			query: "phishing",
			limit: 10,
		})) as any[];

		expect(result.length).toBe(2); // one match from each mailbox
		// Verify the first result is newer (descending date sort)
		const dates = result.map((r) => Date.parse(r.date));
		expect(dates[0]).toBeGreaterThanOrEqual(dates[1]);
	});

	it("respects the limit parameter", async () => {
		const env = makeEnv([makeSummary(), makeSummary()]);
		const tools = createOrgTools(env);

		const result = (await tools.search_cases_across_mailboxes.execute({
			query: "phishing",
			limit: 1,
		})) as any[];

		expect(result.length).toBeLessThanOrEqual(1);
	});

	it("returns empty array when no matches", async () => {
		const env = makeEnv([makeSummary(), makeSummary()]);
		const tools = createOrgTools(env);

		const result = (await tools.search_cases_across_mailboxes.execute({
			query: "no-match-query",
			limit: 10,
		})) as any[];

		expect(result).toEqual([]);
	});

	it("tolerates a failed mailbox and still returns results from healthy ones", async () => {
		// Second mailbox returns null (simulates DO error in searchEmails)
		const env = makeEnv([makeSummary(), null]);
		const tools = createOrgTools(env);

		// Should not throw; just return results from the healthy mailbox
		const result = (await tools.search_cases_across_mailboxes.execute({
			query: "phishing",
			limit: 10,
		})) as any[];

		expect(Array.isArray(result)).toBe(true);
	});
});
