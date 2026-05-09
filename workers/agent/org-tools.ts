// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Cross-mailbox tool definitions for OrgAgent (issue #212).
 *
 * Extracted into a separate module so the tool logic is importable by tests
 * without pulling in the Cloudflare Workers runtime (`@cloudflare/ai-chat`,
 * `workers-ai-provider`) that can't run under Node/Vitest.
 */

import { z } from "zod";
import { listMailboxes } from "../lib/email-helpers";
import { aggregateOrgOverview } from "../lib/dashboard-aggregation";
import type { OrgMailboxSummary } from "../lib/dashboard-aggregation";
import type { Env } from "../types";

/**
 * Fan out to all mailbox DOs and collect their dashboard summaries.
 * Tolerates individual mailbox failures (returns null for failed mailboxes).
 */
export async function fetchOrgSummaries(
	env: Env,
): Promise<{ mailboxes: { id: string; email: string }[]; summaries: Array<OrgMailboxSummary | null> }> {
	const mailboxes = await listMailboxes(env.BUCKET);
	const settled = await Promise.allSettled(
		mailboxes.map((m) =>
			(env.MAILBOX.get(env.MAILBOX.idFromName(m.id)) as any).getDashboardSummary() as Promise<OrgMailboxSummary>,
		),
	);
	const summaries = settled.map((r) => {
		if (r.status !== "fulfilled") return null;
		const v = r.value;
		return { ...v, threatsBlocked7d: v.threatsBlocked7d ?? 0 } as OrgMailboxSummary;
	});
	return { mailboxes, summaries };
}

export function createOrgTools(env: Env) {
	return {
		get_org_overview: {
			description:
				"Return a high-level org summary: threats blocked, open cases, mailbox count, verdict mix (24h and 7d), and pipeline health (success rate, p95 latency). Use this first to orient before answering broad questions.",
			inputSchema: z.object({}),
			execute: async (): Promise<unknown> => {
				const { mailboxes, summaries } = await fetchOrgSummaries(env);
				const overview = aggregateOrgOverview({ mailboxes, summaries });
				return {
					mailboxesCount: overview.mailboxesCount,
					domainsCount: overview.domainsCount,
					threatsBlocked24h: overview.threatsBlocked24h,
					threatsBlocked7d: overview.threatsBlocked7d,
					openCasesTotal: overview.openCasesTotal,
					hubContributions24h: overview.hubContributions24h,
					verdictMix24h: overview.verdictMix,
					verdictMix7d: overview.verdictMix7d,
					pipelineHealth: overview.pipelineHealth,
				};
			},
		},

		list_top_threats: {
			description:
				"Return the top threat categories (e.g. phishing, bec, spam) ranked by count across all mailboxes, with up to 3 representative case IDs per category.",
			inputSchema: z.object({
				limit: z
					.number()
					.int()
					.min(1)
					.max(20)
					.optional()
					.describe("Maximum number of threat categories to return (default 5)"),
			}),
			execute: async ({ limit = 5 }: { limit?: number }): Promise<unknown> => {
				const { mailboxes, summaries } = await fetchOrgSummaries(env);
				const overview = aggregateOrgOverview({ mailboxes, summaries, topN: limit });
				return overview.topThreats.slice(0, limit);
			},
		},

		search_cases_across_mailboxes: {
			description:
				"Search for cases (emails with security verdicts) across all mailboxes. Returns matching emails with their mailbox, verdict, score, and subject. Use for questions like 'show me recent phishing cases' or 'find emails from attacker@evil.com'.",
			inputSchema: z.object({
				query: z.string().describe("Full-text search query"),
				limit: z
					.number()
					.int()
					.min(1)
					.max(50)
					.optional()
					.describe("Maximum results to return (default 10)"),
			}),
			execute: async ({
				query,
				limit = 10,
			}: {
				query: string;
				limit?: number;
			}): Promise<unknown> => {
				const mailboxes = await listMailboxes(env.BUCKET);
				const perMailboxCap = Math.max(limit, 25);
				const settled = await Promise.allSettled(
					mailboxes.map(async (m) => {
						const stub = env.MAILBOX.get(env.MAILBOX.idFromName(m.id)) as any;
						const emails = await stub.searchEmails({
							query,
							page: 1,
							limit: perMailboxCap,
						});
						return (emails as any[]).map((e: any) => ({
							...e,
							mailbox_id: m.id,
							mailbox_email: m.email,
						}));
					}),
				);
				const rows: any[] = [];
				for (const r of settled) {
					if (r.status === "fulfilled") rows.push(...r.value);
				}
				rows.sort((a, b) => {
					const ta = a.date ? Date.parse(a.date) : 0;
					const tb = b.date ? Date.parse(b.date) : 0;
					return tb - ta;
				});
				return rows.slice(0, limit).map((r) => ({
					id: r.id,
					mailbox: r.mailbox_email ?? r.mailbox_id,
					date: r.date,
					sender: r.sender,
					subject: r.subject,
					verdict: r.security_action ?? null,
					score: r.security_score ?? null,
				}));
			},
		},
	};
}
