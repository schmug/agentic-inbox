// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Org-scope durable-object agent (issue #212). Sibling to `EmailAgent`.
 *
 * Where `EmailAgent` operates on a single mailbox, `OrgAgent` operates on
 * org-aggregate data: it fans out to every mailbox DO it can reach via
 * `env.MAILBOX`, merges the results, and surfaces them to the operator
 * through three cross-mailbox tools:
 *
 *   - `get_org_overview`             — threats, verdict mix, pipeline health
 *   - `list_top_threats`             — top N threat categories by count
 *   - `search_cases_across_mailboxes`— full-text search over all mailboxes
 *
 * Auth/multi-tenant routing is intentionally deferred (tracked separately).
 * Today every authenticated caller sees the full org — the same boundary
 * that applies to the `/api/v1/org/overview` HTTP route.
 *
 * Name: a single fixed instance `"default"` — one OrgAgent per deployment.
 */

import { AIChatAgent } from "@cloudflare/ai-chat";
import { streamText, convertToModelMessages, stepCountIs } from "ai";
import { createWorkersAI } from "workers-ai-provider";
import { createOrgTools } from "./org-tools";
import type { Env } from "../types";

export { createOrgTools, fetchOrgSummaries } from "./org-tools";

const ORG_SYSTEM_PROMPT = `You are a cross-mailbox security analyst for a PhishSOC deployment. You have access to org-wide data spanning all mailboxes, threat verdicts, and pipeline metrics. Answer questions concisely and accurately using the tools provided.

Use tools to fetch live data before answering. Do not invent numbers or make up threat counts.

Your scope:
- Org-wide threat summaries (verdict mix, threats blocked, top categories)
- Pipeline health and latency across all mailboxes
- Cross-mailbox case search

You do NOT have access to individual email content or per-mailbox drafting tools — direct those to the per-mailbox Email Agent.`;

export class OrgAgent extends AIChatAgent<any> {
	async onChatMessage(onFinish: any) {
		const env = this.env as Env;
		const workersai = createWorkersAI({ binding: env.AI });
		const tools = createOrgTools(env);

		const result = streamText({
			model: workersai("@cf/meta/llama-3.3-70b-instruct-fp8-fast"),
			system: ORG_SYSTEM_PROMPT,
			messages: await convertToModelMessages(this.messages),
			tools,
			stopWhen: stepCountIs(5),
			onFinish,
		});

		return result.toUIMessageStreamResponse();
	}
}
