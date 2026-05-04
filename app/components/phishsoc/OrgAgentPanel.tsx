// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.
//
// Org-scope co-pilot (#198). Sibling to `~/components/AgentPanel.tsx`. The
// per-mailbox agent is a real durable-object backed chat with tools that
// operate on a single mailbox's emails; this panel is intentionally a much
// thinner thing — a chat-shaped UI that synthesizes answers client-side
// from data already loaded by `useOrgOverview`. v1 has no backing agent,
// no streaming, no tools. The badge/header is deliberately distinct so
// users know they're in cross-mailbox context.
//
// v2 (out of scope here, tracked separately): a real org-scope DO with
// cross-mailbox tools, once the per-mailbox `EmailAgent` story stabilizes.

import { Badge, Button, Tooltip } from "@cloudflare/kumo";
import {
	ArrowUpIcon,
	BuildingsIcon,
	TrashIcon,
	UserIcon,
} from "@phosphor-icons/react";
import { useEffect, useRef, useState } from "react";
import { useOrgOverview } from "~/queries/org";
import type { OrgOverview } from "~/types";

interface ChatMessage {
	id: string;
	role: "user" | "assistant";
	text: string;
}

const SUGGESTED_PROMPTS = [
	"How is the pipeline doing?",
	"What's the verdict mix today?",
	"What are the top threats?",
	"How many threats blocked in the last 24h?",
] as const;

// Format a verdict-mix object as a short summary line. Zero totals get a
// dedicated "no traffic" answer rather than rendering "0 safe, 0 phishing…".
function formatVerdictMix(label: string, mix: OrgOverview["verdictMix"]): string {
	const total = mix.safe + mix.suspicious + mix.phishing + mix.spam + mix.bec;
	if (total === 0) return `${label}: no traffic recorded.`;
	const parts: string[] = [];
	if (mix.safe) parts.push(`${mix.safe} safe`);
	if (mix.suspicious) parts.push(`${mix.suspicious} suspicious`);
	if (mix.phishing) parts.push(`${mix.phishing} phishing`);
	if (mix.spam) parts.push(`${mix.spam} spam`);
	if (mix.bec) parts.push(`${mix.bec} BEC`);
	return `${label} (${total} total): ${parts.join(", ")}.`;
}

function formatPipeline(health: OrgOverview["pipelineHealth"]): string {
	if (health.runs24h === 0) return "Pipeline: no runs in the last 24h.";
	const successPct = health.successRate24h == null
		? "unknown success rate"
		: `${Math.round(health.successRate24h * 100)}% success`;
	const p95 = health.p95Ms == null ? "p95 unavailable" : `${health.p95Ms}ms p95`;
	return `Pipeline (24h): ${health.runs24h} runs, ${successPct}, ${p95}.`;
}

function formatTopThreats(threats: OrgOverview["topThreats"]): string {
	if (threats.length === 0) return "No threat categories recorded yet.";
	const top = threats.slice(0, 5);
	const lines = top.map((t) => `• ${t.category} — ${t.count}`);
	return `Top threats:\n${lines.join("\n")}`;
}

// Tiny deterministic router. Maps the user's prompt to a pre-formatted answer
// over `useOrgOverview` data. No LLM, no fetch — by design. v2 swaps this
// out for a real backing agent.
function answerForPrompt(prompt: string, data: OrgOverview | undefined): string {
	if (!data) {
		return "I don't have the org overview loaded yet. Try again in a moment.";
	}
	const q = prompt.toLowerCase();
	if (q.includes("pipeline") || q.includes("health") || q.includes("latency")) {
		return formatPipeline(data.pipelineHealth);
	}
	if (q.includes("verdict") || q.includes("mix")) {
		const today = formatVerdictMix("Verdict mix (24h)", data.verdictMix);
		const week = formatVerdictMix("Verdict mix (7d)", data.verdictMix7d);
		return `${today}\n\n${week}`;
	}
	if (q.includes("threat") || q.includes("phishing") || q.includes("attack")) {
		const blocked = `Threats blocked: ${data.threatsBlocked24h} (24h), ${data.threatsBlocked7d} (7d).`;
		return `${blocked}\n\n${formatTopThreats(data.topThreats)}`;
	}
	if (q.includes("blocked")) {
		return `Threats blocked: ${data.threatsBlocked24h} in the last 24h, ${data.threatsBlocked7d} in the last 7 days.`;
	}
	if (q.includes("case")) {
		return `Open cases across the org: ${data.openCasesTotal}.`;
	}
	if (q.includes("mailbox") || q.includes("domain")) {
		return `${data.mailboxesCount} mailbox${data.mailboxesCount === 1 ? "" : "es"} across ${data.domainsCount} domain${data.domainsCount === 1 ? "" : "s"}.`;
	}
	if (q.includes("hub") || q.includes("contribution")) {
		return `Hub contributions in the last 24h: ${data.hubContributions24h}.`;
	}
	// Fallback: render an at-a-glance summary so the user still gets something
	// grounded rather than a "I don't know" message.
	return [
		`Here's what I can see across the org:`,
		`• ${data.mailboxesCount} mailbox${data.mailboxesCount === 1 ? "" : "es"} across ${data.domainsCount} domain${data.domainsCount === 1 ? "" : "s"}`,
		`• ${data.threatsBlocked24h} threats blocked in the last 24h`,
		`• ${data.openCasesTotal} open case${data.openCasesTotal === 1 ? "" : "s"}`,
		"",
		`Try asking about pipeline health, verdict mix, or top threats.`,
	].join("\n");
}

let nextId = 0;
function makeId(prefix: string): string {
	nextId += 1;
	return `${prefix}-${nextId}`;
}

export default function OrgAgentPanel() {
	const { data } = useOrgOverview();
	const [messages, setMessages] = useState<ChatMessage[]>([]);
	const [input, setInput] = useState("");
	const scrollRef = useRef<HTMLDivElement>(null);

	useEffect(() => {
		// Pin the scroll to the bottom whenever a new message arrives — same
		// behavior as the per-mailbox AgentPanel.
		if (scrollRef.current) {
			scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
		}
	}, [messages.length]);

	function ask(prompt: string) {
		const trimmed = prompt.trim();
		if (!trimmed) return;
		const userMsg: ChatMessage = { id: makeId("u"), role: "user", text: trimmed };
		const reply: ChatMessage = {
			id: makeId("a"),
			role: "assistant",
			text: answerForPrompt(trimmed, data),
		};
		setMessages((prev) => [...prev, userMsg, reply]);
		setInput("");
	}

	function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
		e.preventDefault();
		ask(input);
	}

	return (
		<div data-testid="org-agent-panel" className="flex flex-col h-full">
			{/* Header — deliberately distinct from AgentPanel's "AI · Email Agent"
			    badge so users know this is org-scope (cross-mailbox) and there
			    are no per-mailbox tools available here. */}
			<div className="flex items-center justify-between px-3 py-1.5 border-b border-line shrink-0">
				<div className="flex items-center gap-2">
					<Badge variant="primary">Org</Badge>
					<span className="text-xs text-ink-3">Org Co-pilot</span>
				</div>
				<div className="flex items-center gap-1">
					{messages.length > 0 && (
						<Tooltip content="Clear chat" asChild>
							<Button
								variant="ghost"
								shape="square"
								size="sm"
								icon={<TrashIcon size={14} />}
								onClick={() => setMessages([])}
								aria-label="Clear chat"
							/>
						</Tooltip>
					)}
				</div>
			</div>

			{/* Messages */}
			<div ref={scrollRef} className="flex-1 overflow-y-auto px-3 py-4">
				{messages.length === 0 ? (
					<div className="flex flex-col items-center justify-center h-full gap-4">
						<div className="flex h-12 w-12 items-center justify-center rounded-xl bg-accent/10">
							<BuildingsIcon
								size={24}
								weight="duotone"
								className="text-accent"
							/>
						</div>
						<p className="text-xs text-ink-3 text-center leading-relaxed px-4">
							I answer org-wide questions from data already loaded on
							this page — verdict mix, top threats, pipeline health.
							Per-mailbox actions live in the mailbox co-pilot.
						</p>
						<div className="flex flex-col gap-1.5 w-full">
							{SUGGESTED_PROMPTS.map((prompt) => (
								<button
									key={prompt}
									type="button"
									onClick={() => ask(prompt)}
									className="text-left px-3 py-2 rounded-lg border border-line text-xs text-ink hover:bg-paper-2 hover:border-line-strong transition-colors cursor-pointer bg-transparent"
								>
									{prompt}
								</button>
							))}
						</div>
					</div>
				) : (
					<div className="flex flex-col gap-3">
						{messages.map((msg) => (
							<MessageBubble key={msg.id} message={msg} />
						))}
					</div>
				)}
			</div>

			{/* Composer */}
			<div className="border-t border-line p-3 shrink-0">
				<form onSubmit={handleSubmit} className="flex items-end gap-2">
					<textarea
						value={input}
						onChange={(e) => setInput(e.target.value)}
						onKeyDown={(e) => {
							if (e.key === "Enter" && !e.shiftKey) {
								e.preventDefault();
								ask(input);
							}
						}}
						placeholder="Ask about pipeline, verdicts, threats…"
						rows={1}
						aria-label="Ask the org co-pilot"
						className="flex-1 resize-none rounded-lg border border-line bg-paper-2 px-3 py-2 text-xs text-ink placeholder:text-ink-3 focus:outline-none focus:ring-1 focus:ring-accent min-h-[36px] max-h-[100px]"
					/>
					<Button
						type="submit"
						variant="primary"
						size="sm"
						shape="square"
						icon={<ArrowUpIcon size={14} weight="bold" />}
						disabled={!input.trim()}
						aria-label="Send"
					/>
				</form>
			</div>
		</div>
	);
}

function MessageBubble({ message }: { message: ChatMessage }) {
	const isUser = message.role === "user";
	return (
		<div className={`flex gap-2 ${isUser ? "flex-row-reverse" : ""}`}>
			<div
				className={`flex h-6 w-6 shrink-0 items-center justify-center rounded-full ${
					isUser ? "bg-accent text-paper" : "bg-paper-3 text-ink"
				}`}
			>
				{isUser ? (
					<UserIcon size={12} weight="bold" />
				) : (
					<BuildingsIcon size={12} weight="bold" />
				)}
			</div>
			<div
				className={`flex-1 min-w-0 rounded-lg px-3 py-2 text-xs leading-relaxed whitespace-pre-wrap ${
					isUser
						? "bg-accent/10 text-ink"
						: "bg-paper-2 text-ink"
				}`}
			>
				{message.text}
			</div>
		</div>
	);
}
