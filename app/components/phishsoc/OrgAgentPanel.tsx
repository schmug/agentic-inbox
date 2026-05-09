// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.
//
// Org-scope co-pilot — v2 (#212). Backed by a real `OrgAgent` durable-object
// with cross-mailbox tools (`get_org_overview`, `list_top_threats`,
// `search_cases_across_mailboxes`). Streaming via `useAgentChat` from
// `@cloudflare/ai-chat/react`, same as the per-mailbox `AgentPanel`.
//
// The header badge ("Org") and icon (BuildingsIcon) are intentionally distinct
// from AgentPanel's "AI" badge and RobotIcon so users know they're in the
// cross-mailbox context and per-mailbox actions aren't available here.

import { Badge, Button, Loader, Tooltip } from "@cloudflare/kumo";
import {
	ArrowUpIcon,
	BuildingsIcon,
	MagnifyingGlassIcon,
	ChartBarIcon,
	ShieldWarningIcon,
	TrashIcon,
	UserIcon,
	WrenchIcon,
	CheckCircleIcon,
	StopIcon,
} from "@phosphor-icons/react";
import { useEffect, useRef, useState } from "react";
import Markdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { useFeedback } from "~/lib/feedback";
import type { UIMessage } from "ai";

const ORG_TOOL_LABELS: Record<string, { label: string; icon: React.ReactNode }> = {
	get_org_overview: {
		label: "Fetching org overview",
		icon: <ChartBarIcon size={14} weight="bold" />,
	},
	list_top_threats: {
		label: "Loading top threats",
		icon: <ShieldWarningIcon size={14} weight="bold" />,
	},
	search_cases_across_mailboxes: {
		label: "Searching cases",
		icon: <MagnifyingGlassIcon size={14} weight="bold" />,
	},
};

const SUGGESTED_PROMPTS = [
	"What's the verdict mix in the last 24 hours?",
	"Show me the top threat categories this week",
	"How is the pipeline performing?",
	"Search for recent phishing cases",
] as const;

function ToolCallBadge({ toolName, state }: { toolName: string; state: string }) {
	const info = ORG_TOOL_LABELS[toolName] ?? {
		label: toolName,
		icon: <WrenchIcon size={14} weight="bold" />,
	};
	const isDone =
		state === "output-available" || state === "result" || state === "output-error";
	return (
		<div className="flex items-center gap-1.5 py-1 px-2 rounded bg-paper-3/50 text-xs">
			<span className="text-accent">{info.icon}</span>
			<span className="text-ink">{info.label}</span>
			{isDone ? (
				<CheckCircleIcon size={12} weight="fill" className="text-safe ml-auto" />
			) : (
				<Loader size="sm" className="ml-auto" />
			)}
		</div>
	);
}

function getToolNameFromPart(part: UIMessage["parts"][number]): string | null {
	if (part.type === "dynamic-tool") return (part as any).toolName ?? null;
	if (part.type.startsWith("tool-")) return part.type.replace("tool-", "");
	return null;
}

function MessageBubble({ message, isStreaming }: { message: UIMessage; isStreaming: boolean }) {
	const isUser = message.role === "user";
	return (
		<div className={`flex gap-2 ${isUser ? "flex-row-reverse" : "flex-row"}`}>
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
				className={`flex flex-col gap-1 max-w-[85%] min-w-0 ${
					isUser ? "items-end" : "items-start"
				}`}
			>
				{message.parts.map((part, i) => {
					const key = `${message.id}-part-${i}`;
					if (part.type === "text" && part.text.trim()) {
						return (
							<div
								key={key}
								className={`rounded-lg px-3 py-2 text-[13px] leading-relaxed break-words overflow-wrap-anywhere ${
									isUser
										? "bg-accent text-paper rounded-br-sm"
										: "bg-paper-3 text-ink border border-line rounded-bl-sm overflow-hidden"
								}`}
							>
								{isUser ? (
									part.text
								) : (
									<Markdown remarkPlugins={[remarkGfm]}>
										{part.text}
									</Markdown>
								)}
							</div>
						);
					}
					const toolName = getToolNameFromPart(part);
					if (toolName) {
						return (
							<ToolCallBadge
								key={key}
								toolName={toolName}
								state={(part as any).state ?? "running"}
							/>
						);
					}
					return null;
				})}
			</div>
		</div>
	);
}

// ── Connected panel (lazy-loaded hooks injected) ─────────────────────────────

function OrgAgentConnected({
	useAgent,
	useAgentChat,
}: {
	useAgent: typeof import("agents/react").useAgent;
	useAgentChat: typeof import("@cloudflare/ai-chat/react").useAgentChat;
}) {
	const scrollRef = useRef<HTMLDivElement>(null);
	const inputRef = useRef<HTMLTextAreaElement>(null);
	const [inputValue, setInputValue] = useState("");
	const feedback = useFeedback();

	// Single fixed-name instance — one OrgAgent per deployment.
	const agent = useAgent({ agent: "OrgAgent", name: "default" });
	const { messages, sendMessage, status, setMessages, stop } = useAgentChat({
		agent,
		onError: (error) => {
			console.error("org agent chat error:", error);
			feedback.error("Org agent request failed. Try again.");
		},
	});
	const isStreaming = status === "streaming" || status === "submitted";

	useEffect(() => {
		const el = scrollRef.current;
		if (el) el.scrollTop = el.scrollHeight;
	}, [messages]);

	useEffect(() => {
		inputRef.current?.focus();
	}, []);

	const handleSend = () => {
		const text = inputValue.trim();
		if (!text || isStreaming) return;
		setInputValue("");
		sendMessage({ text });
		if (inputRef.current) inputRef.current.style.height = "auto";
	};

	const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
		if (e.key === "Enter" && !e.shiftKey) {
			e.preventDefault();
			handleSend();
		}
	};

	return (
		<div data-testid="org-agent-panel" className="flex flex-col h-full">
			{/* Header — Org badge keeps it distinct from the per-mailbox AgentPanel */}
			<div className="flex items-center justify-between px-3 py-1.5 border-b border-line shrink-0">
				<div className="flex items-center gap-2">
					<Badge variant="primary">Org</Badge>
					<span className="text-xs text-ink-3">Org Co-pilot</span>
				</div>
				<div className="flex items-center gap-1">
					{isStreaming && <Loader size="sm" />}
					{messages.length > 0 && (
						<Tooltip content="Clear chat" asChild>
							<Button
								variant="ghost"
								shape="square"
								size="sm"
								icon={<TrashIcon size={14} />}
								onClick={() => {
									if (window.confirm("Clear org chat history?")) {
										setMessages([]);
									}
								}}
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
							<BuildingsIcon size={24} weight="duotone" className="text-accent" />
						</div>
						<p className="text-xs text-ink-3 text-center leading-relaxed px-4">
							I answer cross-mailbox questions using live data — verdict
							mix, top threats, pipeline health, and case search.
						</p>
						<div className="flex flex-col gap-1.5 w-full">
							{SUGGESTED_PROMPTS.map((prompt) => (
								<button
									key={prompt}
									type="button"
									onClick={() => sendMessage({ text: prompt })}
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
							<MessageBubble key={msg.id} message={msg} isStreaming={isStreaming} />
						))}
						{isStreaming && (
							<div className="flex gap-2">
								<div className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-paper-3 text-ink">
									<BuildingsIcon size={12} weight="bold" />
								</div>
								<div className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-paper-3 border border-line rounded-bl-sm">
									<Loader size="sm" />
									<span className="text-xs text-ink-3">Thinking…</span>
								</div>
							</div>
						)}
					</div>
				)}
			</div>

			{/* Input */}
			<div className="shrink-0 border-t border-line px-3 py-2">
				{isStreaming ? (
					<div className="flex justify-center">
						<Button
							variant="secondary"
							size="sm"
							icon={<StopIcon size={14} weight="fill" />}
							onClick={() => stop()}
						>
							Stop generating
						</Button>
					</div>
				) : (
					<div className="flex items-end gap-1.5">
						<textarea
							ref={inputRef}
							value={inputValue}
							onChange={(e) => setInputValue(e.target.value)}
							onKeyDown={handleKeyDown}
							placeholder="Ask about pipeline, verdicts, top threats…"
							rows={1}
							aria-label="Ask the org co-pilot"
							className="flex-1 resize-none rounded-lg border border-line bg-paper-2 px-3 py-2 text-xs text-ink placeholder:text-ink-3 focus:outline-none focus:ring-1 focus:ring-accent min-h-[36px] max-h-[100px]"
							style={{ height: "auto", overflow: "hidden" }}
							onInput={(e) => {
								const t = e.target as HTMLTextAreaElement;
								t.style.height = "auto";
								t.style.height = `${Math.min(t.scrollHeight, 100)}px`;
								t.style.overflow = t.scrollHeight > 100 ? "auto" : "hidden";
							}}
						/>
						<Button
							type="submit"
							variant="primary"
							shape="square"
							size="sm"
							disabled={!inputValue.trim()}
							icon={<ArrowUpIcon size={14} weight="bold" />}
							onClick={handleSend}
							aria-label="Send"
						/>
					</div>
				)}
			</div>
		</div>
	);
}

// ── Default export: lazy-loads agent hooks ───────────────────────────────────

export default function OrgAgentPanel() {
	const [hooks, setHooks] = useState<{
		useAgent: typeof import("agents/react").useAgent;
		useAgentChat: typeof import("@cloudflare/ai-chat/react").useAgentChat;
	} | null>(null);
	const [loadError, setLoadError] = useState<string | null>(null);

	useEffect(() => {
		Promise.all([import("agents/react"), import("@cloudflare/ai-chat/react")])
			.then(([a, c]) => setHooks({ useAgent: a.useAgent, useAgentChat: c.useAgentChat }))
			.catch((err) => {
				console.error("Failed to load org agent modules:", err);
				setLoadError("Failed to connect to org agent. Reload to retry.");
			});
	}, []);

	if (loadError) {
		return (
			<div className="flex flex-col items-center justify-center h-full gap-2 px-4 text-center">
				<span className="text-xs text-danger">{loadError}</span>
			</div>
		);
	}

	if (!hooks) {
		return (
			<div
				data-testid="org-agent-panel"
				className="flex flex-col items-center justify-center h-full gap-2"
			>
				<Loader size="base" />
				<span className="text-xs text-ink-3">Connecting…</span>
			</div>
		);
	}

	return <OrgAgentConnected useAgent={hooks.useAgent} useAgentChat={hooks.useAgentChat} />;
}
