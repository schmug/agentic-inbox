// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Shared search-results helpers used by both the per-mailbox and org-scope
 * search pages so the empty/no-results affordance + query highlighting stay
 * identical across the two surfaces (#197).
 */

import { MagnifyingGlassIcon } from "@phosphor-icons/react";

export function highlightTerms(text: string, query: string): React.ReactNode {
	if (!query || !text) return text;
	const freeText = query
		.replace(/\b(?:from|to|subject|in|is|has|before|after):"[^"]*"/gi, "")
		.replace(/\b(?:from|to|subject|in|is|has|before|after):\S+/gi, "")
		.trim();
	if (!freeText) return text;
	try {
		const escaped = freeText.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
		const regex = new RegExp(`(${escaped})`, "gi");
		const parts = text.split(regex);
		if (parts.length === 1) return text;
		// Avoid `regex.test()` with the `g` flag — its stateful `lastIndex`
		// produces alternating true/false results across iterations.
		const lowerEscaped = escaped.toLowerCase();
		return parts.map((part, i) =>
			part.toLowerCase() === lowerEscaped ? (
				<mark key={i} className="bg-accent-tint text-accent-ink rounded-sm px-0.5">{part}</mark>
			) : (
				part
			),
		);
	} catch {
		return text;
	}
}

export function SearchEmptyState({ query }: { query: string }) {
	return (
		<div className="flex flex-col items-center justify-center py-24 px-6 text-center">
			<div className="mb-4">
				<MagnifyingGlassIcon size={48} weight="thin" className="text-ink-3" />
			</div>
			<h3 className="text-base font-semibold text-ink mb-1.5">No results found</h3>
			<p className="text-sm text-ink-3 max-w-xs">
				{query
					? `Nothing matched "${query}". Try different keywords or check your spelling.`
					: "Enter a search term to find emails by subject, sender, or content."}
			</p>
			{query && (
				<p className="text-xs text-ink-3 mt-3 max-w-sm">
					Tip: Use operators like{" "}
					<code className="bg-paper-3 px-1 rounded pp-mono">from:name</code>,{" "}
					<code className="bg-paper-3 px-1 rounded pp-mono">is:unread</code>,{" "}
					<code className="bg-paper-3 px-1 rounded pp-mono">has:attachment</code>,{" "}
					<code className="bg-paper-3 px-1 rounded pp-mono">before:2025-01-01</code>
				</p>
			)}
		</div>
	);
}
