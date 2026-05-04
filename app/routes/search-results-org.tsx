// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { Badge, Button, Pagination, Tooltip } from "@cloudflare/kumo";
import { ArrowLeftIcon } from "@phosphor-icons/react";
import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate, useSearchParams } from "react-router";
import Shell from "~/components/phishsoc/Shell";
import { useFeedback } from "~/lib/feedback";
import { formatListDate, getSnippetText } from "~/lib/utils";
import { useOrgSearchEmails, SEARCH_PAGE_SIZE, type OrgSearchResultRow } from "~/queries/search";
import { highlightTerms, SearchEmptyState } from "./search-shared";

export default function SearchResultsOrgRoute() {
	const [searchParams] = useSearchParams();
	const navigate = useNavigate();
	const urlQuery = searchParams.get("q") || "";
	const [page, setPage] = useState(1);
	const searchKey = useMemo(() => `_org::${urlQuery}`, [urlQuery]);
	const prevSearchKeyRef = useRef(searchKey);
	const searchChanged = prevSearchKeyRef.current !== searchKey;
	const currentPage = searchChanged ? 1 : page;

	useEffect(() => {
		if (!searchChanged) return;
		prevSearchKeyRef.current = searchKey;
		setPage(1);
	}, [searchChanged, searchKey]);

	const { data: searchData, isLoading, isError } = useOrgSearchEmails(urlQuery, currentPage);
	const results = searchData?.results ?? [];
	const totalCount = searchData?.totalCount ?? 0;

	const feedback = useFeedback();
	useEffect(() => {
		if (isError) feedback.error("Search failed. Try again.");
	}, [isError, feedback]);

	// Org-scope rows can't open an in-page panel — selection state lives in
	// per-mailbox UI stores. Drop the user into the originating mailbox's
	// search page (same query) so they can interact with the email there.
	const handleRowClick = (email: OrgSearchResultRow) => {
		navigate(
			`/mailbox/${encodeURIComponent(email.mailbox_id)}/search?q=${encodeURIComponent(urlQuery)}`,
		);
	};

	const folderDisplayName = (name: string | null | undefined): string => {
		if (!name) return "";
		const map: Record<string, string> = { inbox: "Inbox", sent: "Sent", draft: "Drafts", archive: "Archive", trash: "Trash", quarantine: "Quarantine" };
		return map[name.toLowerCase()] || name;
	};

	return (
		<Shell>
			<div className="flex flex-col h-full">
				<div className="flex items-center gap-2 px-4 py-3.5 border-b border-line shrink-0 md:px-5">
					<Tooltip content="Back" side="bottom" asChild><Button variant="ghost" shape="square" size="sm" icon={<ArrowLeftIcon size={18} />} onClick={() => navigate("/")} aria-label="Back" /></Tooltip>
					<div className="min-w-0 flex-1">
						<h1 className="pp-serif text-ink truncate">Search Results</h1>
						{!isLoading && (
							<span className="text-sm text-ink-3">
								{totalCount} result{totalCount !== 1 ? "s" : ""} across all mailboxes{urlQuery ? ` for "${urlQuery}"` : ""}
							</span>
						)}
					</div>
				</div>
				<div className="flex-1 overflow-y-auto">
					{isLoading ? (
						<div className="divide-y divide-line">
							{Array.from({ length: 5 }).map((_, i) => (
								<div key={i} className="flex items-center gap-3 px-4 py-2.5 md:px-5 md:py-3 animate-pulse">
									<div className="w-2.5 shrink-0" />
									<div className="flex-1 min-w-0">
										<div className="flex items-center gap-2">
											<div className="h-3 w-24 rounded bg-paper-3" />
											<div className="h-3 flex-1 rounded bg-paper-3" />
											<div className="h-3 w-12 rounded bg-paper-3 ml-auto" />
										</div>
										<div className="h-2.5 w-3/4 rounded bg-paper-3 mt-2" />
									</div>
								</div>
							))}
						</div>
					) : results.length === 0 ? (
						<SearchEmptyState query={urlQuery} />
					) : (
						<div>{results.map((email) => {
							const snippet = getSnippetText(email.snippet, 120);
							const folderName = (email as OrgSearchResultRow & { folder_name?: string }).folder_name;
							return (
								<div key={`${email.mailbox_id}:${email.id}`} role="button" tabIndex={0} onClick={() => handleRowClick(email)} onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); handleRowClick(email); } }} className="group flex items-center gap-3 w-full text-left cursor-pointer transition-colors border-b border-line px-4 py-2.5 md:px-5 md:py-3 hover:bg-paper-2">
									<div className="w-2.5 shrink-0 flex justify-center">{!email.read && <div className="h-2 w-2 rounded-full bg-accent" />}</div>
									<div className="min-w-0 flex-1">
										<div className="flex items-center gap-2">
											<span className={`truncate text-sm ${!email.read ? "font-semibold text-ink" : "text-ink"}`}>{highlightTerms(email.sender.split("@")[0], urlQuery)}</span>
											<Badge variant="outline">{email.mailbox_email}</Badge>
											{folderName && <Badge variant="outline">{folderDisplayName(folderName)}</Badge>}
											<span className="text-sm text-ink-3 shrink-0 ml-auto">{formatListDate(email.date)}</span>
										</div>
										<div className={`truncate text-sm mt-0.5 ${!email.read ? "font-medium text-ink" : "text-ink-3"}`}>{highlightTerms(email.subject, urlQuery)}</div>
										{snippet && <div className="truncate text-xs text-ink-3 mt-0.5">{highlightTerms(snippet, urlQuery)}</div>}
									</div>
								</div>
							);
						})}</div>
					)}
				</div>
				{totalCount > SEARCH_PAGE_SIZE && <div className="flex justify-center py-3 border-t border-line shrink-0"><Pagination page={currentPage} setPage={setPage} perPage={SEARCH_PAGE_SIZE} totalCount={totalCount} /></div>}
			</div>
		</Shell>
	);
}
