// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { Loader } from "@cloudflare/kumo";
import { BuildingsIcon, WarningIcon } from "@phosphor-icons/react";
import { useMemo, useState } from "react";
import { Link as RouterLink } from "react-router";
import Shell from "~/components/phishsoc/Shell";
import { useDomains } from "~/queries/domains";
import type { DomainListEntry } from "~/types";

export function meta() {
	return [{ title: "Domains · PhishSOC" }];
}

/**
 * Sort keys exposed in the cross-domain comparison UI (#141). All sorting is
 * done client-side against the data already returned by `/api/v1/domains` —
 * the list is bounded by the number of provisioned domains per org and is
 * small enough that a backend pushdown would be premature optimisation.
 */
type SortKey = "name" | "threatsBlocked24h" | "openCases" | "mailboxesCount";

const SORT_OPTIONS: ReadonlyArray<{ value: SortKey; label: string }> = [
	{ value: "name", label: "Name (A→Z)" },
	{ value: "threatsBlocked24h", label: "Threats blocked · 24h" },
	{ value: "openCases", label: "Open cases" },
	{ value: "mailboxesCount", label: "Mailboxes" },
];

function sortDomains(
	domains: DomainListEntry[],
	key: SortKey,
): DomainListEntry[] {
	const next = [...domains];
	if (key === "name") {
		// `localeCompare` so a domain like `école.fr` sorts predictably and
		// we don't fall back to UTF-16 code-unit ordering.
		next.sort((a, b) => a.domain.localeCompare(b.domain));
	} else {
		// Numeric sorts are descending — the operator is asking "which domain
		// is having the worst day?" and the highest counts belong on top.
		next.sort((a, b) => b[key] - a[key]);
	}
	return next;
}

function filterDomains(
	domains: DomainListEntry[],
	query: string,
): DomainListEntry[] {
	const q = query.trim().toLowerCase();
	if (q === "") return domains;
	return domains.filter((d) => d.domain.toLowerCase().includes(q));
}

export default function DomainsListRoute() {
	const { data, isLoading, isError, refetch } = useDomains();
	const [sortKey, setSortKey] = useState<SortKey>("name");
	const [filter, setFilter] = useState("");

	const visible = useMemo(() => {
		if (!data) return [];
		return sortDomains(filterDomains(data, filter), sortKey);
	}, [data, filter, sortKey]);

	return (
		<Shell>
			<div className="px-6 md:px-10 py-8 max-w-[1280px] space-y-6">
				<DomainsHeader count={data?.length ?? 0} />

				{isLoading ? (
					<div className="flex justify-center py-20">
						<Loader size="lg" />
					</div>
				) : isError ? (
					<DomainsError onRetry={() => refetch()} />
				) : data ? (
					data.length === 0 ? (
						<EmptyDomains />
					) : (
						<>
							<DomainsControls
								sortKey={sortKey}
								onSortKeyChange={setSortKey}
								filter={filter}
								onFilterChange={setFilter}
							/>
							{visible.length === 0 ? (
								<NoDomainsMatch query={filter} onClear={() => setFilter("")} />
							) : (
								<DomainsTable domains={visible} />
							)}
						</>
					)
				) : null}
			</div>
		</Shell>
	);
}

function DomainsHeader({ count }: { count: number }) {
	return (
		<div>
			<div className="text-[11px] uppercase tracking-[0.08em] text-ink-3 mb-1">
				Org · domains
			</div>
			<h1 className="pp-serif text-[40px] leading-none text-ink mb-2">
				Domains.
			</h1>
			<p className="pp-serif text-[24px] leading-tight text-ink-3 max-w-2xl">
				{count > 0
					? `${count} domain${count === 1 ? "" : "s"} provisioned.`
					: "No domains provisioned yet."}
			</p>
		</div>
	);
}

function DomainsError({ onRetry }: { onRetry: () => void }) {
	return (
		<div className="pp-card p-6 flex items-start gap-3">
			<span className="flex h-8 w-8 items-center justify-center rounded-full bg-paper-2 text-ink-3 shrink-0">
				<WarningIcon size={18} />
			</span>
			<div>
				<div className="text-[14px] font-medium text-ink mb-1">
					Couldn't load the domains list
				</div>
				<p className="text-[12.5px] text-ink-3 leading-relaxed mb-2">
					The domains endpoint didn't respond. Check the worker logs and retry.
				</p>
				<button
					type="button"
					onClick={onRetry}
					className="text-[12px] underline text-accent hover:opacity-80"
				>
					Retry
				</button>
			</div>
		</div>
	);
}

function EmptyDomains() {
	return (
		<div className="pp-card py-16 px-6">
			<div className="flex flex-col items-center text-center">
				<div className="mb-4">
					<BuildingsIcon size={48} weight="thin" className="text-ink-3" />
				</div>
				<h3 className="text-base font-semibold text-ink mb-1.5">
					No domains yet
				</h3>
				<p className="text-sm text-ink-3 max-w-sm mb-5">
					Provision a mailbox to start aggregating domain-level threat activity.
				</p>
				<RouterLink
					to="/mailboxes"
					className="text-[13px] underline text-accent hover:opacity-80"
				>
					Go to Mailboxes
				</RouterLink>
			</div>
		</div>
	);
}

/**
 * Distinct from `EmptyDomains` (which means "no domains provisioned"). This
 * state means the operator filtered to a substring that didn't match any
 * provisioned domain — the right call-to-action is "clear the filter", not
 * "go provision more mailboxes".
 */
function NoDomainsMatch({
	query,
	onClear,
}: { query: string; onClear: () => void }) {
	return (
		<div className="pp-card p-6 flex items-start gap-3">
			<span className="flex h-8 w-8 items-center justify-center rounded-full bg-paper-2 text-ink-3 shrink-0">
				<BuildingsIcon size={18} />
			</span>
			<div>
				<div className="text-[14px] font-medium text-ink mb-1">
					No domains match "{query}"
				</div>
				<p className="text-[12.5px] text-ink-3 leading-relaxed mb-2">
					Try a different substring, or clear the filter to see every
					provisioned domain.
				</p>
				<button
					type="button"
					onClick={onClear}
					className="text-[12px] underline text-accent hover:opacity-80"
				>
					Clear filter
				</button>
			</div>
		</div>
	);
}

function DomainsControls({
	sortKey,
	onSortKeyChange,
	filter,
	onFilterChange,
}: {
	sortKey: SortKey;
	onSortKeyChange: (key: SortKey) => void;
	filter: string;
	onFilterChange: (value: string) => void;
}) {
	return (
		<div className="flex flex-col sm:flex-row sm:items-center gap-3 sm:gap-4">
			<label className="flex items-center gap-2 text-[12px] text-ink-3">
				<span className="uppercase tracking-[0.06em] text-[10.5px]">
					Filter
				</span>
				<input
					type="search"
					value={filter}
					onChange={(e) => onFilterChange(e.target.value)}
					placeholder="domain substring"
					aria-label="Filter domains by name"
					className="rounded-md border border-line bg-paper px-2.5 py-1 text-[13px] text-ink placeholder:text-ink-3 focus:outline-none focus:ring-1 focus:ring-accent w-full sm:w-64"
				/>
			</label>
			<label className="flex items-center gap-2 text-[12px] text-ink-3 sm:ml-auto">
				<span className="uppercase tracking-[0.06em] text-[10.5px]">
					Sort
				</span>
				<select
					value={sortKey}
					onChange={(e) => onSortKeyChange(e.target.value as SortKey)}
					aria-label="Sort domains"
					className="rounded-md border border-line bg-paper px-2 py-1 text-[13px] text-ink focus:outline-none focus:ring-1 focus:ring-accent"
				>
					{SORT_OPTIONS.map((opt) => (
						<option key={opt.value} value={opt.value}>
							{opt.label}
						</option>
					))}
				</select>
			</label>
		</div>
	);
}

function DomainsTable({ domains }: { domains: DomainListEntry[] }) {
	return (
		<div className="pp-card overflow-hidden">
			<table className="w-full text-[13px]">
				<thead>
					<tr className="text-left text-[10.5px] uppercase tracking-[0.06em] text-ink-3 border-b border-line">
						<th className="px-4 py-2.5 font-normal">Domain</th>
						<th className="px-4 py-2.5 font-normal text-right">Mailboxes</th>
						<th className="px-4 py-2.5 font-normal text-right">
							Threats blocked · 24h
						</th>
						<th className="px-4 py-2.5 font-normal text-right">Open cases</th>
					</tr>
				</thead>
				<tbody>
					{domains.map((d) => (
						<tr
							key={d.domain}
							className="border-b border-line last:border-b-0 hover:bg-paper-2 transition-colors"
						>
							<td className="px-4 py-3">
								<RouterLink
									to={`/domains/${encodeURIComponent(d.domain)}`}
									className="text-ink hover:text-accent transition-colors"
								>
									{d.domain}
								</RouterLink>
							</td>
							<td className="px-4 py-3 text-right pp-mono tabular-nums text-ink-2">
								{d.mailboxesCount}
							</td>
							<td className="px-4 py-3 text-right pp-mono tabular-nums text-ink-2">
								{d.threatsBlocked24h}
							</td>
							<td className="px-4 py-3 text-right pp-mono tabular-nums text-ink-2">
								{d.openCases}
							</td>
						</tr>
					))}
				</tbody>
			</table>
		</div>
	);
}
