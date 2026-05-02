// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { Loader } from "@cloudflare/kumo";
import { BuildingsIcon, WarningIcon } from "@phosphor-icons/react";
import { Link as RouterLink } from "react-router";
import Shell from "~/components/phishsoc/Shell";
import { useDomains } from "~/queries/domains";
import type { DomainListEntry } from "~/types";

export function meta() {
	return [{ title: "Domains · PhishSOC" }];
}

export default function DomainsListRoute() {
	const { data, isLoading, isError, refetch } = useDomains();

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
						<DomainsTable domains={data} />
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
