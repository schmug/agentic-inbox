// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { Loader } from "@cloudflare/kumo";
import {
	BriefcaseIcon,
	EnvelopeIcon,
	ShieldCheckIcon,
	WarningIcon,
} from "@phosphor-icons/react";
import { Link as RouterLink, useParams } from "react-router";
import Shell from "~/components/phishsoc/Shell";
import { useDomainStats } from "~/queries/domains";
import type {
	DomainStats,
	OrgVerdictMix,
} from "~/types";

export function meta({ params }: { params: { domain?: string } }) {
	return [{ title: `${params.domain ?? "Domain"} · PhishSOC` }];
}

export default function DomainDetailRoute() {
	const { domain } = useParams<{ domain: string }>();
	const { data, isLoading, isError, refetch } = useDomainStats(domain);

	return (
		<Shell>
			<div className="px-6 md:px-10 py-8 max-w-[1280px] space-y-6">
				<DomainHeader domain={domain ?? ""} data={data} />

				{isLoading ? (
					<div className="flex justify-center py-20">
						<Loader size="lg" />
					</div>
				) : isError ? (
					<DomainError onRetry={() => refetch()} />
				) : data ? (
					<DomainBody data={data} />
				) : null}
			</div>
		</Shell>
	);
}

function DomainHeader({
	domain,
	data,
}: { domain: string; data: DomainStats | undefined }) {
	const subtitle = data
		? `${data.mailboxes.length} mailbox${data.mailboxes.length === 1 ? "" : "es"}`
		: "Per-domain operations";
	return (
		<div>
			<div className="text-[11px] uppercase tracking-[0.08em] text-ink-3 mb-1">
				Domain · last 24 hours
			</div>
			<h1 className="pp-serif text-[40px] leading-none text-ink mb-2">
				{domain}
			</h1>
			<p className="pp-serif text-[24px] leading-tight text-ink-3 max-w-2xl">
				{subtitle}
			</p>
		</div>
	);
}

function DomainError({ onRetry }: { onRetry: () => void }) {
	return (
		<div className="pp-card p-6 flex items-start gap-3">
			<span className="flex h-8 w-8 items-center justify-center rounded-full bg-paper-2 text-ink-3 shrink-0">
				<WarningIcon size={18} />
			</span>
			<div>
				<div className="text-[14px] font-medium text-ink mb-1">
					Couldn't load this domain
				</div>
				<p className="text-[12.5px] text-ink-3 leading-relaxed mb-2">
					The domain stats endpoint didn't respond. Check the worker logs and retry.
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

function DomainBody({ data }: { data: DomainStats }) {
	return (
		<>
			<KpiGrid data={data} />
			<div className="grid gap-4 lg:grid-cols-3">
				<VerdictMixCard mix={data.verdictMix} />
				<DmarcPostureCard posture={data.dmarcPosture} />
			</div>
			<MailboxList mailboxes={data.mailboxes} />
			{data.recentCases.length > 0 && <RecentCasesList cases={data.recentCases} />}
		</>
	);
}

interface Kpi {
	label: string;
	value: string;
}

function KpiGrid({ data }: { data: DomainStats }) {
	const kpis: Kpi[] = [
		{ label: "Threats blocked · 24h", value: String(data.threatsBlocked24h) },
		{ label: "Threats blocked · 7d", value: String(data.threatsBlocked7d) },
		{ label: "Open cases", value: String(data.openCases) },
		{ label: "Mailboxes", value: String(data.mailboxes.length) },
	];
	return (
		<div className="grid gap-4 grid-cols-1 sm:grid-cols-2 md:grid-cols-4">
			{kpis.map((k) => (
				<div key={k.label} className="pp-card p-4">
					<div className="text-[10.5px] uppercase tracking-[0.06em] text-ink-3 mb-2">
						{k.label}
					</div>
					<div className="pp-serif text-[36px] leading-none text-ink">
						{k.value}
					</div>
				</div>
			))}
		</div>
	);
}

const VERDICT_LABEL: Record<keyof OrgVerdictMix, string> = {
	safe: "Safe",
	suspicious: "Suspicious",
	phishing: "Phishing",
	spam: "Spam",
	bec: "BEC",
};

function VerdictMixCard({ mix }: { mix: OrgVerdictMix }) {
	const entries = (Object.keys(VERDICT_LABEL) as Array<keyof OrgVerdictMix>).map(
		(k) => ({ key: k, label: VERDICT_LABEL[k], count: mix[k] }),
	);
	const total = entries.reduce((sum, e) => sum + e.count, 0);
	return (
		<div className="pp-card p-5 lg:col-span-2 flex flex-col gap-3">
			<div className="flex items-baseline justify-between gap-3">
				<div className="text-[10.5px] uppercase tracking-[0.06em] text-ink-3 flex items-center gap-1.5">
					<ShieldCheckIcon size={12} />
					Verdict mix · 24h
				</div>
				<div className="text-[12px] text-ink-3">{total} classified</div>
			</div>
			{total === 0 ? (
				<p className="text-[12.5px] text-ink-3">
					No classified mail in the window.
				</p>
			) : (
				<ul className="space-y-2">
					{entries.map((e) => {
						const pct = total === 0 ? 0 : (e.count / total) * 100;
						return (
							<li key={e.key} className="flex items-center gap-3">
								<div className="text-[12px] text-ink-2 w-24 shrink-0">
									{e.label}
								</div>
								<div className="flex-1 h-1.5 rounded-full bg-paper-3 overflow-hidden">
									<div
										className="h-full bg-accent"
										style={{ width: `${pct}%` }}
										aria-hidden
									/>
								</div>
								<div className="pp-mono text-[11px] text-ink-3 tabular-nums w-10 text-right">
									{e.count}
								</div>
							</li>
						);
					})}
				</ul>
			)}
		</div>
	);
}

function DmarcPostureCard({
	posture,
}: { posture: DomainStats["dmarcPosture"] }) {
	// All-null posture is the v1 norm — real DMARC report ingestion at the
	// apex-domain level isn't shipping in this iteration. Render an
	// "unavailable" affordance rather than misleading defaults.
	const allNull =
		posture.p === null &&
		posture.sp === null &&
		posture.pct === null &&
		posture.ruaConfigured === null &&
		posture.alignmentRate === null;
	return (
		<div className="pp-card p-5">
			<div className="text-[10.5px] uppercase tracking-[0.06em] text-ink-3 mb-3 flex items-center gap-1.5">
				<ShieldCheckIcon size={12} />
				DMARC posture
			</div>
			{allNull ? (
				<p className="text-[12.5px] text-ink-3">
					Apex-domain DMARC posture isn't ingested yet. The per-mailbox DMARC
					dashboard surfaces the report rollups available today.
				</p>
			) : (
				<dl className="space-y-1.5 text-[12.5px]">
					<PostureRow label="p" value={posture.p ?? "—"} />
					<PostureRow label="sp" value={posture.sp ?? "—"} />
					<PostureRow
						label="pct"
						value={posture.pct === null ? "—" : `${posture.pct}%`}
					/>
					<PostureRow
						label="rua"
						value={
							posture.ruaConfigured === null
								? "—"
								: posture.ruaConfigured
									? "configured"
									: "not configured"
						}
					/>
					<PostureRow
						label="alignment"
						value={
							posture.alignmentRate === null
								? "—"
								: `${Math.round(posture.alignmentRate * 100)}%`
						}
					/>
				</dl>
			)}
		</div>
	);
}

function PostureRow({ label, value }: { label: string; value: string }) {
	return (
		<div className="flex items-baseline justify-between gap-3">
			<dt className="text-ink-3">{label}</dt>
			<dd className="pp-mono text-ink-2 tabular-nums">{value}</dd>
		</div>
	);
}

function MailboxList({
	mailboxes,
}: { mailboxes: DomainStats["mailboxes"] }) {
	return (
		<div className="pp-card p-5">
			<div className="text-[10.5px] uppercase tracking-[0.06em] text-ink-3 mb-3 flex items-center gap-1.5">
				<EnvelopeIcon size={12} />
				Mailboxes
			</div>
			{mailboxes.length === 0 ? (
				<p className="text-[12.5px] text-ink-3">
					No mailboxes for this domain.
				</p>
			) : (
				<ul className="divide-y divide-line">
					{mailboxes.map((m) => (
						<li key={m.id} className="py-2">
							<RouterLink
								to={`/mailbox/${encodeURIComponent(m.id)}/dashboard`}
								className="flex items-center justify-between gap-3 text-[13px] text-ink hover:text-accent transition-colors"
							>
								<span className="truncate">{m.email}</span>
								<span className="text-[11px] text-ink-3">Dashboard</span>
							</RouterLink>
						</li>
					))}
				</ul>
			)}
		</div>
	);
}

function RecentCasesList({
	cases,
}: { cases: DomainStats["recentCases"] }) {
	return (
		<div className="pp-card p-5">
			<div className="text-[10.5px] uppercase tracking-[0.06em] text-ink-3 mb-3 flex items-center gap-1.5">
				<BriefcaseIcon size={12} />
				Recent cases
			</div>
			<ul className="divide-y divide-line">
				{cases.map((c) => (
					<li
						key={c.id}
						className="py-2 flex items-baseline justify-between gap-3"
					>
						<span className="text-[13px] text-ink truncate">{c.title}</span>
						<span className="pp-mono text-[11px] text-ink-3 tabular-nums shrink-0">
							{c.status}
						</span>
					</li>
				))}
			</ul>
		</div>
	);
}
