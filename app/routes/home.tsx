// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { Loader } from "@cloudflare/kumo";
import {
	BriefcaseIcon,
	EnvelopeIcon,
	ShieldCheckIcon,
	WarningIcon,
} from "@phosphor-icons/react";
import { useState } from "react";
import { Link as RouterLink } from "react-router";
import Shell from "~/components/phishsoc/Shell";
import { useAutoProvisionMailboxes } from "~/hooks/useAutoProvisionMailboxes";
import { useMailboxes } from "~/queries/mailboxes";
import { useOrgOverview } from "~/queries/org";
import type { OrgOverview, OrgVerdictMix } from "~/types";

export function meta() {
	return [{ title: "PhishSOC" }];
}

export default function HomeRoute() {
	useAutoProvisionMailboxes();
	const { data, isLoading, isError, refetch } = useOrgOverview();
	const { data: mailboxes = [] } = useMailboxes();

	return (
		<Shell>
			<div className="px-6 md:px-10 py-8 max-w-[1280px] space-y-6">
				<OrgHeader data={data} mailboxCount={mailboxes.length} />

				{isLoading ? (
					<div className="flex justify-center py-20">
						<Loader size="lg" />
					</div>
				) : isError ? (
					<OrgError onRetry={() => refetch()} />
				) : data ? (
					<OrgBody data={data} mailboxCount={mailboxes.length} />
				) : null}
			</div>
		</Shell>
	);
}

function OrgHeader({
	data,
	mailboxCount,
}: { data: OrgOverview | undefined; mailboxCount: number }) {
	const summary = data
		? `${data.mailboxesCount} mailbox${data.mailboxesCount === 1 ? "" : "es"} · ${data.domainsCount} domain${data.domainsCount === 1 ? "" : "s"}`
		: mailboxCount > 0
			? `${mailboxCount} mailbox${mailboxCount === 1 ? "" : "es"}`
			: "Org overview";
	return (
		<div>
			<div className="text-[11px] uppercase tracking-[0.08em] text-ink-3 mb-1">
				Operations · last 24 hours
			</div>
			<h1 className="pp-serif text-[40px] leading-none text-ink mb-2">
				Across the fleet.
			</h1>
			<p className="pp-serif text-[24px] leading-tight text-ink-3 max-w-2xl">
				{summary}
			</p>
		</div>
	);
}

function OrgError({ onRetry }: { onRetry: () => void }) {
	return (
		<div className="pp-card p-6 flex items-start gap-3">
			<span className="flex h-8 w-8 items-center justify-center rounded-full bg-paper-2 text-ink-3 shrink-0">
				<WarningIcon size={18} />
			</span>
			<div>
				<div className="text-[14px] font-medium text-ink mb-1">
					Couldn't load the org overview
				</div>
				<p className="text-[12.5px] text-ink-3 leading-relaxed mb-2">
					The overview endpoint didn't respond. Check the worker logs and retry.
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

function OrgBody({
	data,
	mailboxCount,
}: { data: OrgOverview; mailboxCount: number }) {
	if (data.mailboxesCount === 0 && mailboxCount === 0) {
		return <EmptyOrg />;
	}
	return (
		<>
			<KpiGrid data={data} />
			<div className="grid gap-4 lg:grid-cols-3">
				<VerdictMixCard
					mix24h={data.verdictMix}
					mix7d={data.verdictMix7d}
				/>
				<TopThreatsCard threats={data.topThreats} />
			</div>
		</>
	);
}

function EmptyOrg() {
	return (
		<div className="pp-card py-16 px-6">
			<div className="flex flex-col items-center text-center">
				<div className="mb-4">
					<EnvelopeIcon size={48} weight="thin" className="text-ink-3" />
				</div>
				<h3 className="text-base font-semibold text-ink mb-1.5">
					No mailboxes yet
				</h3>
				<p className="text-sm text-ink-3 max-w-sm mb-5">
					Provision a mailbox to start aggregating org-wide threat activity.
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

interface Kpi {
	label: string;
	value: string;
}

function KpiGrid({ data }: { data: OrgOverview }) {
	const kpis: Kpi[] = [
		{ label: "Threats blocked · 24h", value: String(data.threatsBlocked24h) },
		{ label: "Threats blocked · 7d", value: String(data.threatsBlocked7d) },
		{ label: "Open cases", value: String(data.openCasesTotal) },
		{
			label: "Pipeline success · 24h",
			value:
				data.pipelineHealth.successRate24h === null
					? "—"
					: `${Math.round(data.pipelineHealth.successRate24h * 100)}%`,
		},
		{
			label: "Pipeline p95 · 24h",
			value:
				data.pipelineHealth.p95Ms === null
					? "—"
					: formatLatency(data.pipelineHealth.p95Ms),
		},
		{ label: "Mailboxes", value: String(data.mailboxesCount) },
		{ label: "Domains", value: String(data.domainsCount) },
		{
			label: "Hub contributions · 24h",
			value: String(data.hubContributions24h),
		},
		{
			label: "Pipeline runs · 24h",
			value: String(data.pipelineHealth.runs24h),
		},
	];
	return (
		<div className="grid gap-4 grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4">
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

type VerdictWindow = "24h" | "7d";

function VerdictMixCard({
	mix24h,
	mix7d,
}: {
	mix24h: OrgVerdictMix;
	mix7d: OrgVerdictMix;
}) {
	const [window, setWindow] = useState<VerdictWindow>("24h");
	const mix = window === "24h" ? mix24h : mix7d;
	const entries = (Object.keys(VERDICT_LABEL) as Array<keyof OrgVerdictMix>).map(
		(k) => ({ key: k, label: VERDICT_LABEL[k], count: mix[k] }),
	);
	const total = entries.reduce((sum, e) => sum + e.count, 0);
	return (
		<div className="pp-card p-5 lg:col-span-2 flex flex-col gap-3">
			<div className="flex items-baseline justify-between gap-3">
				<div className="text-[10.5px] uppercase tracking-[0.06em] text-ink-3 flex items-center gap-1.5">
					<ShieldCheckIcon size={12} />
					Verdict mix
				</div>
				<div
					role="tablist"
					aria-label="Verdict-mix window"
					className="flex items-center gap-1 rounded-md bg-paper-2 p-0.5"
				>
					{(["24h", "7d"] as const).map((w) => (
						<button
							key={w}
							type="button"
							role="tab"
							aria-selected={window === w}
							onClick={() => setWindow(w)}
							className={`px-2 py-0.5 rounded text-[11px] tabular-nums transition-colors ${
								window === w
									? "bg-paper text-ink shadow-sm"
									: "text-ink-3 hover:text-ink"
							}`}
						>
							{w}
						</button>
					))}
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

function formatLatency(ms: number): string {
	if (ms < 1000) return `${Math.round(ms)}ms`;
	const seconds = ms / 1000;
	return seconds >= 10 ? `${Math.round(seconds)}s` : `${seconds.toFixed(1)}s`;
}

function TopThreatsCard({
	threats,
}: { threats: OrgOverview["topThreats"] }) {
	return (
		<div className="pp-card p-5">
			<div className="text-[10.5px] uppercase tracking-[0.06em] text-ink-3 mb-3 flex items-center gap-1.5">
				<BriefcaseIcon size={12} />
				Top threats · 24h
			</div>
			{threats.length === 0 ? (
				<p className="text-[12.5px] text-ink-3">No threats actioned yet.</p>
			) : (
				<ul className="space-y-2">
					{threats.map((t) => (
						<li key={t.category} className="flex items-baseline justify-between gap-3">
							<span className="text-[13px] text-ink capitalize">
								{t.category}
							</span>
							<span className="pp-mono text-[12px] text-ink-3 tabular-nums">
								{t.count}
							</span>
						</li>
					))}
				</ul>
			)}
		</div>
	);
}
