// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

import { Button, Loader, useKumoToastManager } from "@cloudflare/kumo";
import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router";

interface CaseEmail { case_id: string; email_id: string; }
interface CaseObservable { id: string; kind: string; value: string; }
interface CaseRecord {
	id: string;
	created_at: string;
	updated_at: string;
	status: string;
	title: string;
	notes: string | null;
	shared_to_hub: number;
	hub_event_uuid: string | null;
	emails: CaseEmail[];
	observables: CaseObservable[];
}

export default function CaseDetailRoute() {
	const { mailboxId, caseId } = useParams<{ mailboxId: string; caseId: string }>();
	const toast = useKumoToastManager();
	const [data, setData] = useState<CaseRecord | null>(null);

	const load = useCallback(async () => {
		if (!mailboxId || !caseId) return;
		const res = await fetch(`/api/v1/mailboxes/${encodeURIComponent(mailboxId)}/cases/${encodeURIComponent(caseId)}`);
		if (!res.ok) return setData(null);
		const body = (await res.json()) as { case: CaseRecord };
		setData(body.case);
	}, [mailboxId, caseId]);

	useEffect(() => { load(); }, [load]);

	const updateStatus = async (status: string) => {
		if (!mailboxId || !caseId) return;
		await fetch(`/api/v1/mailboxes/${encodeURIComponent(mailboxId)}/cases/${encodeURIComponent(caseId)}`, {
			method: "PATCH",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ status }),
		});
		toast.add({ title: "Case updated" });
		await load();
	};

	if (!data) return <div className="flex justify-center py-20"><Loader size="lg" /></div>;

	return (
		<div className="max-w-3xl px-4 py-6 md:px-8 h-full overflow-y-auto">
			<Link
				to={`/mailbox/${encodeURIComponent(mailboxId ?? "")}/cases`}
				className="text-sm text-kumo-subtle hover:underline"
			>
				← All cases
			</Link>

			<h1 className="text-lg font-semibold text-kumo-default mt-2 mb-1">{data.title}</h1>
			<div className="text-xs text-kumo-subtle mb-6">
				Opened {new Date(data.created_at).toLocaleString()} · Status {data.status}
				{data.shared_to_hub ? ` · Shared (${data.hub_event_uuid ?? "pending"})` : " · Not shared"}
			</div>

			<div className="flex gap-2 mb-6">
				{data.status === "open" && (
					<>
						<Button size="sm" variant="secondary" onClick={() => updateStatus("closed-tp")}>
							Close as true positive
						</Button>
						<Button size="sm" variant="secondary" onClick={() => updateStatus("closed-fp")}>
							Close as false positive
						</Button>
						<Button size="sm" variant="ghost" onClick={() => updateStatus("closed-dup")}>
							Close as duplicate
						</Button>
					</>
				)}
				{data.status !== "open" && (
					<Button size="sm" variant="secondary" onClick={() => updateStatus("open")}>
						Reopen
					</Button>
				)}
			</div>

			<section className="mb-6">
				<h2 className="text-sm font-semibold text-kumo-default mb-2">Observables ({data.observables.length})</h2>
				{data.observables.length === 0 ? (
					<div className="text-kumo-subtle text-sm">None extracted.</div>
				) : (
					<div className="overflow-x-auto rounded-lg border border-kumo-line">
						<table className="w-full text-sm">
							<thead className="bg-kumo-fill text-kumo-subtle text-xs uppercase">
								<tr>
									<th className="text-left px-3 py-2">Kind</th>
									<th className="text-left px-3 py-2">Value</th>
								</tr>
							</thead>
							<tbody>
								{data.observables.map((o) => (
									<tr key={o.id} className="border-t border-kumo-line">
										<td className="px-3 py-2 text-kumo-subtle">{o.kind}</td>
										<td className="px-3 py-2 font-mono break-all">{o.value}</td>
									</tr>
								))}
							</tbody>
						</table>
					</div>
				)}
			</section>

			{data.emails.length > 0 && (
				<section>
					<h2 className="text-sm font-semibold text-kumo-default mb-2">Linked emails ({data.emails.length})</h2>
					<ul className="text-sm text-kumo-default space-y-1">
						{data.emails.map((e) => (
							<li key={e.email_id} className="font-mono text-xs text-kumo-subtle">{e.email_id}</li>
						))}
					</ul>
				</section>
			)}

			{data.notes && (
				<section className="mt-6">
					<h2 className="text-sm font-semibold text-kumo-default mb-2">Notes</h2>
					<div className="text-sm text-kumo-default whitespace-pre-wrap">{data.notes}</div>
				</section>
			)}
		</div>
	);
}
