// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

import { Loader } from "@cloudflare/kumo";
import { useEffect, useState } from "react";
import { Link, useParams } from "react-router";

interface CaseRow {
	id: string;
	created_at: string;
	updated_at: string;
	status: string;
	title: string;
	shared_to_hub: number;
}

const STATUS_LABEL: Record<string, string> = {
	open: "Open",
	"closed-tp": "Closed — true positive",
	"closed-fp": "Closed — false positive",
	"closed-dup": "Closed — duplicate",
};

export default function CasesRoute() {
	const { mailboxId } = useParams<{ mailboxId: string }>();
	const [cases, setCases] = useState<CaseRow[] | null>(null);
	const [filter, setFilter] = useState<string>("all");

	useEffect(() => {
		if (!mailboxId) return;
		const q = filter === "all" ? "" : `?status=${filter}`;
		fetch(`/api/v1/mailboxes/${encodeURIComponent(mailboxId)}/cases${q}`)
			.then((r) => r.json() as Promise<{ cases: CaseRow[] }>)
			.then((r) => setCases(r.cases))
			.catch((e) => console.error("cases fetch failed", e));
	}, [mailboxId, filter]);

	if (!cases) return <div className="flex justify-center py-20"><Loader size="lg" /></div>;

	return (
		<div className="max-w-4xl px-4 py-6 md:px-8 h-full overflow-y-auto">
			<h1 className="text-lg font-semibold text-kumo-default mb-4">Cases</h1>
			<div className="mb-4 flex items-center gap-2 text-sm">
				{["all", "open", "closed-tp", "closed-fp", "closed-dup"].map((s) => (
					<button
						key={s}
						type="button"
						onClick={() => setFilter(s)}
						className={`px-2 py-1 rounded ${filter === s ? "bg-kumo-fill text-kumo-default" : "text-kumo-subtle hover:bg-kumo-tint"}`}
					>
						{s === "all" ? "All" : STATUS_LABEL[s] ?? s}
					</button>
				))}
			</div>

			{cases.length === 0 ? (
				<div className="rounded-lg border border-kumo-line p-6 text-kumo-subtle">
					No cases yet. Report a phish from any email in your inbox to open one.
				</div>
			) : (
				<div className="overflow-x-auto rounded-lg border border-kumo-line">
					<table className="w-full text-sm">
						<thead className="bg-kumo-fill text-kumo-subtle text-xs uppercase">
							<tr>
								<th className="text-left px-3 py-2">Title</th>
								<th className="text-left px-3 py-2">Status</th>
								<th className="text-left px-3 py-2">Shared</th>
								<th className="text-left px-3 py-2">Updated</th>
							</tr>
						</thead>
						<tbody>
							{cases.map((c) => (
								<tr key={c.id} className="border-t border-kumo-line hover:bg-kumo-tint cursor-pointer">
									<td className="px-3 py-2">
										<Link
											to={`/mailbox/${encodeURIComponent(mailboxId ?? "")}/cases/${c.id}`}
											className="text-kumo-default hover:underline"
										>
											{c.title}
										</Link>
									</td>
									<td className="px-3 py-2 text-kumo-subtle">{STATUS_LABEL[c.status] ?? c.status}</td>
									<td className="px-3 py-2">{c.shared_to_hub ? "Yes" : "No"}</td>
									<td className="px-3 py-2 text-kumo-subtle">{new Date(c.updated_at).toLocaleString()}</td>
								</tr>
							))}
						</tbody>
					</table>
				</div>
			)}
		</div>
	);
}
