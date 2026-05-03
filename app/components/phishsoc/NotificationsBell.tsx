// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { Popover } from "@base-ui/react/popover";
import { BellIcon } from "@phosphor-icons/react";
import { Link } from "react-router";
import { useDashboardSummary } from "~/queries/dashboard";

// Minimal notifications popover (#185). v1 has no notifications subsystem
// behind it — the bell would otherwise be a dead affordance — so we surface
// a single derived signal from data already on the wire: the number of open
// cases on the active mailbox (`useDashboardSummary().openCases`). When the
// bell is rendered outside a mailbox (org routes have `mailboxId === undefined`)
// the dashboard query is gated off and the popover renders the empty state.
//
// The aria-haspopup / aria-expanded / Escape-to-close / focus-management
// contract is owned by base-ui's Popover.Trigger + Popover.Popup — see
// `node_modules/@base-ui/react/popover/trigger/PopoverTrigger.d.ts`. We don't
// hand-roll any of it.
//
// Out of scope (per the issue): push/web notifications, persistent unread
// state, agent-error feed, incoming hub-invitation feed. A follow-up under
// the org-shell sweep (#191) tracks expanding the surface once those data
// sources exist.

interface NotificationItem {
	key: string;
	label: string;
	to: string;
}

interface NotificationsBellProps {
	mailboxId: string | undefined;
}

export default function NotificationsBell({ mailboxId }: NotificationsBellProps) {
	// `useDashboardSummary` is `enabled: !!mailboxId` internally, so passing
	// `undefined` off-mailbox doesn't trigger a fetch — the popover just
	// renders the empty state.
	const { data: summary } = useDashboardSummary(mailboxId);
	const openCases = summary?.openCases ?? 0;

	const items: NotificationItem[] = [];
	if (mailboxId && openCases > 0) {
		items.push({
			key: "open-cases",
			label: `${openCases} open case${openCases === 1 ? "" : "s"}`,
			to: `/mailbox/${encodeURIComponent(mailboxId)}/cases`,
		});
	}

	const hasItems = items.length > 0;

	return (
		<Popover.Root>
			<Popover.Trigger
				aria-label="Notifications"
				className="relative flex h-8 w-8 items-center justify-center rounded-md text-ink-3 hover:bg-paper-2 hover:text-ink transition-colors"
			>
				<BellIcon size={16} />
				{hasItems && (
					<span
						aria-hidden
						data-testid="notifications-badge"
						className="absolute top-1 right-1 h-2 w-2 rounded-full bg-accent ring-2 ring-paper"
					/>
				)}
			</Popover.Trigger>
			<Popover.Portal>
				<Popover.Positioner sideOffset={6} align="end">
					<Popover.Popup
						aria-label="Notifications"
						className="min-w-[260px] max-w-[320px] rounded-md border border-line bg-paper text-ink shadow-lg outline-none p-1"
					>
						{hasItems ? (
							<ul className="flex flex-col">
								{items.map((item) => (
									<li key={item.key}>
										<Link
											to={item.to}
											className="block rounded-md px-2.5 py-1.5 text-[13px] text-ink hover:bg-paper-2 hover:text-ink"
										>
											{item.label}
										</Link>
									</li>
								))}
							</ul>
						) : (
							<div className="px-2.5 py-2 text-[12px] text-ink-3">
								No notifications
							</div>
						)}
					</Popover.Popup>
				</Popover.Positioner>
			</Popover.Portal>
		</Popover.Root>
	);
}
