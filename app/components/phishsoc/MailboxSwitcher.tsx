// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

import { Menu } from "@base-ui/react/menu";
import { CaretUpDownIcon, CheckIcon } from "@phosphor-icons/react";
import { useNavigate } from "react-router";
import type { Mailbox } from "~/types";

// Sidebar mailbox-switcher (#188). Replaces the old "Select mailbox" card
// that previously routed to "/" on click — a no-op from the org root and a
// dishonest affordance everywhere else, since the chevron promised a
// switcher.
//
// Sourced from `useMailboxes()` already loaded by Shell, so this component
// stays presentational: it consumes the mailbox list and the active id, and
// hands the picked id back as a navigation. base-ui Menu provides the
// keyboard model (arrow keys, Enter, Escape), focus management, and the
// `aria-haspopup` / `aria-expanded` wiring.

interface MailboxSwitcherProps {
	/** Active mailbox id, or undefined at the org root. Used to mark the
	 * currently-selected entry in the menu and to no-op the trigger label. */
	activeMailboxId: string | undefined;
	/** Active mailbox object, sourced from `useMailbox(activeId)` in Shell.
	 * Drives the trigger label; the menu items render from `mailboxes`.
	 * Loosely typed because the Shell signature already widens to nullable
	 * fields and this component just consumes them. */
	mailbox: { name?: string | null; email?: string | null } | undefined;
	/** Full mailbox list for the current org. Empty array renders the
	 * "No mailboxes yet" state. */
	mailboxes: Mailbox[] | undefined;
	/** Total mailbox count surfaced under the trigger label. */
	mailboxCount: number;
	/** Closes the mobile drawer when the menu opens or an item is picked.
	 * On desktop this is a no-op. The `[location.pathname]` effect in Shell
	 * also catches route changes, but selecting the *currently active*
	 * mailbox doesn't change pathname, so the explicit close is still needed
	 * on mobile. */
	onClose: () => void;
}

export default function MailboxSwitcher({
	activeMailboxId,
	mailbox,
	mailboxes,
	mailboxCount,
	onClose,
}: MailboxSwitcherProps) {
	const navigate = useNavigate();
	const orgDomain = mailbox?.email?.split("@")[1] ?? "—";
	const orgInitial = (mailbox?.name || mailbox?.email || "?")[0]?.toUpperCase();
	const list = mailboxes ?? [];

	const handlePick = (id: string) => {
		onClose();
		if (id === activeMailboxId) return;
		navigate(`/mailbox/${encodeURIComponent(id)}/dashboard`);
	};

	return (
		<Menu.Root
			// Sidebar dropdown — not a modal. Default `modal: true` would lock
			// page scroll and disable outside interaction, which is heavier
			// than a popover should be. base-ui still wires Escape and
			// outside-click dismissal in non-modal mode.
			modal={false}
		>
			<Menu.Trigger
				className="mx-3 flex items-center gap-2.5 rounded-md border border-line bg-paper px-2.5 py-2 text-left hover:border-line-strong transition-colors"
			>
				<span className="flex h-7 w-7 items-center justify-center rounded-md bg-accent-tint text-accent-ink pp-serif text-[15px]">
					{orgInitial}
				</span>
				<span className="flex-1 min-w-0">
					<span className="block truncate text-[12.5px] font-medium text-ink">
						{mailbox?.name || "Select mailbox"}
					</span>
					<span className="block truncate text-[10.5px] text-ink-3">
						{orgDomain} · {mailboxCount} mailbox{mailboxCount === 1 ? "" : "es"}
					</span>
				</span>
				<CaretUpDownIcon size={12} className="text-ink-3 shrink-0" />
			</Menu.Trigger>
			<Menu.Portal>
				<Menu.Positioner sideOffset={4} align="start" className="z-50">
					<Menu.Popup
						aria-label="Switch mailbox"
						className="min-w-[220px] max-w-[320px] rounded-md border border-line bg-paper py-1 shadow-lg outline-none"
					>
						{list.length === 0 ? (
							// Empty state. Not a `MenuItem` — that would make it
							// selectable; this is a static blurb plus a nav link the
							// user can reach via Tab.
							<div className="px-3 py-2 text-[12px] text-ink-2">
								<div className="font-medium text-ink">No mailboxes yet</div>
								<div className="mt-0.5 text-ink-3">
									<a
										href="/mailboxes"
										onClick={(e) => {
											e.preventDefault();
											onClose();
											navigate("/mailboxes");
										}}
										className="text-accent hover:underline"
									>
										Provision a mailbox
									</a>
								</div>
							</div>
						) : (
							list.map((mb) => {
								const isActive = mb.id === activeMailboxId;
								return (
									<Menu.Item
										key={mb.id}
										onClick={() => handlePick(mb.id)}
										className={`mx-1 flex cursor-pointer items-center gap-2 rounded-sm px-2 py-1.5 text-[12.5px] outline-none data-[highlighted]:bg-paper-2 ${
											isActive ? "text-ink" : "text-ink-2"
										}`}
									>
										<span className="flex-1 min-w-0">
											<span className="block truncate font-medium">
												{mb.name || mb.email || mb.id}
											</span>
											{mb.email && mb.name && (
												<span className="block truncate text-[10.5px] text-ink-3">
													{mb.email}
												</span>
											)}
										</span>
										{isActive && (
											<CheckIcon
												size={12}
												weight="bold"
												aria-label="Active mailbox"
												className="text-accent shrink-0"
											/>
										)}
									</Menu.Item>
								);
							})
						)}
					</Menu.Popup>
				</Menu.Positioner>
			</Menu.Portal>
		</Menu.Root>
	);
}
