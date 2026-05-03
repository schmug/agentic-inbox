// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { Menu } from "@base-ui/react/menu";
import { GearSixIcon, SignOutIcon } from "@phosphor-icons/react";
import { useNavigate } from "react-router";

// Sidebar account menu (#204). Replaces the placeholder footer slot left
// by #189 with an auth-aware avatar + email row that opens to a popover
// containing the org-settings link and the Cloudflare Access sign-out.
//
// Identity is sourced from `useMe()` upstream and passed in here so the
// component stays presentational and unit-testable in isolation. base-ui
// `Menu` provides the `aria-haspopup` / `aria-expanded` / Escape /
// focus-management contract for free — same pattern as MailboxSwitcher.

interface AccountMenuProps {
	/**
	 * Authenticated user email (from `/api/v1/me`). Undefined while the
	 * query is in flight; the component renders a muted "Loading…" label
	 * until it resolves rather than holding back the entire footer mount.
	 */
	email: string | undefined;
	/** Closes the mobile drawer when an item is picked. No-op on desktop. */
	onClose: () => void;
}

// Cloudflare Access sign-out endpoint. Relative path so it works on the
// same Access-protected origin without hardcoding a team subdomain — Access
// resolves `/cdn-cgi/access/logout` against the current host.
const ACCESS_LOGOUT_URL = "/cdn-cgi/access/logout";

export default function AccountMenu({ email, onClose }: AccountMenuProps) {
	const navigate = useNavigate();
	const initial = (email?.[0] ?? "?").toUpperCase();
	// Local-part of the email is what we surface as the visible label; the
	// full address shows underneath. Falls back to "Loading…" while the
	// query resolves so we don't render an empty avatar.
	const localPart = email?.split("@")[0];
	const label = email ? localPart || email : "Loading…";

	const handleSettings = () => {
		onClose();
		navigate("/settings");
	};

	return (
		<Menu.Root modal={false}>
			<Menu.Trigger
				className="flex flex-1 items-center gap-2 rounded-md border border-transparent px-1.5 py-1 text-left hover:bg-paper-3 transition-colors"
				aria-label={email ? `Account menu for ${email}` : "Account menu"}
			>
				<span
					aria-hidden
					className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-accent-tint text-accent-ink pp-serif text-[11px]"
				>
					{initial}
				</span>
				<span className="min-w-0 flex-1">
					<span className="block truncate text-[12px] font-medium text-ink">
						{label}
					</span>
					{email && (
						<span className="block truncate text-[10px] text-ink-3">
							{email}
						</span>
					)}
				</span>
			</Menu.Trigger>
			<Menu.Portal>
				<Menu.Positioner sideOffset={4} align="start" side="top" className="z-50">
					<Menu.Popup
						aria-label="Account menu"
						className="min-w-[200px] rounded-md border border-line bg-paper py-1 shadow-lg outline-none"
					>
						{email && (
							// Static identity header — not a MenuItem so it isn't
							// arrow-key-selectable. Mirrors the MailboxSwitcher
							// empty-state blurb pattern.
							<div className="px-3 py-1.5 border-b border-line mb-1">
								<div className="text-[10px] uppercase tracking-[0.06em] text-ink-3">
									Signed in as
								</div>
								<div className="truncate text-[12px] text-ink">{email}</div>
							</div>
						)}
						<Menu.Item
							onClick={handleSettings}
							className="mx-1 flex cursor-pointer items-center gap-2 rounded-sm px-2 py-1.5 text-[12.5px] text-ink-2 outline-none data-[highlighted]:bg-paper-2"
						>
							<GearSixIcon size={14} className="shrink-0 text-ink-3" />
							<span>Org settings</span>
						</Menu.Item>
						{/*
						 * Sign-out is rendered as a `Menu.Item` wrapping a real
						 * anchor so base-ui keyboard activation (Enter / Space)
						 * reaches the navigation, the link is right-clickable
						 * (open in new tab if the operator wants), and the
						 * `href` is directly assertable in tests. We let the
						 * browser perform a full navigation — Access expects to
						 * receive a top-level GET, not an SPA route push — so
						 * deliberately *not* `navigate()`. `onClose` runs first
						 * so the mobile drawer collapses before the navigation.
						 */}
						<Menu.Item
							render={
								<a
									href={ACCESS_LOGOUT_URL}
									onClick={() => onClose()}
								/>
							}
							className="mx-1 flex cursor-pointer items-center gap-2 rounded-sm px-2 py-1.5 text-[12.5px] text-ink-2 outline-none data-[highlighted]:bg-paper-2"
						>
							<SignOutIcon size={14} className="shrink-0 text-ink-3" />
							<span>Sign out</span>
						</Menu.Item>
					</Menu.Popup>
				</Menu.Positioner>
			</Menu.Portal>
		</Menu.Root>
	);
}
