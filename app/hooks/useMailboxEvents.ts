// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

import { useEffect } from "react";

export interface MailboxEvent {
	type: "new-email";
	id: string;
	folder: string;
}

/**
 * Subscribe to a mailbox's realtime event stream. Auth piggybacks on the
 * Cloudflare Access cookie attached to same-origin WebSocket upgrades.
 *
 * Reconnects with simple jittered backoff. Backoff resets on a successful
 * `open`; component unmount or a `mailboxId` change closes the socket and
 * cancels any pending reconnect.
 */
export function useMailboxEvents(
	mailboxId: string | undefined,
	onEvent: (event: MailboxEvent) => void,
) {
	useEffect(() => {
		if (!mailboxId) return;
		if (typeof window === "undefined") return;

		let ws: WebSocket | null = null;
		let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
		let attempt = 0;
		let cancelled = false;

		const url = (() => {
			const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
			return `${proto}//${window.location.host}/api/v1/mailboxes/${encodeURIComponent(mailboxId)}/events`;
		})();

		const connect = () => {
			if (cancelled) return;
			ws = new WebSocket(url);

			ws.addEventListener("open", () => {
				attempt = 0;
			});

			ws.addEventListener("message", (e) => {
				if (typeof e.data !== "string") return;
				try {
					const parsed = JSON.parse(e.data) as MailboxEvent;
					if (parsed && parsed.type === "new-email") onEvent(parsed);
				} catch {
					// Ignore malformed frames.
				}
			});

			ws.addEventListener("close", () => {
				if (cancelled) return;
				attempt += 1;
				// 1s, 2s, 4s, ... capped at 30s, with up to 1s of jitter.
				const base = Math.min(30_000, 1_000 * 2 ** Math.min(attempt - 1, 5));
				const delay = base + Math.random() * 1_000;
				reconnectTimer = setTimeout(connect, delay);
			});
		};

		connect();

		return () => {
			cancelled = true;
			if (reconnectTimer) clearTimeout(reconnectTimer);
			if (ws && ws.readyState <= WebSocket.OPEN) ws.close();
		};
	}, [mailboxId, onEvent]);
}
