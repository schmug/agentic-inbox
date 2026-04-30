// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { useQuery } from "@tanstack/react-query";
import { useEffect, useRef } from "react";
import api from "~/services/api";
import { queryKeys } from "~/queries/keys";
import { useMailboxes } from "~/queries/mailboxes";

/**
 * Idempotent best-effort: when `EMAIL_ADDRESSES` is configured server-side,
 * create one mailbox per address on first load if it doesn't already exist.
 *
 * Lives in a shared hook so both `/` (org overview) and `/mailboxes` (picker)
 * can call it on mount — whichever route the operator lands on first
 * provisions the configured fleet. The internal `autoCreateDone` ref guards
 * against double-firing within a single mounted instance; routes are mutually
 * exclusive, so cross-route double-firing is not a concern.
 */
export function useAutoProvisionMailboxes() {
	const {
		data: mailboxes = [],
		refetch: refetchMailboxes,
		isFetched: mailboxesFetched,
	} = useMailboxes();

	const { data: configData } = useQuery({
		queryKey: queryKeys.config,
		queryFn: () => api.getConfig(),
		staleTime: Infinity,
	});

	const emailAddresses = configData?.emailAddresses ?? [];
	const autoCreateDone = useRef(false);

	useEffect(() => {
		if (autoCreateDone.current) return;
		if (emailAddresses.length === 0 || !mailboxesFetched) return;
		const existingEmails = new Set(
			mailboxes.map((m) => m.email.toLowerCase()),
		);
		const toCreate = emailAddresses.filter(
			(addr) => !existingEmails.has(addr.toLowerCase()),
		);
		if (toCreate.length === 0) {
			autoCreateDone.current = true;
			return;
		}
		autoCreateDone.current = true;
		let cancelled = false;
		Promise.all(
			toCreate.map((addr) => {
				const localPart = addr.split("@")[0] || addr;
				return api.createMailbox(addr, localPart).catch(() => {});
			}),
		).then(() => {
			if (!cancelled) refetchMailboxes();
		});
		return () => {
			cancelled = true;
		};
	}, [emailAddresses, mailboxes, mailboxesFetched, refetchMailboxes]);
}
