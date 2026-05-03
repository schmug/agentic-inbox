// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import api from "~/services/api";
import { queryKeys } from "./keys";

export function useOrgSettings() {
	return useQuery({
		queryKey: queryKeys.org.settings,
		queryFn: () => api.getOrgSettings(),
	});
}

export function useUpdateOrgSettings() {
	const qc = useQueryClient();
	return useMutation({
		mutationFn: (settings: unknown) => api.updateOrgSettings(settings),
		onSuccess: () => {
			qc.invalidateQueries({ queryKey: queryKeys.org.settings });
			// Org changes ripple to every mailbox's resolved view.
			qc.invalidateQueries({ queryKey: ["mailboxes"] });
		},
	});
}

export function useEffectiveMailboxSettings(mailboxId: string | undefined) {
	return useQuery({
		queryKey: mailboxId
			? queryKeys.effectiveMailboxSettings(mailboxId)
			: ["effective", "_disabled"],
		queryFn: () => api.getEffectiveMailboxSettings(mailboxId!),
		enabled: !!mailboxId,
	});
}
