// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import api from "~/services/api";
import { queryKeys } from "./keys";

export function useDomainSettings(domain: string | undefined) {
	return useQuery({
		queryKey: domain ? queryKeys.domains.settings(domain) : ["domains", "_disabled"],
		queryFn: () => api.getDomainSettings(domain!),
		enabled: !!domain,
	});
}

export function useUpdateDomainSettings(domain: string | undefined) {
	const qc = useQueryClient();
	return useMutation({
		mutationFn: (settings: unknown) => api.updateDomainSettings(domain!, settings),
		onSuccess: () => {
			if (domain) {
				qc.invalidateQueries({ queryKey: queryKeys.domains.settings(domain) });
			}
			// Domain changes ripple to every mailbox under it; the resolved
			// view depends on this tier. Invalidate the whole mailboxes
			// subtree (cheap) rather than enumerating mailbox ids.
			qc.invalidateQueries({ queryKey: ["mailboxes"] });
		},
	});
}
