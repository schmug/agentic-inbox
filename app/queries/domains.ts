// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { useQuery } from "@tanstack/react-query";
import api from "~/services/api";
import type { DomainListEntry, DomainStats } from "~/types";
import { queryKeys } from "./keys";

/**
 * `/api/v1/domains` — domains list with aggregate stats (#85). The worker
 * caches the merged result for 60s, so a 30s client stale window keeps
 * navigation snappy without serving data older than ~90s.
 */
export function useDomains() {
	return useQuery<DomainListEntry[]>({
		queryKey: queryKeys.domains.list,
		queryFn: ({ signal }) =>
			api.listDomains({ signal }) as Promise<DomainListEntry[]>,
		staleTime: 30_000,
	});
}

export function useDomainStats(domain: string | undefined) {
	return useQuery<DomainStats>({
		queryKey: domain ? queryKeys.domains.detail(domain) : ["domains", "_disabled"],
		queryFn: ({ signal }) =>
			api.getDomainStats(domain!, { signal }) as Promise<DomainStats>,
		enabled: !!domain,
		staleTime: 30_000,
	});
}
