// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

import { useQuery } from "@tanstack/react-query";
import api from "~/services/api";
import { queryKeys } from "./keys";

/**
 * Authenticated-user identity for the current session (#204). Sourced from
 * the worker's `/api/v1/me` endpoint, which reads the verified-by-Access
 * `Cf-Access-Authenticated-User-Email` header. Drives the Shell sidebar
 * account menu — the email is the single piece of identity we surface
 * today (no display name; Access doesn't ship one through the header
 * channel).
 */
export function useMe() {
	return useQuery<{ email: string }>({
		queryKey: queryKeys.me,
		queryFn: () => api.getMe() as Promise<{ email: string }>,
		// Identity rarely changes within a session — keep the cache long
		// so the menu doesn't flicker on remount and we don't refetch on
		// every focus-cycle.
		staleTime: 5 * 60 * 1000,
	});
}
