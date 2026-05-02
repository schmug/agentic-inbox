// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { useQuery } from "@tanstack/react-query";
import { TEXT_MODELS } from "shared/mailbox-settings";
import api from "~/services/api";
import { queryKeys } from "./keys";

/**
 * Workers AI text-generation models (#64).
 *
 * Calls the worker's `/api/v1/ai/text-models` endpoint, which itself
 * does a read-through KV cache against the Cloudflare API and falls
 * back to the curated `TEXT_MODELS` constant when the upstream call
 * isn't possible. The hook surfaces a fallback `models` value so the
 * Settings dropdown is never empty even on transient errors.
 */
export function useTextModels() {
	const query = useQuery<{ models: string[] }>({
		queryKey: queryKeys.textModels,
		queryFn: ({ signal }) => api.getTextModels({ signal }),
		// Worker caches at 1h; client refresh on this scale doesn't
		// need to be tighter than 5 min.
		staleTime: 5 * 60_000,
	});
	return {
		...query,
		models: query.data?.models ?? [...TEXT_MODELS],
	};
}
