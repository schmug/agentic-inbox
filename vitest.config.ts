// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Vitest configuration for the security pipeline harness.
 *
 * Deliberately uses the default Node pool (with forks for isolation) rather
 * than `@cloudflare/vitest-pool-workers`. The pipeline tests drive
 * `runSecurityPipeline` with in-memory fakes for Env bindings — running them
 * in a real Workers runtime would couple the test suite to `wrangler dev`
 * startup and slow CI with no additional coverage.
 */

import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		include: ["test/**/*.test.ts"],
		pool: "forks",
		globals: false,
		environment: "node",
		testTimeout: 10000,
	},
});
