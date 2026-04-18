import { defineConfig } from "vitest/config";

/**
 * Vitest config for the security pipeline.
 *
 * Two suites live side-by-side:
 *   - `tests/**` — pure-function unit tests (parsing, scoring, aggregation).
 *     No Workers runtime required.
 *   - `test/**`  — integration harness that drives `runSecurityPipeline`
 *     end-to-end against in-memory fakes for Env bindings. Deliberately uses
 *     the default Node pool (with forks for isolation) rather than
 *     `@cloudflare/vitest-pool-workers` — the fakes are sufficient and
 *     spinning up the real Workers runtime would only slow CI.
 */
export default defineConfig({
	test: {
		include: ["tests/**/*.test.ts", "test/**/*.test.ts"],
		environment: "node",
		globals: false,
		pool: "forks",
		reporters: ["default"],
		testTimeout: 10000,
	},
});
