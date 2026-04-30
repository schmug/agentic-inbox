// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

import { reactRouter } from "@react-router/dev/vite";
import { cloudflare } from "@cloudflare/vite-plugin";
import tailwindcss from "@tailwindcss/vite";
import { defineConfig } from "vite";
import tsconfigPaths from "vite-tsconfig-paths";
import path from "node:path";

// `wrangler.jsonc` marks the `send_email` binding as `remote: true`, which
// makes the Cloudflare vite plugin authenticate against the deployed Worker
// at startup. That Worker sits behind Cloudflare Access, so without service-
// token creds the dev server fails to boot. Only enable remote bindings when
// the contributor has opted in via direnv / their shell (see README).
const hasAccessCreds = Boolean(
  process.env.CLOUDFLARE_ACCESS_CLIENT_ID &&
    process.env.CLOUDFLARE_ACCESS_CLIENT_SECRET,
);

export default defineConfig({
  plugins: [
    cloudflare({
      viteEnvironment: { name: "ssr" },
      remoteBindings: hasAccessCreds,
    }),
    tailwindcss(),
    reactRouter(),
    tsconfigPaths(),
  ],
  server: {
    fs: {
      // When running inside a git worktree, node_modules resolves to the parent
      // checkout. Allow Vite to serve files from the repo root one level up.
      allow: [path.resolve(__dirname, "..", "..", "..")],
    },
  },
});
