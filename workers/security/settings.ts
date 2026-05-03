// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Mailbox-effective security settings — thin wrapper around the inheritance
 * resolver from #106.
 *
 * Pre-#106 this module owned the field-by-field merge that filled in
 * security defaults from `mailboxes/{id}.json`. Post-#106, all merge
 * semantics live in `workers/lib/mailbox-settings.ts`
 * (`resolveMailboxSettings`), and this module just re-exposes the resolved
 * `security` block under the legacy function name + signature so the
 * triage/auth/url scoring pipeline doesn't have to learn about the
 * resolver's wider return shape.
 *
 * Defaults and the `MailboxSecuritySettings` type itself live in
 * `./defaults` to keep the import graph acyclic — the resolver imports
 * defaults, this wrapper imports the resolver, and a third party that just
 * wants the type or the constant can import directly from `./defaults`
 * (or, for back-compat, from this module via the re-exports below).
 */

import type { Env } from "../types";
import { resolveMailboxSettings } from "../lib/mailbox-settings";
import {
	DEFAULT_CLASSIFICATION_SETTINGS,
	DEFAULT_SECURITY_SETTINGS,
	type BusinessHours,
	type ClassificationSettings,
	type FolderPolicy,
	type MailboxSecuritySettings,
} from "./defaults";

// Back-compat re-exports — pre-#106 callers imported these from this module.
export {
	DEFAULT_CLASSIFICATION_SETTINGS,
	DEFAULT_SECURITY_SETTINGS,
	type BusinessHours,
	type ClassificationSettings,
	type FolderPolicy,
	type MailboxSecuritySettings,
};

/**
 * Return the effective security settings for a mailbox after running the
 * full inheritance hierarchy (mailbox > org > system default), with the
 * resolved block normalised (lowercased allowlists, etc.).
 *
 * Never throws — the resolver returns `DEFAULT_SECURITY_SETTINGS` when
 * neither tier set the block.
 */
export async function getSecuritySettings(
	env: Env,
	mailboxId: string,
): Promise<MailboxSecuritySettings> {
	const resolved = await resolveMailboxSettings(env, mailboxId);
	return resolved.security;
}
