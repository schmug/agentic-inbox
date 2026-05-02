// shared/mailbox-settings.ts
// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { z } from "zod";

/**
 * Per-mailbox settings stored at R2 key `mailboxes/<mailboxId>.json`.
 *
 * The schema is intentionally lenient on the write side (passthrough) so
 * future fields can land without coordinated frontend/backend deploys.
 * Strict on the read side: every consumer that reads a typed field uses
 * `MailboxSettings.parse(...)` which fills in defaults.
 *
 * `security` is a typed sub-shape: only `attachment_policy` and
 * `folder_policies` are validated here — the rest of the object is
 * passthrough so unrelated security fields (allowlist_senders, thresholds,
 * business_hours, etc.) round-trip untouched. Defaults intentionally NOT
 * set in the schema; the runtime consumer in `workers/security/settings.ts`
 * (`getSecuritySettings`) is the single source of default values, and
 * duplicating them here would invite drift.
 */

const AttachmentAction = z.enum(["block", "score", "ignore"]);

const AttachmentPolicy = z
  .object({
    executable_action: AttachmentAction.optional(),
    container_action: AttachmentAction.optional(),
    macro_office_action: AttachmentAction.optional(),
    custom_blocklist_extensions: z.array(z.string()).optional(),
  })
  .passthrough();

const FolderPolicy = z
  .object({
    mode: z.enum(["skip_all", "skip_classifier"]).optional(),
    treat_as_verified: z.boolean().optional(),
  })
  .passthrough();

const SecuritySettings = z
  .object({
    attachment_policy: AttachmentPolicy.optional(),
    folder_policies: z.record(z.string(), FolderPolicy).optional(),
  })
  .passthrough();

/**
 * Per-mailbox MISP-compatible threat-intel hub config (#97).
 *
 * Mirrors the backend `HubConfig` interface in `workers/lib/hub-config.ts`.
 * The API key itself is NEVER persisted in R2 — only the *name* of a worker
 * secret (`api_key_secret_name`) is stored, and the worker resolves the live
 * value from `c.env` at call time. That way an org can rotate the key with
 * `wrangler secret put` without rewriting the mailbox JSON.
 *
 * `loadHubConfig` requires `url`, `org_uuid`, and `api_key_secret_name` to be
 * non-empty strings, so the schema marks them required when `hub` is present.
 * The whole `intel` block is optional + passthrough so unrelated future intel
 * fields (#29 peer subscriptions) round-trip without a coordinated deploy.
 */
const HubConfig = z
  .object({
    url: z.string().min(1),
    org_uuid: z.string().min(1),
    api_key_secret_name: z.string().min(1),
    default_sharing_group_uuid: z.string().optional(),
    auto_report: z.boolean().optional(),
  })
  .passthrough();

const IntelSettings = z
  .object({
    hub: HubConfig.optional(),
  })
  .passthrough();

export const MailboxSettings = z.object({
  agentSystemPrompt: z.string().optional(),
  autoDraft: z
    .object({
      enabled: z.boolean().default(true),
    })
    .default({ enabled: true }),
  agentModel: z.string().default("@cf/moonshotai/kimi-k2.5"),
  /**
   * Optional per-mailbox override for the prompt-injection scanner model
   * (#67). Falls back to `DEFAULT_INJECTION_SCANNER_MODEL` when undefined.
   * Wrong choice can let injections through — defaults are intentionally
   * hardcoded to a tested model.
   */
  injectionScannerModel: z.string().optional(),
  /**
   * Optional per-mailbox override for the draft-verifier model (#67).
   * Falls back to `DEFAULT_DRAFT_VERIFIER_MODEL` when undefined.
   */
  draftVerifierModel: z.string().optional(),
  /**
   * Optional per-mailbox override for the LLM email classifier (#67).
   * Falls back to `DEFAULT_CLASSIFIER_MODEL` when undefined.
   */
  classifierModel: z.string().optional(),
  security: SecuritySettings.optional(),
  intel: IntelSettings.optional(),
}).passthrough();

export type MailboxSettings = z.infer<typeof MailboxSettings>;

/** The hand-curated list shown in the Settings model dropdown. The first
 *  entry MUST match the default in MailboxSettings.agentModel above so an
 *  unconfigured mailbox renders with a list option selected, not "Custom". */
export const TEXT_MODELS = [
  "@cf/moonshotai/kimi-k2.5",
  "@cf/meta/llama-3.3-70b-instruct-fp8-fast",
] as const;

/**
 * Defaults for the three security-critical AI surfaces (#67). These mirror
 * the hardcoded values in the worker call sites and are exported so the
 * settings UI can show them as the placeholder when no override is set.
 *
 * Switching the injection-scanner or classifier model can degrade
 * detection — only override when you know what you're doing.
 */
export const DEFAULT_INJECTION_SCANNER_MODEL =
  "@cf/meta/llama-3.1-8b-instruct-fast";
export const DEFAULT_DRAFT_VERIFIER_MODEL =
  "@cf/meta/llama-4-scout-17b-16e-instruct";
export const DEFAULT_CLASSIFIER_MODEL = "@cf/meta/llama-3.1-8b-instruct-fast";
