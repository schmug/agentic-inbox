// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Per-mailbox access-control list (#27).
 *
 * ACLs are stored at R2 key `mailboxes-acl/<mailboxId>.json` — separate
 * from the settings blob at `mailboxes/<mailboxId>.json` so a settings PUT
 * never clobbers them, and the existing `listMailboxes` prefix scan over
 * `mailboxes/` doesn't pick them up.
 *
 * Backwards-compat invariant: when no ACL blob exists (pre-#27 mailboxes or
 * single-user deploys without CF Access in front), `callerInAcl` returns
 * true — anyone admitted by the global CF Access policy retains full access.
 */

export interface MailboxAcl {
	/** Email of the user who created the mailbox (lower-cased). */
	owner: string;
	/** All emails permitted to access the mailbox (always includes owner). */
	members: string[];
}

function aclKey(mailboxId: string): string {
	return `mailboxes-acl/${mailboxId}.json`;
}

export async function readMailboxAcl(
	env: { BUCKET: R2Bucket },
	mailboxId: string,
): Promise<MailboxAcl | null> {
	const obj = await env.BUCKET.get(aclKey(mailboxId));
	if (!obj) return null;
	try {
		return await obj.json<MailboxAcl>();
	} catch {
		return null;
	}
}

export async function writeMailboxAcl(
	env: { BUCKET: R2Bucket },
	mailboxId: string,
	acl: MailboxAcl,
): Promise<void> {
	await env.BUCKET.put(aclKey(mailboxId), JSON.stringify(acl));
}

export async function deleteMailboxAcl(
	env: { BUCKET: R2Bucket },
	mailboxId: string,
): Promise<void> {
	await env.BUCKET.delete(aclKey(mailboxId));
}

/**
 * Returns true when `callerEmail` should be granted access to the mailbox.
 *
 * - `acl === null`: no ACL written yet → allow anyone (backwards-compat for
 *   pre-#27 mailboxes and single-user deploys).
 * - `callerEmail` falsy: CF Access not in front (local dev) → allow.
 * - Otherwise: caller must appear in `acl.members` (case-insensitive).
 */
export function callerInAcl(
	acl: MailboxAcl | null,
	callerEmail: string | null | undefined,
): boolean {
	if (acl === null) return true;
	if (!callerEmail) return true;
	const lower = callerEmail.toLowerCase();
	return acl.members.some((m) => m.toLowerCase() === lower);
}
