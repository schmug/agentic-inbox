// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Send and preflight endpoints for issue #15 slice 3.
 * Mounted under `/api/v1/mailboxes/:mailboxId` in workers/index.ts.
 */

import { Hono } from "hono";
import { sendEmail } from "../email-sender";
import { storeAttachments } from "../lib/attachments";
import {
	validateSender,
	SenderValidationError,
	generateMessageId,
	buildThreadingHeaders,
} from "../lib/email-helpers";
import { SendEmailRequestSchema } from "../lib/schemas";
import { classifySend } from "../security/send-risk";
import { verifyConfirmationToken, computePayloadHash } from "../lib/confirm-token";
import { requireMailbox, type MailboxContext } from "../lib/mailbox";
import { Folders } from "../../shared/folders";

export const sendEmailRoutes = new Hono<MailboxContext>();

sendEmailRoutes.use("*", requireMailbox);

sendEmailRoutes.post("/emails/preflight", async (c) => {
	const mailboxId = c.req.param("mailboxId")!;
	const body = SendEmailRequestSchema.parse(await c.req.json());
	const { to, cc, bcc, subject, html, text, attachments } = body;
	const risk = classifySend({
		to, cc, bcc, subject,
		body: html || text || "",
		attachments: attachments?.map((a) => ({ filename: a.filename })),
		mailboxId,
	});
	return c.json(risk);
});

sendEmailRoutes.post("/emails", async (c) => {
	const mailboxId = c.req.param("mailboxId")!;
	const body = SendEmailRequestSchema.parse(await c.req.json());
	const { to, cc, bcc, from, subject, html, text, attachments, in_reply_to, references, thread_id } = body;

	let toStr: string, fromEmail: string, fromDomain: string;
	try {
		({ toStr, fromEmail, fromDomain } = validateSender(to, from, mailboxId));
	} catch (e) {
		if (e instanceof SenderValidationError) return c.json({ error: e.message }, 400);
		throw e;
	}

	const risk = classifySend({
		to, cc, bcc, subject,
		body: html || text || "",
		attachments: attachments?.map((a) => ({ filename: a.filename })),
		mailboxId,
	});
	if (risk.tier >= 1) {
		const confirmationToken = c.req.header("x-confirmation-token");
		if (!confirmationToken) {
			return c.json({ error: "confirmation_required", risk }, 401);
		}
		const { CONFIRMATION_TOKEN_SECRET, BLOOM_KV } = c.env;
		if (CONFIRMATION_TOKEN_SECRET && BLOOM_KV) {
			const payloadHash = await computePayloadHash(
				to,
				subject,
				html || text || "",
				[],
			);
			const verified = await verifyConfirmationToken(
				confirmationToken,
				CONFIRMATION_TOKEN_SECRET,
				mailboxId,
				payloadHash,
				BLOOM_KV,
			);
			if (!verified) return c.json({ error: "invalid or expired confirmation token" }, 401);
		}
	}

	const { messageId, outgoingMessageId } = generateMessageId(fromDomain);
	const stub = c.var.mailboxStub;
	const rateLimitError = await (stub as any).checkSendRateLimit();
	if (rateLimitError) return c.json({ error: rateLimitError }, 429);
	const attachmentData = await storeAttachments(c.env.BUCKET, messageId, attachments);

	await stub.createEmail(Folders.SENT, {
		id: messageId, subject, sender: fromEmail, recipient: toStr,
		cc: cc ? (Array.isArray(cc) ? cc.join(", ") : cc).toLowerCase() : null,
		bcc: bcc ? (Array.isArray(bcc) ? bcc.join(", ") : bcc).toLowerCase() : null,
		date: new Date().toISOString(), body: html || text || "",
		in_reply_to: in_reply_to || null, email_references: references ? JSON.stringify(references) : null,
		thread_id: thread_id || in_reply_to || messageId, message_id: outgoingMessageId,
		raw_headers: JSON.stringify([
			{ key: "from", value: typeof from === "string" ? from : `${from.name} <${from.email}>` },
			{ key: "to", value: Array.isArray(to) ? to.join(", ") : to },
			...(cc ? [{ key: "cc", value: Array.isArray(cc) ? cc.join(", ") : cc }] : []),
			...(bcc ? [{ key: "bcc", value: Array.isArray(bcc) ? bcc.join(", ") : bcc }] : []),
			{ key: "subject", value: subject }, { key: "date", value: new Date().toISOString() },
			{ key: "message-id", value: `<${outgoingMessageId}>` },
		]),
	}, attachmentData);

	c.executionCtx.waitUntil(
		sendEmail(c.env.EMAIL, {
			to, cc, bcc, from, subject, html, text,
			attachments: attachments?.map((att) => ({ content: att.content, filename: att.filename, type: att.type, disposition: att.disposition || "attachment", contentId: att.contentId })),
			...(in_reply_to ? { headers: buildThreadingHeaders(in_reply_to, references || []) } : {}),
		}).catch((e) => console.error("Deferred email delivery failed:", (e as Error).message)),
	);
	return c.json({ id: messageId, status: "sent" }, 202);
});
