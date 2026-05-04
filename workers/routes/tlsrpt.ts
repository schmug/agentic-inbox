// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * TLS-RPT (RFC 8460) dashboard REST endpoints. Mounted under
 * `/api/v1/mailboxes/:mailboxId/tlsrpt`. Mirrors `routes/dmarc.ts`.
 */

import { Hono } from "hono";
import { requireMailbox, type MailboxContext } from "../lib/mailbox";

export const tlsrptRoutes = new Hono<MailboxContext>();

tlsrptRoutes.use("*", requireMailbox);

tlsrptRoutes.get("/reports", async (c) => {
	const domain = c.req.query("domain") ?? undefined;
	const limit = Number(c.req.query("limit") ?? 50);
	const offset = Number(c.req.query("offset") ?? 0);
	const reports = await c.var.mailboxStub.listTlsRptReports({ domain, limit, offset });
	return c.json({ reports });
});

tlsrptRoutes.get("/reports/:reportId/records", async (c) => {
	const reportId = c.req.param("reportId");
	const records = await c.var.mailboxStub.getTlsRptRecords(reportId);
	return c.json({ records });
});

tlsrptRoutes.get("/summary", async (c) => {
	const domain = c.req.query("domain");
	if (!domain) return c.json({ error: "domain query param required" }, 400);
	const [sources, failures] = await Promise.all([
		c.var.mailboxStub.getTlsRptSummary(domain),
		c.var.mailboxStub.getTlsRptFailureRollup(domain),
	]);
	return c.json({ domain, sources, failures });
});
