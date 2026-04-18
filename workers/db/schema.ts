// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

import { sqliteTable, text, integer, real, primaryKey } from "drizzle-orm/sqlite-core";

export const folders = sqliteTable("folders", {
	id: text("id").primaryKey(),
	name: text("name").notNull().unique(),
	is_deletable: integer("is_deletable").notNull().default(1),
});

export const emails = sqliteTable("emails", {
	id: text("id").primaryKey(),
	folder_id: text("folder_id")
		.notNull()
		.references(() => folders.id, { onDelete: "cascade" }),
	subject: text("subject"),
	sender: text("sender"),
	recipient: text("recipient"),
	cc: text("cc"),
	bcc: text("bcc"),
	date: text("date"),
	read: integer("read").default(0),
	starred: integer("starred").default(0),
	body: text("body"),
	in_reply_to: text("in_reply_to"),
	email_references: text("email_references"),
	thread_id: text("thread_id"),
	message_id: text("message_id"),
	raw_headers: text("raw_headers"),
	security_verdict: text("security_verdict"),
	security_score: integer("security_score"),
	security_explanation: text("security_explanation"),
	deep_scan_status: text("deep_scan_status").default("pending"),
});

export const attachments = sqliteTable("attachments", {
	id: text("id").primaryKey(),
	email_id: text("email_id")
		.notNull()
		.references(() => emails.id, { onDelete: "cascade" }),
	filename: text("filename").notNull(),
	mimetype: text("mimetype").notNull(),
	size: integer("size").notNull(),
	content_id: text("content_id"),
	disposition: text("disposition"),
	scan_status: text("scan_status").default("pending"),
	scan_verdict: text("scan_verdict"),
});

// ── Security ─────────────────────────────────────────────────────

export const urls = sqliteTable("urls", {
	id: text("id").primaryKey(),
	email_id: text("email_id")
		.notNull()
		.references(() => emails.id, { onDelete: "cascade" }),
	url: text("url").notNull(),
	display_text: text("display_text"),
	is_homograph: integer("is_homograph").notNull().default(0),
	is_shortener: integer("is_shortener").notNull().default(0),
	resolved_url: text("resolved_url"),
	page_title: text("page_title"),
	fetch_status: text("fetch_status").default("pending"),
	verdict: text("verdict"),
	created_at: text("created_at").notNull().default("CURRENT_TIMESTAMP"),
});

export const senderReputation = sqliteTable("sender_reputation", {
	sender: text("sender").primaryKey(),
	first_seen: text("first_seen").notNull(),
	last_seen: text("last_seen").notNull(),
	message_count: integer("message_count").notNull().default(1),
	avg_score: real("avg_score").notNull().default(50.0),
	flagged: integer("flagged").notNull().default(0),
});

// ── Threat intel ─────────────────────────────────────────────────

export const intelFeedState = sqliteTable("intel_feed_state", {
	feed_id: text("feed_id").primaryKey(),
	url: text("url").notNull(),
	last_fetched_at: text("last_fetched_at"),
	etag: text("etag"),
	entry_count: integer("entry_count"),
	bloom_kv_key: text("bloom_kv_key"),
});

// ── DMARC ────────────────────────────────────────────────────────

export const dmarcReports = sqliteTable("dmarc_reports", {
	id: text("id").primaryKey(),
	received_at: text("received_at").notNull(),
	org_name: text("org_name"),
	report_id: text("report_id"),
	domain: text("domain").notNull(),
	date_range_begin: text("date_range_begin"),
	date_range_end: text("date_range_end"),
	policy_p: text("policy_p"),
	raw_r2_key: text("raw_r2_key"),
});

export const dmarcRecords = sqliteTable("dmarc_records", {
	id: text("id").primaryKey(),
	report_id: text("report_id")
		.notNull()
		.references(() => dmarcReports.id, { onDelete: "cascade" }),
	source_ip: text("source_ip").notNull(),
	count: integer("count").notNull(),
	disposition: text("disposition"),
	dkim_result: text("dkim_result"),
	spf_result: text("spf_result"),
	header_from: text("header_from"),
});

export const dmarcSources = sqliteTable("dmarc_sources", {
	source_ip: text("source_ip").primaryKey(),
	label: text("label"),
	legitimate: integer("legitimate").notNull().default(0),
	notes: text("notes"),
});

// ── Cases (TheHive-lite) ─────────────────────────────────────────

export const cases = sqliteTable("cases", {
	id: text("id").primaryKey(),
	created_at: text("created_at").notNull().default("CURRENT_TIMESTAMP"),
	updated_at: text("updated_at").notNull().default("CURRENT_TIMESTAMP"),
	status: text("status").notNull().default("open"),
	title: text("title").notNull(),
	notes: text("notes"),
	shared_to_hub: integer("shared_to_hub").notNull().default(0),
	hub_event_uuid: text("hub_event_uuid"),
});

export const caseEmails = sqliteTable(
	"case_emails",
	{
		case_id: text("case_id")
			.notNull()
			.references(() => cases.id, { onDelete: "cascade" }),
		email_id: text("email_id").notNull(),
	},
	(t) => ({
		pk: primaryKey({ columns: [t.case_id, t.email_id] }),
	}),
);

export const caseObservables = sqliteTable("case_observables", {
	id: text("id").primaryKey(),
	case_id: text("case_id")
		.notNull()
		.references(() => cases.id, { onDelete: "cascade" }),
	kind: text("kind").notNull(),
	value: text("value").notNull(),
});
