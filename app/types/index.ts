// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

export interface SignatureSettings {
	enabled: boolean;
	text: string;
	html?: string;
}

export interface BusinessHoursSettings {
	timezone: string;
	start_hour: number;
	end_hour: number;
	weekdays_only: boolean;
	boost_on_off_hours: boolean;
}

export interface VerdictThresholdSettings {
	tag: number;
	quarantine: number;
	block: number;
}

export type AttachmentAction = "block" | "score" | "ignore";

export interface AttachmentPolicySettings {
	executable_action?: AttachmentAction;
	container_action?: AttachmentAction;
	macro_office_action?: AttachmentAction;
	custom_blocklist_extensions?: string[];
}

export interface FolderPolicySettings {
	mode?: "skip_all" | "skip_classifier";
	treat_as_verified?: boolean;
}

/**
 * Per-mailbox threat-intel hub config (#97). Mirrors the backend `HubConfig`
 * shape in `workers/lib/hub-config.ts`. `api_key_secret_name` holds the NAME
 * of a worker secret, not the secret value — the raw key never leaves
 * `wrangler secret put`.
 */
export interface HubConfigSettings {
	url?: string;
	org_uuid?: string;
	api_key_secret_name?: string;
	default_sharing_group_uuid?: string;
	auto_report?: boolean;
}

export interface IntelSettings {
	hub?: HubConfigSettings;
}

export interface SecuritySettings {
	enabled?: boolean;
	learning_mode?: boolean;
	thresholds?: VerdictThresholdSettings;
	allowlist_senders?: string[];
	allowlist_domains?: string[];
	trusted_authserv_ids?: string[];
	trusted_auto_allow?: boolean;
	trusted_auto_allow_min_messages?: number;
	intel_auto_block?: boolean;
	business_hours?: BusinessHoursSettings;
	attachment_policy?: AttachmentPolicySettings;
	folder_policies?: Record<string, FolderPolicySettings>;
}

export interface MailboxSettings {
	fromName?: string;
	forwarding?: { enabled: boolean; email: string };
	signature?: SignatureSettings;
	autoReply?: { enabled: boolean; subject: string; message: string };
	agentSystemPrompt?: string;
	security?: SecuritySettings;
	intel?: IntelSettings;
}

export interface Mailbox {
	id: string;
	email: string;
	name: string;
	settings?: MailboxSettings;
}

export interface Email {
	id: string;
	thread_id?: string | null;
	folder_id?: string | null;
	subject: string;
	sender: string;
	recipient: string;
	cc?: string;
	bcc?: string;
	date: string;
	read: boolean;
	starred: boolean;
	body?: string | null;
	in_reply_to?: string | null;
	email_references?: string | null;
	message_id?: string | null;
	raw_headers?: string | null;
	attachments?: Attachment[];
	snippet?: string | null;
	// Thread aggregate fields (only present in threaded list view)
	thread_count?: number;
	thread_unread_count?: number;
	participants?: string;
	needs_reply?: boolean;
	has_draft?: boolean;
	// Security pipeline verdict (null when the pipeline didn't run)
	security_verdict?: string | null;
	security_score?: number | null;
	security_explanation?: string | null;
}

/** Shape of the JSON stored in Email.security_verdict. */
export interface SecurityVerdict {
	action: "allow" | "tag" | "quarantine" | "block";
	score: number;
	explanation: string;
	auth: {
		spf: string;
		dkim: string;
		dmarc: string;
		authservId?: string;
	};
	classification: {
		label: "safe" | "spam" | "phishing" | "bec" | "suspicious";
		confidence: number;
		reasoning: string;
	};
	signals: string[];
	/** Present when a triage tier short-circuited the pipeline. */
	triage?: "hard_allow" | "hard_block" | "attachment_block" | "folder_bypass";
}

export function parseVerdict(raw: string | null | undefined): SecurityVerdict | null {
	if (!raw) return null;
	try {
		return JSON.parse(raw) as SecurityVerdict;
	} catch {
		return null;
	}
}

export interface Attachment {
	id: string;
	filename: string;
	mimetype: string;
	size: number;
	content_id?: string;
	disposition?: string;
}

export interface Folder {
	id: string;
	name: string;
	unreadCount: number;
}

export interface DashboardCase {
	id: string;
	title: string;
	status: string;
	updated_at: string;
}

export interface DashboardSummary {
	now: string;
	threatsBlocked: number;
	openCases: number;
	hubContributions: number;
	pipelineSuccess: number | null;
	/** 95th-percentile pipeline duration over the last 24h, in ms. Null when no completed runs. */
	p95Ms: number | null;
	threatPressure: number[];
	recentCases: DashboardCase[];
}

export interface OrgVerdictMix {
	safe: number;
	suspicious: number;
	phishing: number;
	spam: number;
	bec: number;
}

export interface OrgTopThreatSample {
	emailId: string;
	subject: string;
	sender: string;
}

export interface OrgTopThreat {
	category: string;
	count: number;
	/**
	 * Up to N representative emails per category, deduped across mailboxes
	 * (#101). Optional so older deploys without samples render the count-only
	 * card unchanged.
	 */
	samples?: OrgTopThreatSample[];
}

export interface OrgPipelineHealth {
	successRate24h: number | null;
	/** Org-wide p95 latency in ms — unioned per-mailbox samples (#71). */
	p95Ms: number | null;
	runs24h: number;
}

export interface OrgOverview {
	now: string;
	threatsBlocked24h: number;
	threatsBlocked7d: number;
	openCasesTotal: number;
	mailboxesCount: number;
	domainsCount: number;
	verdictMix: OrgVerdictMix;
	/** 7-day verdict mix (#103). Always present, sums per-mailbox tallies. */
	verdictMix7d: OrgVerdictMix;
	topThreats: OrgTopThreat[];
	pipelineHealth: OrgPipelineHealth;
	hubContributions24h: number;
}

export interface HubContribution {
	uuid: string;
	info: string;
	date: string;
	timestamp: string;
	sharing_group_uuid?: string;
	attribute_count: number;
}

export interface HubSharingGroup {
	uuid: string;
	name: string;
	description?: string;
	role?: string;
}

/**
 * Every hub UI endpoint returns this envelope. `configured: false` is the
 * normal state for a mailbox without `intel.hub` set; the UI renders one
 * "Configure hub credentials" panel and stops querying.
 */
export type HubEnvelope<T> = { configured: true; data: T } | { configured: false };

export type HubContributionsResponse = HubEnvelope<HubContribution[]>;
export type HubDestroylistResponse = HubEnvelope<{ values: string[]; count: number }>;
export type HubSharingGroupsResponse = HubEnvelope<{ groups: HubSharingGroup[] }>;

/**
 * Hub invite request — mirrors the hub `POST /orgs/invite` zod schema. All
 * fields optional; `sharing_group_uuid` binds the invite to a specific
 * sharing group (the hub returns 403 if the inviter isn't a member).
 */
export interface HubInviteRequest {
	sharing_group_uuid?: string;
	note?: string;
	ttl_hours?: number;
}

/** Hub invite response — token is returned ONCE; the modal must show it
 * immediately and clear it on close. `expires_at` is an ISO timestamp. */
export interface HubInviteResponse {
	token: string;
	expires_at: string;
}
