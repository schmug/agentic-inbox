import { Link, useLocation, useParams } from "react-router";
import { useMailbox } from "~/queries/mailboxes";

interface Segment {
	label: string;
	to?: string;
}

const FOLDER_LABELS: Record<string, string> = {
	inbox: "Inbox",
	sent: "Sent",
	draft: "Drafts",
	archive: "Archive",
	trash: "Trash",
	quarantine: "Quarantine",
};

// Map a route path + params to a list of breadcrumb segments. Returns
// null when the breadcrumb should be hidden (org overview / not-found).
function segmentsFor(
	pathname: string,
	mailboxId: string | undefined,
	mailboxLabel: string,
	mailboxEmail: string | undefined,
): Segment[] | null {
	if (pathname === "/" || pathname === "") return null;

	const orgRoot: Segment = { label: "Org", to: "/" };

	if (pathname.startsWith("/mailboxes")) {
		return [orgRoot, { label: "Mailboxes" }];
	}

	// `/settings` (org settings, #184). Org-level settings have no
	// per-resource params — render a simple two-segment chain so the
	// page is reachable-back from inside.
	if (pathname === "/settings" || pathname === "/settings/") {
		return [orgRoot, { label: "Org settings" }];
	}

	// `/domains`, `/domains/:domain`, and `/domains/:domain/settings`
	// (#85, #184). Read the domain from the path rather than a hook —
	// the breadcrumb has no router param for these top-level routes.
	// Decode in case a future caller percent-encodes.
	const domainsRoot: Segment = { label: "Domains", to: "/domains" };
	if (pathname === "/domains" || pathname === "/domains/") {
		return [orgRoot, { label: "Domains" }];
	}
	if (pathname.startsWith("/domains/")) {
		const tail = pathname.slice("/domains/".length).replace(/\/$/, "");
		// Split at most once: domain segment + optional sub-route. The
		// domain itself is a single path segment (no slashes), so this
		// is unambiguous.
		const slashIdx = tail.indexOf("/");
		const rawDomain = slashIdx === -1 ? tail : tail.slice(0, slashIdx);
		const sub = slashIdx === -1 ? "" : tail.slice(slashIdx + 1);
		const domain = decodeURIComponent(rawDomain);
		if (!domain) {
			return [orgRoot, { label: "Domains" }];
		}
		const domainHref = `/domains/${encodeURIComponent(domain)}`;
		if (sub === "settings") {
			return [
				orgRoot,
				domainsRoot,
				{ label: domain, to: domainHref },
				{ label: "Settings" },
			];
		}
		// `/domains/:domain` and any unknown sub-routes: link Domains
		// back to the list so users can step up one level (#184).
		return [orgRoot, domainsRoot, { label: domain }];
	}

	if (!mailboxId) return null;

	const base = `/mailbox/${encodeURIComponent(mailboxId)}`;
	const mailboxSegment: Segment = { label: mailboxLabel, to: base };
	// Inject a domain segment between Org and the mailbox label when the
	// mailbox query has resolved. Defensive on the loading case: skip the
	// extra segment until `mailbox.email` is available so we don't flash
	// "undefined". Links to the per-domain drill-down at `/domains/:domain`.
	const domain = mailboxEmail?.split("@")[1]?.toLowerCase();
	const orgChain: Segment[] = domain
		? [orgRoot, { label: domain, to: `/domains/${encodeURIComponent(domain)}` }]
		: [orgRoot];

	const tail = pathname.slice(base.length);

	if (tail === "" || tail === "/") {
		return [...orgChain, { label: mailboxLabel }];
	}

	if (tail.startsWith("/dashboard")) {
		return [...orgChain, mailboxSegment, { label: "Dashboard" }];
	}
	if (tail.startsWith("/settings")) {
		return [...orgChain, mailboxSegment, { label: "Settings" }];
	}
	if (tail.startsWith("/search")) {
		return [...orgChain, mailboxSegment, { label: "Search" }];
	}
	if (tail.startsWith("/dmarc")) {
		return [...orgChain, mailboxSegment, { label: "DMARC" }];
	}
	if (tail.startsWith("/hub")) {
		return [...orgChain, mailboxSegment, { label: "Threat-intel hub" }];
	}
	if (tail.startsWith("/cases")) {
		const casesSegment: Segment = { label: "Cases", to: `${base}/cases` };
		// /cases/:caseId — derive the trailing case id from the path so
		// this works regardless of which route matched (e.g. when a
		// parent route uses a wildcard match).
		const caseId = tail.split("/")[2];
		if (caseId) {
			return [...orgChain, mailboxSegment, casesSegment, { label: caseId }];
		}
		return [...orgChain, mailboxSegment, { label: "Cases" }];
	}
	if (tail.startsWith("/emails/")) {
		const folder = tail.split("/")[2] ?? "";
		const folderLabel = FOLDER_LABELS[folder.toLowerCase()] ?? folder;
		return [...orgChain, mailboxSegment, { label: folderLabel }];
	}

	return [...orgChain, mailboxSegment];
}

export default function Breadcrumb() {
	const location = useLocation();
	const { mailboxId } = useParams<{ mailboxId?: string }>();
	const { data: mailbox } = useMailbox(mailboxId);

	const mailboxLabel = mailbox?.email ?? mailbox?.name ?? mailboxId ?? "Mailbox";
	const segments = segmentsFor(
		location.pathname,
		mailboxId,
		mailboxLabel,
		mailbox?.email,
	);

	if (!segments || segments.length === 0) return null;

	return (
		<nav
			aria-label="Breadcrumb"
			className="flex items-center gap-1.5 px-4 md:px-6 py-2 text-[12px] text-ink-3 border-b border-line bg-paper"
		>
			<ol className="flex items-center gap-1.5 min-w-0">
				{segments.map((segment, idx) => {
					const isLast = idx === segments.length - 1;
					return (
						<li
							key={`${segment.label}-${idx}`}
							className="flex items-center gap-1.5 min-w-0"
						>
							{idx > 0 && (
								<span
									aria-hidden
									className="pp-mono text-ink-4 select-none"
								>
									›
								</span>
							)}
							{segment.to && !isLast ? (
								<Link
									to={segment.to}
									className="truncate hover:text-ink transition-colors"
								>
									{segment.label}
								</Link>
							) : (
								<span
									className={`truncate ${isLast ? "text-ink" : ""}`}
									aria-current={isLast ? "page" : undefined}
								>
									{segment.label}
								</span>
							)}
						</li>
					);
				})}
			</ol>
		</nav>
	);
}
