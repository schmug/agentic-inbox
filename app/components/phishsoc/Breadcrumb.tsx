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
): Segment[] | null {
	if (pathname === "/" || pathname === "") return null;

	const orgRoot: Segment = { label: "Org", to: "/" };

	if (pathname.startsWith("/mailboxes")) {
		return [orgRoot, { label: "Mailboxes" }];
	}

	if (!mailboxId) return null;

	const base = `/mailbox/${encodeURIComponent(mailboxId)}`;
	const mailboxSegment: Segment = { label: mailboxLabel, to: base };

	const tail = pathname.slice(base.length);

	if (tail === "" || tail === "/") {
		return [orgRoot, { label: mailboxLabel }];
	}

	if (tail.startsWith("/dashboard")) {
		return [orgRoot, mailboxSegment, { label: "Dashboard" }];
	}
	if (tail.startsWith("/settings")) {
		return [orgRoot, mailboxSegment, { label: "Settings" }];
	}
	if (tail.startsWith("/search")) {
		return [orgRoot, mailboxSegment, { label: "Search" }];
	}
	if (tail.startsWith("/dmarc")) {
		return [orgRoot, mailboxSegment, { label: "DMARC" }];
	}
	if (tail.startsWith("/hub")) {
		return [orgRoot, mailboxSegment, { label: "Threat-intel hub" }];
	}
	if (tail.startsWith("/cases")) {
		const casesSegment: Segment = { label: "Cases", to: `${base}/cases` };
		// /cases/:caseId — derive the trailing case id from the path so
		// this works regardless of which route matched (e.g. when a
		// parent route uses a wildcard match).
		const caseId = tail.split("/")[2];
		if (caseId) {
			return [orgRoot, mailboxSegment, casesSegment, { label: caseId }];
		}
		return [orgRoot, mailboxSegment, { label: "Cases" }];
	}
	if (tail.startsWith("/emails/")) {
		const folder = tail.split("/")[2] ?? "";
		const folderLabel = FOLDER_LABELS[folder.toLowerCase()] ?? folder;
		return [orgRoot, mailboxSegment, { label: folderLabel }];
	}

	return [orgRoot, mailboxSegment];
}

export default function Breadcrumb() {
	const location = useLocation();
	const { mailboxId } = useParams<{ mailboxId?: string }>();
	const { data: mailbox } = useMailbox(mailboxId);

	const mailboxLabel = mailbox?.email ?? mailbox?.name ?? mailboxId ?? "Mailbox";
	const segments = segmentsFor(location.pathname, mailboxId, mailboxLabel);

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
