import {
	BriefcaseIcon,
	BuildingsIcon,
	EnvelopeIcon,
	GaugeIcon,
	GearSixIcon,
	GlobeIcon,
	GraphIcon,
	ListIcon,
	MagnifyingGlassIcon,
	MoonIcon,
	SparkleIcon,
	SunIcon,
	TrayIcon,
	XIcon,
} from "@phosphor-icons/react";
import { type FormEvent, type ReactNode, useEffect, useRef, useState } from "react";
import { NavLink, useLocation, useMatch, useNavigate, useParams } from "react-router";
import { useUIStore } from "~/hooks/useUIStore";
import { useDashboardSummary } from "~/queries/dashboard";
import { useDomainStats } from "~/queries/domains";
import { useMailbox, useMailboxes } from "~/queries/mailboxes";
import type { DomainMailboxRef, Mailbox } from "~/types";
import AgentPanelSlot from "./AgentPanelSlot";
import Breadcrumb from "./Breadcrumb";
import Logo from "./Logo";
import MailboxSwitcher from "./MailboxSwitcher";
import NotificationsBell from "./NotificationsBell";

type PipelineTone = "safe" | "suspect" | "danger" | "muted";

interface PipelineState {
	tone: PipelineTone;
	label: string;
	pulse: boolean;
}

// Map the dashboard summary's pipelineSuccess (0..1, or null) to a visible
// pill state. Thresholds match the issue spec (#86): >=0.95 healthy, >=0.5
// degraded, otherwise failing. Null/loading shows muted "No data" — never a
// fake-green dot.
function computePipelineState(
	pipelineSuccess: number | null | undefined,
): PipelineState {
	if (pipelineSuccess == null) {
		return { tone: "muted", label: "No data", pulse: false };
	}
	if (pipelineSuccess >= 0.95) {
		return { tone: "safe", label: "Pipeline online", pulse: true };
	}
	if (pipelineSuccess >= 0.5) {
		return { tone: "suspect", label: "Degraded", pulse: false };
	}
	return { tone: "danger", label: "Pipeline failing", pulse: false };
}

const PIPELINE_DOT_BG: Record<PipelineTone, string> = {
	safe: "bg-safe",
	suspect: "bg-suspect",
	danger: "bg-danger",
	muted: "bg-ink-4",
};

interface NavItemProps {
	to: string;
	icon: ReactNode;
	label: string;
	count?: number | string;
	end?: boolean;
}

function NavItem({ to, icon, label, count, end }: NavItemProps) {
	return (
		<NavLink
			to={to}
			end={end}
			className={({ isActive }) =>
				`relative flex items-center gap-2.5 px-3 py-1.5 rounded-md text-[13px] transition-colors ${
					isActive
						? "bg-paper-3 text-ink"
						: "text-ink-2 hover:bg-paper-2 hover:text-ink"
				}`
			}
		>
			{({ isActive }) => (
				<>
					{isActive && (
						<span
							aria-hidden
							className="absolute left-[-12px] top-1/2 -translate-y-1/2 h-4 w-[2px] rounded-full bg-accent"
						/>
					)}
					<span className="shrink-0 text-current">{icon}</span>
					<span className="flex-1 truncate">{label}</span>
					{count !== undefined && (
						<span className="pp-mono text-[11px] text-ink-3 tabular-nums">
							{count}
						</span>
					)}
				</>
			)}
		</NavLink>
	);
}

function SectionLabel({ children }: { children: ReactNode }) {
	return (
		<div className="px-3 pt-4 pb-1.5 text-[10.5px] uppercase tracking-[0.08em] text-ink-3">
			{children}
		</div>
	);
}

interface NavContentsProps {
	mailboxId: string | undefined;
	mailbox: { name?: string | null; email?: string | null } | undefined;
	mailboxes: Mailbox[] | undefined;
	mailboxCount: number;
	pipelineState: PipelineState;
	theme: "light" | "dark";
	onToggleTheme: () => void;
	onCloseSidebar: () => void;
	onPipelineClick: () => void;
	/**
	 * When the current route is `/domains/:domain`, the active domain plus
	 * the mailboxes that belong to it (#139). Both fields are gated so other
	 * routes never pay the network cost: `domain` is `undefined` off-route,
	 * and `domainMailboxes` is `undefined` while the query is pending so the
	 * sidebar can fall back to the org-level nav instead of flashing an
	 * empty list.
	 */
	domain: string | undefined;
	domainMailboxes: DomainMailboxRef[] | undefined;
}

// Shared sidebar contents — rendered inline on `md+` and inside the mobile
// drawer on `<md`. Keeping a single source of truth here means the next
// nav-item addition only has to touch one place.
function NavContents({
	mailboxId,
	mailbox,
	mailboxes,
	mailboxCount,
	pipelineState,
	theme,
	onToggleTheme,
	onCloseSidebar,
	onPipelineClick,
	domain,
	domainMailboxes,
}: NavContentsProps) {
	const base = mailboxId ? `/mailbox/${encodeURIComponent(mailboxId)}` : "";

	return (
		<>
			<div className="px-4 pt-4 pb-3">
				<Logo />
			</div>

			{/* Mailbox switcher (#188). Replaces the old "Select mailbox" card,
			    which was wired to `navigate("/")` and therefore a no-op at the
			    org root. The new card opens a base-ui Menu listing every
			    mailbox the user has access to; selecting one navigates to the
			    per-mailbox dashboard. */}
			<MailboxSwitcher
				activeMailboxId={mailboxId}
				mailbox={mailbox}
				mailboxes={mailboxes}
				mailboxCount={mailboxCount}
				onClose={onCloseSidebar}
			/>

			<nav className="mt-3 px-3 flex-1 overflow-y-auto">
				{/* Org-scoped entries are always visible. They route to / and
				    /mailboxes respectively, regardless of which mailbox is
				    currently selected. */}
				<NavItem
					to="/"
					end
					icon={<BuildingsIcon size={16} />}
					label="Org overview"
				/>
				<NavItem
					to="/mailboxes"
					icon={<EnvelopeIcon size={16} />}
					label="Mailboxes"
					count={mailboxCount > 0 ? mailboxCount : undefined}
				/>
				<NavItem
					to="/domains"
					icon={<GlobeIcon size={16} />}
					label="Domains"
				/>
				{/* Org-wide settings (#153) — surfaced as a top-level entry so
				    operators can reach `/settings` from a cold start, without
				    first picking a mailbox. The per-mailbox `Settings` entry
				    below is unaffected; that one stays mailbox-scoped. */}
				<NavItem
					to="/settings"
					end
					icon={<GearSixIcon size={16} />}
					label="Org settings"
				/>
				{mailboxId && (
					<>
						<SectionLabel>This mailbox</SectionLabel>
						<NavItem
							to={`${base}/dashboard`}
							icon={<GaugeIcon size={16} />}
							label="Dashboard"
						/>
						<NavItem
							to={`${base}/cases`}
							icon={<BriefcaseIcon size={16} />}
							label="Cases"
						/>
						<NavItem
							to={`${base}/emails/inbox`}
							icon={<TrayIcon size={16} />}
							label="Mail review"
						/>
						<NavItem
							to={`${base}/hub`}
							icon={<GraphIcon size={16} />}
							label="Threat-intel hub"
						/>
						<SectionLabel>System</SectionLabel>
						<NavItem
							to={`${base}/settings`}
							icon={<GearSixIcon size={16} />}
							label="Settings"
						/>
					</>
				)}
				{/* Domain-scoped block (#139): on `/domains/:domain` surface the
				    mailboxes that belong to the domain, mirroring the
				    mailbox-scoped block above. Only render once the query has
				    resolved — while pending we fall through to the org-level
				    nav rather than flashing an empty list or "undefined". */}
				{domain && domainMailboxes && domainMailboxes.length > 0 && (
					<>
						<SectionLabel>Mailboxes in {domain}</SectionLabel>
						{domainMailboxes.map((mb) => (
							<NavItem
								key={mb.id}
								to={`/mailbox/${encodeURIComponent(mb.id)}/dashboard`}
								icon={<EnvelopeIcon size={16} />}
								label={mb.email || mb.name || mb.id}
							/>
						))}
					</>
				)}
			</nav>

			{/* Pipeline status pill. State derives from the dashboard summary's
			    `pipelineSuccess` (#86); real p95 latency is now surfaced as a
			    KPI on the Operations dashboard (#71). The pill stays scoped to
			    success/failure so the sidebar reads as a status indicator
			    rather than a metric. */}
			{mailboxId && (
				<button
					type="button"
					role="status"
					aria-live="polite"
					aria-label={`Pipeline status: ${pipelineState.label}`}
					onClick={onPipelineClick}
					className="mx-3 mb-3 flex items-center gap-2 rounded-md border border-line bg-paper px-2.5 py-1.5 text-left hover:border-line-strong transition-colors"
				>
					<span className="relative flex h-2 w-2">
						{pipelineState.pulse && (
							<span
								aria-hidden
								className={`absolute inline-flex h-full w-full animate-ping rounded-full opacity-60 ${PIPELINE_DOT_BG[pipelineState.tone]}`}
							/>
						)}
						<span
							aria-hidden
							className={`relative inline-flex h-2 w-2 rounded-full ${PIPELINE_DOT_BG[pipelineState.tone]}`}
						/>
					</span>
					<span className="text-[11px] text-ink-2">
						{pipelineState.label}
					</span>
				</button>
			)}

			<div className="border-t border-line px-3 py-2.5 flex items-center gap-2">
				<div className="flex h-7 w-7 items-center justify-center rounded-full bg-accent-tint text-accent-ink text-[11px] font-medium">
					SA
				</div>
				<div className="flex-1 min-w-0">
					<div className="text-[12px] text-ink truncate">SOC analyst</div>
					<div className="text-[10.5px] text-ink-3 truncate">Preview</div>
				</div>
				<button
					type="button"
					onClick={onToggleTheme}
					className="flex h-7 w-7 items-center justify-center rounded-md text-ink-3 hover:bg-paper-3 hover:text-ink transition-colors"
					aria-label={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
				>
					{theme === "dark" ? <SunIcon size={14} /> : <MoonIcon size={14} />}
				</button>
			</div>
		</>
	);
}

interface ShellProps {
	children: ReactNode;
	/**
	 * Optional right-hand content that shares the main column. Today this hosts
	 * the agent + MCP panel (#82); the slot is responsible for choosing
	 * in-flow (xl+) vs slide-over (<xl) rendering based on viewport.
	 */
	rightPanel?: ReactNode;
}

export default function Shell({ children, rightPanel }: ShellProps) {
	const { mailboxId } = useParams<{ mailboxId: string }>();
	const navigate = useNavigate();
	const location = useLocation();
	const {
		theme,
		toggleTheme,
		isSidebarOpen,
		openSidebar,
		closeSidebar,
		isAgentPanelOpen,
		toggleAgentPanel,
	} = useUIStore();
	const { data: mailbox } = useMailbox(mailboxId);
	const { data: mailboxes } = useMailboxes();
	const mailboxCount = mailboxes?.length ?? 0;

	const { data: dashboardSummary } = useDashboardSummary(mailboxId);
	const pipelineState = computePipelineState(dashboardSummary?.pipelineSuccess);

	// `/domains/:domain` (#139). Use a route match rather than `useParams`
	// because Shell can be rendered from either the per-domain route or the
	// per-mailbox route; only the former should pull domain stats. The
	// `useDomainStats` hook is `enabled: !!domain` internally, so passing
	// `undefined` off-route is the gate that keeps other pages from paying
	// the network cost.
	const domainMatch = useMatch("/domains/:domain");
	const rawDomain = domainMatch?.params.domain;
	const activeDomain = rawDomain ? decodeURIComponent(rawDomain) : undefined;
	const { data: domainStats } = useDomainStats(activeDomain);

	const searchInputRef = useRef<HTMLInputElement>(null);
	const [searchQuery, setSearchQuery] = useState("");

	useEffect(() => {
		// Cmd/Ctrl+K from anywhere focuses the search input. Escape closes the
		// mobile drawer if it's open.
		const onKey = (e: KeyboardEvent) => {
			if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
				e.preventDefault();
				searchInputRef.current?.focus();
				searchInputRef.current?.select();
				return;
			}
			if (e.key === "Escape" && useUIStore.getState().isSidebarOpen) {
				e.preventDefault();
				useUIStore.getState().closeSidebar();
			}
		};
		window.addEventListener("keydown", onKey);
		return () => window.removeEventListener("keydown", onKey);
	}, []);

	// Close the mobile drawer whenever the route changes. The mailbox-switch
	// effect in routes/mailbox.tsx covers cross-mailbox navigation; this covers
	// in-mailbox nav (Dashboard ↔ Cases etc.), so individual NavItem onClicks
	// don't have to remember to dismiss.
	useEffect(() => {
		closeSidebar();
	}, [location.pathname, closeSidebar]);

	const handleSearchSubmit = (e: FormEvent<HTMLFormElement>) => {
		e.preventDefault();
		const q = searchQuery.trim();
		if (!q || !mailboxId) return;
		navigate(
			`/mailbox/${encodeURIComponent(mailboxId)}/search?q=${encodeURIComponent(q)}`,
		);
	};

	const navContents = (
		<NavContents
			mailboxId={mailboxId}
			mailbox={mailbox}
			mailboxes={mailboxes}
			mailboxCount={mailboxCount}
			pipelineState={pipelineState}
			theme={theme}
			onToggleTheme={toggleTheme}
			onCloseSidebar={closeSidebar}
			onPipelineClick={() => {
				if (!mailboxId) return;
				closeSidebar();
				navigate(`/mailbox/${encodeURIComponent(mailboxId)}/dashboard`);
			}}
			domain={activeDomain}
			domainMailboxes={domainStats?.mailboxes}
		/>
	);

	return (
		<div className="flex h-screen overflow-hidden bg-paper text-ink">
			{/* Sidebar — 232px on desktop. On `<md` the same contents are surfaced
			    via the hamburger drawer below. */}
			<aside className="hidden md:flex w-[232px] shrink-0 flex-col bg-paper-2 border-r border-line">
				{navContents}
			</aside>

			{/* Mobile drawer — backdrop + slide-over. Kept out of the DOM when
			    closed so Esc/click-outside listeners aren't always attached and
			    the desktop test surface stays unchanged. */}
			{isSidebarOpen && (
				<>
					<div
						data-testid="mobile-drawer-backdrop"
						aria-hidden
						className="md:hidden fixed inset-0 z-40 bg-black/50"
						onClick={closeSidebar}
					/>
					<aside
						role="dialog"
						aria-label="Primary navigation"
						className="md:hidden fixed left-0 top-0 bottom-0 z-50 w-[260px] max-w-[85vw] flex flex-col bg-paper-2 border-r border-line shadow-xl"
					>
						<button
							type="button"
							onClick={closeSidebar}
							aria-label="Close menu"
							className="absolute right-2 top-2 flex h-8 w-8 items-center justify-center rounded-md text-ink-3 hover:bg-paper-3 hover:text-ink transition-colors"
						>
							<XIcon size={16} />
						</button>
						{navContents}
					</aside>
				</>
			)}

			{/* Main column. Topbar pinned, content scrolls. */}
			<div className="flex-1 flex flex-col min-w-0">
				<header className="flex items-center gap-3 h-[52px] px-4 md:px-6 border-b border-line bg-paper">
					<button
						type="button"
						onClick={openSidebar}
						aria-label="Open menu"
						aria-expanded={isSidebarOpen}
						className="md:hidden flex h-8 w-8 items-center justify-center rounded-md text-ink-3 hover:bg-paper-2 hover:text-ink transition-colors shrink-0"
					>
						<ListIcon size={18} />
					</button>
					<form
						role="search"
						onSubmit={handleSearchSubmit}
						className="flex items-center gap-2 flex-1 max-w-xl"
					>
						<MagnifyingGlassIcon
							size={14}
							className={`shrink-0 ${mailboxId ? "text-ink-3" : "text-ink-4"}`}
						/>
						{/*
						 * Search today is mailbox-scoped: the only registered route is
						 * `/mailbox/:mailboxId/search`, and the submit handler bails when
						 * `mailboxId` is missing. On org-level routes (`/`, `/settings`,
						 * `/mailboxes`, `/domains`, `/domains/:domain`) we surface a
						 * disabled input with explanatory placeholder so cmd+K + Enter
						 * doesn't appear to silently swallow the query (#187). Org-scope
						 * search across every mailbox the user can see is tracked
						 * separately.
						 */}
						<input
							ref={searchInputRef}
							type="search"
							value={searchQuery}
							onChange={(e) => setSearchQuery(e.target.value)}
							disabled={!mailboxId}
							aria-disabled={!mailboxId}
							className="flex-1 bg-transparent border-0 outline-none text-[13px] text-ink placeholder:text-ink-4 disabled:cursor-not-allowed"
							placeholder={
								mailboxId
									? "Search emails…  ⌘K"
									: "Pick a mailbox to search emails"
							}
							aria-label="Search"
						/>
					</form>
					<div className="ml-auto flex items-center gap-1.5 shrink-0">
						<NotificationsBell mailboxId={mailboxId} />
						{/* The agent panel only mounts inside `/mailbox/:mailboxId/*`
						    routes (mailbox.tsx is the only caller passing
						    `rightPanel={<AgentSidebar />}`). On org-level routes
						    (`/`, `/settings`, `/mailboxes`, `/domains`,
						    `/domains/:domain`) clicking the button toggled
						    internal state but nothing visible happened — silent
						    no-op (#186). Until an org-scope co-pilot ships
						    (follow-up #198), gate the trigger on `mailboxId` so
						    the button only fires where it can do work. We render
						    `disabled` with a `title` tooltip rather than hiding
						    so the affordance stays discoverable and the topbar
						    layout doesn't shift when entering a mailbox. */}
						<button
							type="button"
							onClick={() => toggleAgentPanel()}
							disabled={!mailboxId}
							aria-disabled={!mailboxId}
							title={
								mailboxId
									? undefined
									: "Pick a mailbox to chat with the agent"
							}
							aria-expanded={mailboxId ? isAgentPanelOpen : undefined}
							aria-controls="agent-panel"
							className={`flex items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-[12px] font-medium transition-colors ${
								!mailboxId
									? "bg-paper-2 text-ink-3 border-line cursor-not-allowed opacity-60"
									: isAgentPanelOpen
									? "bg-accent text-paper border-accent hover:bg-[color-mix(in_oklch,var(--accent)_85%,black)]"
									: "bg-accent-tint text-accent border-[color-mix(in_oklch,var(--accent)_25%,transparent)] hover:bg-[color-mix(in_oklch,var(--accent-tint)_70%,var(--paper))]"
							}`}
						>
							<SparkleIcon
								size={13}
								weight="fill"
								className={
									!mailboxId
										? "text-ink-3"
										: isAgentPanelOpen
										? "text-paper"
										: "text-accent"
								}
							/>
							Ask co-pilot
						</button>
					</div>
				</header>

				{/* Main + optional right panel share a flex row so the in-flow
				    panel (xl+) shrinks the children's column instead of overlaying.
				    Below xl the slot renders a slide-over that owns its own
				    positioning and doesn't push the main column. */}
				<div className="flex-1 flex min-h-0 overflow-hidden">
					<main className="flex-1 min-w-0 overflow-y-auto flex flex-col">
						{/* Breadcrumb shows org → mailbox → section context.
						    Hidden at "/" since the org root is implied. */}
						<Breadcrumb />
						<div className="flex-1 min-h-0">{children}</div>
					</main>
					{rightPanel && <AgentPanelSlot rightPanel={rightPanel} />}
				</div>
			</div>
		</div>
	);
}
