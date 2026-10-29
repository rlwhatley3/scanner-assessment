import { Link, Navigate, NavLink, Route, Routes, useMatch } from "react-router-dom";
import GuideView, { PlaygroundHome } from "./guide/GuideView.tsx";
import RuleSetsView, { VersionRedirect } from "./rule-sets/RuleSetsView.tsx";
import RulesView from "./rules/RulesView.tsx";
import ScanView from "./scan/ScanView.tsx";
import { ActiveSessionProvider } from "./session.tsx";
import SessionsView from "./sessions/SessionsView.tsx";
import { useApiHealth } from "./useApiHealth.ts";
import "./style.css";

const SECTIONS = [
  { to: "/playground/guide", label: "Guide" },
  { to: "/playground/scan", label: "Scan" },
  { to: "/playground/rules", label: "Rules" },
  { to: "/playground/rule-sets", label: "Rule sets" },
  { to: "/playground/sessions", label: "Sessions" },
];

export default function PlaygroundView() {
  const health = useApiHealth();
  const onScan = useMatch("/playground/scan") !== null;

  return (
    <ActiveSessionProvider>
      <main className="page-content playground">
        <header className="playground-header">
          <div>
            <h1>Secrets Scanner Playground</h1>
            <p className="intro">
              Paste text and scan it for secrets. Change what counts as a secret in Rules, and group
              rules into Rule sets to scan with.{" "}
              <Link to="/playground/guide">How does this work?</Link>
            </p>
          </div>
          <span className={`api-status ${health}`} role="status">
            <span className="status" aria-hidden="true" />
            {health === "checking"
              ? "Checking API…"
              : health === "online"
                ? "API connected"
                : "API unreachable"}
          </span>
        </header>

        <nav className="playground-menu" aria-label="Playground sections">
          {SECTIONS.map((section) => (
            <NavLink key={section.to} to={section.to} className="playground-menu-item">
              {section.label}
            </NavLink>
          ))}
        </nav>

        {/* Always mounted, so pasted text and a running scan survive visits to other sections. */}
        <ScanView visible={onScan} />
        <Routes>
          <Route index element={<PlaygroundHome />} />
          <Route path="guide" element={<GuideView />} />
          <Route path="scan" element={null} />
          <Route path="rules/:ruleId?" element={<RulesView />} />
          {/* One route, so picking a version doesn't remount the page and lose its state. */}
          <Route path="rule-sets/*" element={<RuleSetsView />} />
          <Route path="versions/:versionId" element={<VersionRedirect />} />
          <Route path="sessions/:sessionId?" element={<SessionsView />} />
          <Route path="*" element={<Navigate to="scan" replace />} />
        </Routes>
      </main>
    </ActiveSessionProvider>
  );
}
