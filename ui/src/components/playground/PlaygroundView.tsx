import { Navigate, NavLink, Route, Routes, useMatch } from "react-router-dom";
import RuleSetsView from "./rule-sets/RuleSetsView.tsx";
import RulesView from "./rules/RulesView.tsx";
import ScanView from "./scan/ScanView.tsx";
import { ActiveSessionProvider } from "./session.tsx";
import SessionsView from "./sessions/SessionsView.tsx";
import { useApiHealth } from "./useApiHealth.ts";
import "./style.css";

const SECTIONS = [
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
              Write rules, save them as a rule set version, then scan text with it. Scan text is
              never saved; only results are.
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
          <Route index element={<Navigate to="scan" replace />} />
          <Route path="scan" element={null} />
          <Route path="rules/:ruleId?" element={<RulesView />} />
          <Route path="rule-sets/:versionId?" element={<RuleSetsView />} />
          <Route path="sessions/:sessionId?" element={<SessionsView />} />
          <Route path="*" element={<Navigate to="scan" replace />} />
        </Routes>
      </main>
    </ActiveSessionProvider>
  );
}
