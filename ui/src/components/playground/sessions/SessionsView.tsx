import { Link, NavLink, useNavigate, useParams } from "react-router-dom";
import {
  formatDate,
  getSession,
  listSessions,
  listSuppressions,
  type SavedMatch,
  type StoredScan,
} from "../api.ts";
import { HelpLink } from "../guide/GuideView.tsx";
import { SlowRulesNote } from "../scan/SlowRules.tsx";
import SuppressionsPanel from "../scan/SuppressionsPanel.tsx";
import { useActiveSession } from "../session.tsx";
import { SEVERITY_LABELS, SeverityIcon } from "../severity.tsx";
import { useLoad } from "../useLoad.ts";

export default function SessionsView() {
  const { sessionId } = useParams();
  const navigate = useNavigate();
  const { session: active, setSession } = useActiveSession();
  const sessions = useLoad(listSessions, []);
  const id = sessionId === undefined ? null : Number(sessionId);
  const detail = useLoad(() => (id === null ? Promise.resolve(null) : getSession(id)), [id]);
  const session = detail.data?.id === id ? detail.data : null;
  const suppressions = useLoad(
    () => (id === null ? Promise.resolve([]) : listSuppressions(id)),
    [id],
  );

  function reopen() {
    if (!session) return;
    setSession(session);
    navigate("/playground/scan");
  }

  return (
    <div className="playground-section master-detail">
      <section className="panel master" aria-label="Scan sessions">
        <div className="master-header">
          <h2>
            Scan sessions <HelpLink section="sessions" label="How sessions work" />
          </h2>
        </div>
        <p className="muted small">
          Your first scan on the Scan tab starts a session. Each one keeps its scans' results and
          the values marked safe in it.
        </p>
        {sessions.error && (
          <p className="banner error" role="alert">
            {sessions.error}
          </p>
        )}
        {sessions.data?.length === 0 && (
          <p className="muted">
            No scan sessions yet. <Link to="/playground/scan">Run a scan</Link> to start one.
          </p>
        )}
        <ul className="master-list">
          {sessions.data?.map((entry) => (
            <li key={entry.id}>
              <NavLink to={`/playground/sessions/${entry.id}`} className="master-item">
                <span className="master-item-title">
                  Session {entry.id}
                  {active?.id === entry.id && <span className="badge subtle">Open</span>}
                </span>
                <span className="muted small">
                  {entry.ruleSetName} v{entry.versionNumber} · {entry.scanCount}{" "}
                  {entry.scanCount === 1 ? "scan" : "scans"} ·{" "}
                  {entry.activeSuppressionCount > 0 &&
                    `${entry.activeSuppressionCount} ${
                      entry.activeSuppressionCount === 1 ? "value" : "values"
                    } marked safe · `}
                  {entry.lastRan ? `last ran ${formatDate(entry.lastRan)}` : "not run yet"}
                </span>
              </NavLink>
            </li>
          ))}
        </ul>
      </section>

      <section className="panel detail" aria-label="Scan session details">
        {session ? (
          <div className="version-detail">
            <header className="rule-form-header">
              <div>
                <h2>Session {session.id}</h2>
                <p className="muted">
                  Started {formatDate(session.createdAt)} · rule set{" "}
                  <Link
                    to={`/playground/rule-sets/${session.ruleSetId}/versions/${session.ruleSetVersionId}`}
                  >
                    {session.ruleSetName} v{session.versionNumber}
                  </Link>
                </p>
              </div>
            </header>
            <div className="form-actions">
              <button type="button" className="button primary" onClick={reopen}>
                {active?.id === session.id ? "Back to scanning" : "Continue scanning"}
              </button>
            </div>
            <p className="muted small">
              Scan text is never stored, so past scans show where each finding was and which rule it
              broke, not the text itself.
            </p>
            <SuppressionsPanel sessionId={session.id} suppressions={suppressions} />
            {session.scans.length === 0 ? (
              <p className="muted">No scans in this session yet.</p>
            ) : (
              [...session.scans].reverse().map((scan) => <ScanSummary key={scan.id} scan={scan} />)
            )}
          </div>
        ) : (
          <p className="results-placeholder">
            {detail.error ?? "Select a session to see its scans, or continue scanning in it."}
          </p>
        )}
      </section>
    </div>
  );
}

function ScanSummary({ scan }: { scan: StoredScan }) {
  const matches = scan.findings.filter(
    (finding): finding is SavedMatch => finding.kind === "match",
  );
  const ruleErrors = scan.findings.filter((finding) => finding.kind === "rule_error");
  // A scan that never finished has no saved findings, which must not read as clean.
  const finished = scan.status === "completed";
  const outcome = !finished
    ? scan.status === "running"
      ? "Running"
      : "Interrupted"
    : ruleErrors.length > 0
      ? "Partial"
      : matches.length === 0
        ? "Clean"
        : "Findings";

  return (
    <article className="scan-summary">
      <h3>
        Scan {scan.id} · {formatDate(scan.createdAt)} ·{" "}
        <span className={`outcome ${outcome.toLowerCase()}`}>{outcome}</span>
        {scan.truncated && <span className="badge">Cut off at 200</span>}
        {scan.slowRules.length > 0 && <span className="badge">Slow</span>}
        {scan.suppressedCount > 0 && (
          <span className="badge subtle">{scan.suppressedCount} marked safe, not flagged</span>
        )}
      </h3>
      {!finished && (
        <p className="banner warning">
          {scan.status === "running"
            ? "This scan hasn't finished, so its results aren't here yet."
            : "This scan stopped before it finished, so its results weren't saved. It doesn't mean the text was clean. Scan the text again to check it."}
        </p>
      )}
      <SlowRulesNote slowRules={scan.slowRules} />
      {ruleErrors.length > 0 && (
        <ul className="banner warning">
          {ruleErrors.map((finding) => (
            <li key={finding.id}>
              {finding.violationPretty}{" "}
              <Link to={`/playground/rules/${finding.ruleId}`}>Fix rule</Link>
            </li>
          ))}
        </ul>
      )}
      {matches.length > 0 && (
        <table className="data-table">
          <thead>
            <tr>
              <th>Rule</th>
              <th>Severity</th>
              <th>Where</th>
              <th>Starts with</th>
            </tr>
          </thead>
          <tbody>
            {matches.map((finding) => {
              const { violation } = finding;
              return (
                <tr key={finding.id}>
                  <td>{violation.ruleName}</td>
                  <td>
                    <SeverityIcon tone={violation.severity} /> {SEVERITY_LABELS[violation.severity]}
                  </td>
                  <td>Line {violation.location.startLine}</td>
                  <td>{violation.redactedPreview && <code>{violation.redactedPreview}</code>}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </article>
  );
}
