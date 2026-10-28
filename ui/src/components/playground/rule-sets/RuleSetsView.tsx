import { useState } from "react";
import { Link, NavLink, useNavigate, useParams } from "react-router-dom";
import {
  createSession,
  formatDate,
  getVersion,
  listVersions,
  type RuleSetVersionDetail,
  ruleName,
  setVersionArchived,
} from "../api.ts";
import { describeChecksum } from "../checksum.ts";
import { useActiveSession } from "../session.tsx";
import { DETECTION_LABELS, SEVERITY_LABELS, SeverityIcon } from "../severity.tsx";
import { useLoad } from "../useLoad.ts";
import VersionComposer from "./VersionComposer.tsx";

type Composing = { parent: RuleSetVersionDetail | null } | null;

export default function RuleSetsView() {
  const { versionId } = useParams();
  const navigate = useNavigate();
  const { setSession } = useActiveSession();
  const [showArchived, setShowArchived] = useState(false);
  const [composing, setComposing] = useState<Composing>(null);
  const [error, setError] = useState<string | null>(null);

  const versions = useLoad(() => listVersions(showArchived), [showArchived]);
  const id = versionId === undefined ? null : Number(versionId);
  const detail = useLoad(() => (id === null ? Promise.resolve(null) : getVersion(id)), [id]);
  const version = detail.data?.id === id ? detail.data : null;

  async function archive(archived: boolean) {
    if (!version) return;
    setError(null);
    try {
      await setVersionArchived(version.id, archived);
      if (archived && !showArchived) setShowArchived(true);
      versions.reload();
      detail.reload();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not update the version.");
    }
  }

  async function startSession() {
    if (!version) return;
    setError(null);
    try {
      setSession(await createSession(version.id));
      navigate("/playground/scan");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not start a session.");
    }
  }

  // Newest first reads best as a timeline.
  const timeline = [...(versions.data ?? [])].reverse();

  return (
    <div className="playground-section master-detail">
      <section className="panel master" aria-label="Rule set versions">
        <div className="master-header">
          <h2>Rule set versions</h2>
          <button
            type="button"
            className="button primary"
            onClick={() => setComposing({ parent: null })}
          >
            New version
          </button>
        </div>
        <label className="findings-sort">
          <input
            type="checkbox"
            checked={showArchived}
            onChange={(event) => setShowArchived(event.target.checked)}
          />
          Show archived
        </label>
        {versions.error && (
          <p className="banner error" role="alert">
            {versions.error}
          </p>
        )}
        {versions.data?.length === 0 && (
          <p className="muted">No versions yet. Save your rules as the first version.</p>
        )}
        <ol className="master-list timeline">
          {timeline.map((entry) => (
            <li key={entry.id}>
              <NavLink
                to={`/playground/rule-sets/${entry.id}`}
                className="master-item"
                onClick={() => setComposing(null)}
              >
                <span className="master-item-title">Version {entry.id}</span>
                <span className="muted small">
                  {entry.ruleCount} {entry.ruleCount === 1 ? "rule" : "rules"} ·{" "}
                  {entry.scanSessionCount} {entry.scanSessionCount === 1 ? "session" : "sessions"}
                  {entry.parentId !== null && ` · from v${entry.parentId}`}
                </span>
                {entry.archived && (
                  <span className="badges">
                    <span className="badge">Archived</span>
                  </span>
                )}
              </NavLink>
            </li>
          ))}
        </ol>
      </section>

      <section className="panel detail" aria-label="Rule set version details">
        {composing ? (
          <VersionComposer
            key={composing.parent?.id ?? "new"}
            parent={composing.parent}
            onCancel={() => setComposing(null)}
            onCreated={(created) => {
              setComposing(null);
              versions.reload();
              navigate(`/playground/rule-sets/${created.id}`);
            }}
          />
        ) : version ? (
          <div className="version-detail">
            <header className="rule-form-header">
              <div>
                <h2>
                  Version {version.id}
                  {version.archived && <span className="badge">Archived</span>}
                </h2>
                <p className="muted">
                  Saved {formatDate(version.createdAt)}
                  {version.parentId !== null && (
                    <>
                      {" "}
                      · based on{" "}
                      <Link to={`/playground/rule-sets/${version.parentId}`}>
                        version {version.parentId}
                      </Link>
                    </>
                  )}{" "}
                  · {version.scanSessionCount}{" "}
                  {version.scanSessionCount === 1 ? "scan session" : "scan sessions"}
                </p>
              </div>
            </header>
            <div className="form-actions">
              <button
                type="button"
                className="button primary"
                onClick={startSession}
                disabled={version.archived}
              >
                Start scan session
              </button>
              <button
                type="button"
                className="button"
                onClick={() => setComposing({ parent: version })}
              >
                New version from this
              </button>
              <button type="button" className="button" onClick={() => archive(!version.archived)}>
                {version.archived ? "Restore" : "Archive"}
              </button>
            </div>
            {error && (
              <p className="banner error" role="alert">
                {error}
              </p>
            )}
            <table className="data-table">
              <thead>
                <tr>
                  <th>Rule</th>
                  <th>Severity</th>
                  <th>Type</th>
                  <th>Pattern</th>
                  <th>Checksum</th>
                </tr>
              </thead>
              <tbody>
                {version.rules.map(({ ruleId, definition }) => (
                  <tr
                    key={ruleId}
                    className={definition.enabled === false ? "disabled" : undefined}
                  >
                    <td>
                      <Link to={`/playground/rules/${ruleId}`}>{ruleName(definition, ruleId)}</Link>
                      {definition.enabled === false && <span className="badge">Disabled</span>}
                    </td>
                    <td>
                      {definition.severity && (
                        <>
                          <SeverityIcon tone={definition.severity} />{" "}
                          {SEVERITY_LABELS[definition.severity]}
                        </>
                      )}
                    </td>
                    <td>
                      {definition.detectionType && DETECTION_LABELS[definition.detectionType]}
                    </td>
                    <td>
                      <code className="pattern">{definition.pattern}</code>
                    </td>
                    <td>{describeChecksum(definition.checksum) ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="results-placeholder">
            {detail.error ?? "Select a version, or start a new one."}
          </p>
        )}
      </section>
    </div>
  );
}
