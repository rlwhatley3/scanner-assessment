import { useEffect, useState } from "react";
import { Link, NavLink, useNavigate } from "react-router-dom";
import {
  formatDate,
  getRuleSet,
  getVersion,
  type RuleSetVersionDetail,
  ruleName,
  setVersionArchived,
  updateRuleSet,
  versionLabel,
} from "../api.ts";
import { describeChecksum } from "../checksum.ts";
import MoreMenu from "../MoreMenu.tsx";
import { useActiveSession } from "../session.tsx";
import { DETECTION_LABELS, SEVERITY_LABELS, SeverityIcon } from "../severity.tsx";
import { useLoad } from "../useLoad.ts";
import VersionComposer from "./VersionComposer.tsx";

interface RuleSetPanelProps {
  ruleSetId: number;
  /** The version to show; defaults to the set's latest. */
  versionId: number | null;
  /** Something in the set changed, so lists elsewhere should reload. */
  onChanged: () => void;
  /** Start a new rule set from a copy of this version. */
  onCopy: (versionId: number) => void;
}

export function versionPath(ruleSetId: number, versionId: number): string {
  return `/playground/rule-sets/${ruleSetId}/versions/${versionId}`;
}

/** A link to a version by id, labelled like "Payments v2" once it loads. */
export function VersionLink({ versionId }: { versionId: number }) {
  const version = useLoad(() => getVersion(versionId), [versionId]);
  return (
    <Link to={`/playground/versions/${versionId}`}>
      {version.data ? versionLabel(version.data) : `version ${versionId}`}
    </Link>
  );
}

/** One rule set: its name and description, its versions, and the selected version's rules. */
export default function RuleSetPanel({
  ruleSetId,
  versionId,
  onChanged,
  onCopy,
}: RuleSetPanelProps) {
  const navigate = useNavigate();
  const { session, setSession, setVersionChoice } = useActiveSession();
  const ruleSet = useLoad(() => getRuleSet(ruleSetId), [ruleSetId]);
  const [composing, setComposing] = useState<{ parent: RuleSetVersionDetail | null } | null>(null);
  const [editing, setEditing] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [error, setError] = useState<string | null>(null);

  const set = ruleSet.data?.id === ruleSetId ? ruleSet.data : null;
  const selectedId = versionId ?? set?.latestVersionId ?? set?.versions.at(-1)?.id ?? null;
  const detail = useLoad(
    () => (selectedId === null ? Promise.resolve(null) : getVersion(selectedId)),
    [selectedId],
  );
  const version = detail.data?.id === selectedId ? detail.data : null;

  // A different set or version starts with nothing open.
  // biome-ignore lint/correctness/useExhaustiveDependencies: reset only when the selection moves.
  useEffect(() => {
    setComposing(null);
    setEditing(false);
    setError(null);
  }, [ruleSetId, versionId]);

  function changed() {
    ruleSet.reload();
    detail.reload();
    onChanged();
  }

  async function run(action: () => Promise<unknown>, failure: string) {
    setError(null);
    try {
      await action();
      changed();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : failure);
    }
  }

  async function newVersion() {
    setError(null);
    const latest = set?.latestVersionId ?? null;
    try {
      setComposing({ parent: latest === null ? null : await getVersion(latest) });
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not load the latest version.");
    }
  }

  /** Opens Scan with this version chosen. The next scan starts a session with it. */
  function scanWith() {
    if (!version) return;
    if (session?.ruleSetVersionId !== version.id) {
      setSession(null);
      setVersionChoice(version.id);
    }
    navigate("/playground/scan");
  }

  if (!set) {
    return (
      <p className="results-placeholder">{ruleSet.error ?? (ruleSet.loading ? "Loading…" : "")}</p>
    );
  }

  if (composing) {
    return (
      <VersionComposer
        key={composing.parent?.id ?? "empty"}
        ruleSet={set}
        parent={composing.parent}
        onCancel={() => setComposing(null)}
        onCreated={(created) => {
          setComposing(null);
          changed();
          navigate(versionPath(set.id, created.id));
        }}
      />
    );
  }

  // Newest first reads best as a timeline.
  const timeline = [...set.versions].reverse();

  return (
    <div className="version-detail">
      {editing ? (
        <form
          className="rule-form"
          onSubmit={(event) => {
            event.preventDefault();
            run(async () => {
              await updateRuleSet(set.id, { name, description });
              setEditing(false);
            }, "Could not rename the rule set.");
          }}
        >
          <label className="field">
            <span className="field-label">Name</span>
            <input value={name} maxLength={80} onChange={(event) => setName(event.target.value)} />
          </label>
          <label className="field">
            <span className="field-label">Description</span>
            <textarea
              rows={2}
              value={description}
              onChange={(event) => setDescription(event.target.value)}
            />
          </label>
          <div className="form-actions">
            <button type="submit" className="button primary" disabled={!name.trim()}>
              Save
            </button>
            <button type="button" className="button" onClick={() => setEditing(false)}>
              Cancel
            </button>
          </div>
        </form>
      ) : (
        <header className="rule-form-header">
          <h2>
            {set.name}
            {set.archived && <span className="badge">Archived</span>}
          </h2>
          {set.description && <p>{set.description}</p>}
          <p className="muted">
            {set.versionCount} {set.versionCount === 1 ? "version" : "versions"} · created{" "}
            {formatDate(set.createdAt)}
          </p>
        </header>
      )}

      {!editing && (
        <div className="form-actions">
          <button
            type="button"
            // Only the main action while there is no version to scan with yet.
            className={`button${set.versions.length === 0 ? " primary" : ""}`}
            onClick={newVersion}
            disabled={set.archived}
            title={set.archived ? "Restore the rule set to add versions." : undefined}
          >
            New version
          </button>
          <MoreMenu
            label="More…"
            items={[
              {
                label: "Rename",
                onSelect: () => {
                  setName(set.name);
                  setDescription(set.description);
                  setEditing(true);
                },
              },
              {
                label: set.archived ? "Restore rule set" : "Archive rule set",
                onSelect: () =>
                  run(
                    () => updateRuleSet(set.id, { archived: !set.archived }),
                    "Could not update the rule set.",
                  ),
              },
            ]}
          />
        </div>
      )}

      {error && (
        <p className="banner error" role="alert">
          {error}
        </p>
      )}

      {timeline.length === 0 ? (
        <p className="muted">
          No versions yet. Use <b>New version</b> to pick the rules for this set's first version.
        </p>
      ) : (
        <ol className="version-timeline" aria-label="Versions">
          {timeline.map((entry) => (
            <li key={entry.id}>
              <NavLink
                to={versionPath(set.id, entry.id)}
                className={`version-chip${entry.id === selectedId ? " active" : ""}`}
              >
                <b>v{entry.number}</b>
                <span className="muted small">
                  {entry.ruleCount} {entry.ruleCount === 1 ? "rule" : "rules"} ·{" "}
                  {formatDate(entry.createdAt)}
                </span>
                {entry.archived && <span className="badge">Archived</span>}
              </NavLink>
            </li>
          ))}
        </ol>
      )}

      {version && (
        <section className="version-section" aria-label={`Version ${version.number}`}>
          <header className="rule-form-header">
            <h3>
              Version {version.number}
              {version.archived && <span className="badge">Archived</span>}
            </h3>
            <p className="muted">
              Saved {formatDate(version.createdAt)}
              {version.parentId !== null && (
                <>
                  {" "}
                  · based on <VersionLink versionId={version.parentId} />
                </>
              )}{" "}
              · {version.scanSessionCount}{" "}
              {version.scanSessionCount === 1 ? "scan session" : "scan sessions"}
            </p>
          </header>
          <div className="form-actions">
            <button
              type="button"
              className="button primary"
              onClick={scanWith}
              disabled={version.archived || set.archived}
              title={
                version.archived || set.archived
                  ? "Restore it to scan with this version."
                  : undefined
              }
            >
              Scan with this version
            </button>
            <MoreMenu
              label="More…"
              items={[
                {
                  label: "New version from this",
                  onSelect: () => setComposing({ parent: version }),
                  disabled: set.archived,
                },
                { label: "Copy to new rule set", onSelect: () => onCopy(version.id) },
                {
                  label: version.archived ? "Restore version" : "Archive version",
                  onSelect: () =>
                    run(
                      () => setVersionArchived(version.id, !version.archived),
                      "Could not update the version.",
                    ),
                },
              ]}
            />
          </div>
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
                <tr key={ruleId} className={definition.enabled === false ? "disabled" : undefined}>
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
                  <td>{definition.detectionType && DETECTION_LABELS[definition.detectionType]}</td>
                  <td>
                    <code className="pattern">{definition.pattern}</code>
                  </td>
                  <td>{describeChecksum(definition.checksum) ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}
    </div>
  );
}
