import { useEffect, useState } from "react";
import { Navigate, NavLink, useNavigate, useParams } from "react-router-dom";
import { getVersion, listRuleSets } from "../api.ts";
import { useLoad } from "../useLoad.ts";
import NewRuleSetForm from "./NewRuleSetForm.tsx";
import RuleSetPanel, { versionPath } from "./RuleSetPanel.tsx";

/** Rule sets on the left; the selected set, or a new one being named, on the right. */
export default function RuleSetsView() {
  const params = useParams();
  const navigate = useNavigate();
  const [showArchived, setShowArchived] = useState(false);
  // null: no form open. Otherwise the new set form, maybe starting from a copy of a version.
  const [creating, setCreating] = useState<{ fromVersionId: number | null } | null>(null);
  const ruleSets = useLoad(() => listRuleSets(showArchived), [showArchived]);

  // The rest of the path is "", "{setId}", or "{setId}/versions/{versionId}".
  const [setPart, , versionPart] = (params["*"] ?? "").split("/");
  const ruleSetId = setPart ? Number(setPart) : null;
  const versionId = versionPart ? Number(versionPart) : null;

  // Leaving the form open while picking another set would be confusing.
  // biome-ignore lint/correctness/useExhaustiveDependencies: close only when the selection moves.
  useEffect(() => setCreating(null), [ruleSetId, versionId]);

  // With nothing selected, open the first set.
  const first = ruleSets.data?.[0];
  if (ruleSetId === null && !creating && first) {
    return <Navigate to={`/playground/rule-sets/${first.id}`} replace />;
  }

  return (
    <div className="playground-section master-detail">
      <section className="panel master" aria-label="Rule sets">
        <div className="master-header">
          <h2>Rule sets</h2>
          <button
            type="button"
            className="button primary"
            onClick={() => setCreating({ fromVersionId: null })}
          >
            New rule set
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
        {ruleSets.error && (
          <p className="banner error" role="alert">
            {ruleSets.error}
          </p>
        )}
        {ruleSets.data?.length === 0 && (
          <p className="muted">No rule sets yet. Create one to start saving versions.</p>
        )}
        <ul className="master-list">
          {ruleSets.data?.map((ruleSet) => (
            <li key={ruleSet.id}>
              <NavLink
                to={`/playground/rule-sets/${ruleSet.id}`}
                className={`master-item${ruleSet.id === ruleSetId && !creating ? " active" : ""}`}
              >
                <span className="master-item-title">{ruleSet.name}</span>
                {ruleSet.description && (
                  <span className="muted small clamp">{ruleSet.description}</span>
                )}
                <span className="muted small">
                  {ruleSet.versionCount} {ruleSet.versionCount === 1 ? "version" : "versions"}
                </span>
                {ruleSet.archived && (
                  <span className="badges">
                    <span className="badge">Archived</span>
                  </span>
                )}
              </NavLink>
            </li>
          ))}
        </ul>
      </section>

      <section className="panel detail" aria-label="Rule set details">
        {creating ? (
          <NewRuleSetForm
            key={creating.fromVersionId ?? "empty"}
            fromVersionId={creating.fromVersionId}
            onCancel={() => setCreating(null)}
            onCreated={(created) => {
              setCreating(null);
              ruleSets.reload();
              const firstVersion = created.versions[0];
              navigate(
                firstVersion
                  ? versionPath(created.id, firstVersion.id)
                  : `/playground/rule-sets/${created.id}`,
              );
            }}
          />
        ) : ruleSetId !== null ? (
          <RuleSetPanel
            ruleSetId={ruleSetId}
            versionId={versionId}
            onChanged={ruleSets.reload}
            onCopy={(id) => setCreating({ fromVersionId: id })}
          />
        ) : (
          <p className="results-placeholder">
            {ruleSets.loading ? "Loading…" : "Create a rule set to get started."}
          </p>
        )}
      </section>
    </div>
  );
}

/** Opens a version by id alone, for links that don't know its rule set. */
export function VersionRedirect() {
  const { versionId } = useParams();
  const id = Number(versionId);
  const version = useLoad(() => getVersion(id), [id]);
  if (version.data) return <Navigate to={versionPath(version.data.ruleSetId, id)} replace />;
  return (
    <div className="playground-section">
      <p className="results-placeholder">{version.error ?? "Opening the version…"}</p>
    </div>
  );
}
