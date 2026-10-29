import { useCallback, useRef, useState } from "react";
import { NavLink, useNavigate, useParams } from "react-router-dom";
import { createRule, listRules, listVersions, ruleName } from "../api.ts";
import { HelpLink } from "../guide/GuideView.tsx";
import { SeverityIcon } from "../severity.tsx";
import { useLoad } from "../useLoad.ts";
import RuleForm from "./RuleForm.tsx";

export default function RulesView() {
  const { ruleId } = useParams();
  const navigate = useNavigate();
  const rules = useLoad(listRules, []);
  // Every version, to name the rule sets each rule is in. Reloads with the rules.
  const versions = useLoad(() => listVersions({ includeArchived: true }), [rules.data]);
  const setNames = (versionIds: number[]): string[] => [
    ...new Set(
      (versions.data ?? [])
        .filter((version) => versionIds.includes(version.id))
        .map((version) => version.ruleSetName),
    ),
  ];
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const dirtyRef = useRef(false);

  const selected = rules.data?.find((rule) => String(rule.id) === ruleId) ?? null;
  const setDirty = useCallback((dirty: boolean) => {
    dirtyRef.current = dirty;
  }, []);

  function confirmLeave(): boolean {
    return !dirtyRef.current || window.confirm("Discard unsaved changes to this rule?");
  }

  async function newRule() {
    if (!confirmLeave()) return;
    setCreating(true);
    setError(null);
    try {
      const rule = await createRule();
      rules.reload();
      navigate(`/playground/rules/${rule.id}`);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not create a rule.");
    } finally {
      setCreating(false);
    }
  }

  return (
    <div className="playground-section master-detail">
      <section className="panel master" aria-label="Rules">
        <div className="master-header">
          <h2>
            Rules <HelpLink section="rules" label="How rules work" />
          </h2>
          <button type="button" className="button primary" onClick={newRule} disabled={creating}>
            New rule
          </button>
        </div>
        {(rules.error || error) && (
          <p className="banner error" role="alert">
            {rules.error ?? error}
          </p>
        )}
        {rules.data?.length === 0 && (
          <p className="muted">
            No rules yet. Create one, then add it to a rule set to scan with it.
          </p>
        )}
        <ul className="master-list">
          {rules.data?.map((rule) => (
            <li key={rule.id}>
              <NavLink
                to={`/playground/rules/${rule.id}`}
                className="master-item"
                onClick={(event) => {
                  if (!confirmLeave()) event.preventDefault();
                }}
              >
                <span className="master-item-title">
                  {rule.definition.severity && <SeverityIcon tone={rule.definition.severity} />}
                  {ruleName(rule.definition, rule.id)}
                </span>
                <span className="badges">
                  {rule.definition.enabled === false && <span className="badge">Off</span>}
                  {versions.data && <SetsBadge names={setNames(rule.versionIds)} />}
                </span>
              </NavLink>
            </li>
          ))}
        </ul>
      </section>

      <section className="panel detail" aria-label="Rule details">
        {selected ? (
          <RuleForm
            key={selected.id}
            rule={selected}
            onSaved={rules.reload}
            onDeleted={() => {
              dirtyRef.current = false;
              rules.reload();
              navigate("/playground/rules");
            }}
            onDirtyChange={setDirty}
          />
        ) : (
          <p className="results-placeholder">
            {ruleId && rules.data
              ? `Rule ${ruleId} does not exist.`
              : "Select a rule to edit it, or create one with New rule."}
          </p>
        )}
      </section>
    </div>
  );
}

/** Which rule sets have the rule in any of their versions. */
function SetsBadge({ names }: { names: string[] }) {
  if (names.length === 0) return <span className="badge">Not used in scans yet</span>;
  return (
    <span className="badge subtle" title={names.join(", ")}>
      {names.length === 1 ? `Used in ${names[0]}` : `Used in ${names.length} rule sets`}
    </span>
  );
}
