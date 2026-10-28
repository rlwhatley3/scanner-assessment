import { useCallback, useRef, useState } from "react";
import { NavLink, useNavigate, useParams } from "react-router-dom";
import { createRule, listRules, ruleName } from "../api.ts";
import { SeverityIcon } from "../severity.tsx";
import { useLoad } from "../useLoad.ts";
import RuleForm from "./RuleForm.tsx";

export default function RulesView() {
  const { ruleId } = useParams();
  const navigate = useNavigate();
  const rules = useLoad(listRules, []);
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
          <h2>Rules</h2>
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
          <p className="muted">No rules yet. Create one, then add it to a rule set version.</p>
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
                  {rule.drafting && <span className="badge">Draft</span>}
                  {rule.definition.enabled === false && <span className="badge">Disabled</span>}
                  {rule.version_ids.length > 0 && (
                    <span className="badge subtle">
                      {rule.version_ids.length === 1
                        ? `In version ${rule.version_ids[0]}`
                        : `In ${rule.version_ids.length} versions`}
                    </span>
                  )}
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
            {ruleId && rules.data ? `Rule ${ruleId} does not exist.` : "Select or create a rule."}
          </p>
        )}
      </section>
    </div>
  );
}
