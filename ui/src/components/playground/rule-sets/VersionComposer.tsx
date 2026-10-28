import { useState } from "react";
import { Link } from "react-router-dom";
import {
  ApiError,
  createVersion,
  listRules,
  type RuleError,
  type RuleSetVersionDetail,
  ruleName,
} from "../api.ts";
import { SeverityIcon } from "../severity.tsx";
import { useLoad } from "../useLoad.ts";

interface VersionComposerProps {
  /** The version this one is based on, or null to start from nothing. */
  parent: RuleSetVersionDetail | null;
  onCreated: (version: RuleSetVersionDetail) => void;
  onCancel: () => void;
}

/** Picks the rules for a new rule set version, snapshotting each one's current definition. */
export default function VersionComposer({ parent, onCreated, onCancel }: VersionComposerProps) {
  const rules = useLoad(listRules, []);
  const [included, setIncluded] = useState(
    () => new Set(parent?.rules.map((rule) => rule.rule_id) ?? []),
  );
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [ruleErrors, setRuleErrors] = useState<RuleError[]>([]);

  const snapshots = new Map(
    parent?.rules.map((rule) => [rule.rule_id, JSON.stringify(rule.definition)]) ?? [],
  );

  function toggle(id: number, on: boolean) {
    setIncluded((current) => {
      const next = new Set(current);
      if (on) next.add(id);
      else next.delete(id);
      return next;
    });
  }

  async function save() {
    setSaving(true);
    setMessage(null);
    setRuleErrors([]);
    try {
      onCreated(await createVersion([...included], parent?.id ?? null));
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Could not save the version.");
      if (error instanceof ApiError) setRuleErrors(error.errors);
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="composer">
      <header>
        <h2>{parent ? `New version based on version ${parent.id}` : "New rule set version"}</h2>
        <p className="muted">
          Choose the rules to include. Each one is copied into the version as it is now, so later
          edits to a rule never change a saved version. Every rule must be valid to save.
        </p>
      </header>

      {rules.error && (
        <p className="banner error" role="alert">
          {rules.error}
        </p>
      )}
      {rules.data?.length === 0 && (
        <p className="muted">
          There are no rules yet. <Link to="/playground/rules">Create one</Link> first.
        </p>
      )}

      <ul className="composer-list">
        {rules.data?.map((rule) => {
          const snapshot = snapshots.get(rule.id);
          const errors = ruleErrors.filter((error) => error.rule_id === rule.id);
          return (
            <li key={rule.id} className={errors.length > 0 ? "invalid" : undefined}>
              <label className="composer-item">
                <input
                  type="checkbox"
                  checked={included.has(rule.id)}
                  onChange={(event) => toggle(rule.id, event.target.checked)}
                />
                {rule.definition.severity && <SeverityIcon tone={rule.definition.severity} />}
                <span>{ruleName(rule.definition, rule.id)}</span>
                <span className="badges">
                  {rule.drafting && <span className="badge">Draft</span>}
                  {rule.definition.enabled === false && <span className="badge">Disabled</span>}
                  {parent && snapshot === undefined && <span className="badge subtle">New</span>}
                  {snapshot !== undefined && snapshot !== JSON.stringify(rule.definition) && (
                    <span className="badge subtle">Changed since version {parent?.id}</span>
                  )}
                </span>
              </label>
              {errors.length > 0 && (
                <div className="composer-errors">
                  <ul>
                    {errors.map((error) => (
                      <li
                        key={`${error.field}-${error.code}`}
                        className={error.code === "invalid_regex" ? "mono" : undefined}
                      >
                        <b>{error.field.replace("_", " ")}:</b> {error.message}
                      </li>
                    ))}
                  </ul>
                  <Link to={`/playground/rules/${rule.id}`}>Edit rule</Link>
                </div>
              )}
            </li>
          );
        })}
      </ul>

      {message && (
        <p className="banner error" role="alert">
          {message}
        </p>
      )}

      <div className="form-actions">
        <button
          type="button"
          className="button primary"
          onClick={save}
          disabled={saving || included.size === 0}
        >
          {saving
            ? "Saving…"
            : `Save version with ${included.size} ${included.size === 1 ? "rule" : "rules"}`}
        </button>
        <button type="button" className="button" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </div>
  );
}
