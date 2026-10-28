import { useState } from "react";
import { createRuleSet, listVersions, type RuleSetDetail, versionLabel } from "../api.ts";
import { useLoad } from "../useLoad.ts";

const MAX_NAME_LENGTH = 80;

interface NewRuleSetFormProps {
  /** Pre-selects this version to copy, e.g. from a version's "Copy to new rule set". */
  fromVersionId: number | null;
  onCreated: (ruleSet: RuleSetDetail) => void;
  onCancel: () => void;
}

/** Names a new rule set and picks how it starts: empty, or as a copy of an existing version. */
export default function NewRuleSetForm({
  fromVersionId,
  onCreated,
  onCancel,
}: NewRuleSetFormProps) {
  const versions = useLoad(() => listVersions(), []);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [source, setSource] = useState<number | null>(fromVersionId);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function save() {
    setSaving(true);
    setError(null);
    try {
      onCreated(await createRuleSet({ name, description, fromVersionId: source }));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not create the rule set.");
    } finally {
      setSaving(false);
    }
  }

  return (
    <form
      className="rule-form"
      onSubmit={(event) => {
        event.preventDefault();
        save();
      }}
    >
      <header className="rule-form-header">
        <h2>New rule set</h2>
        <p className="muted">
          A rule set is a named line of versions, such as one per team or project. Each version is a
          saved, unchangeable set of rules that scans run with.
        </p>
      </header>
      <label className="field">
        <span className="field-label">Name</span>
        <input
          value={name}
          maxLength={MAX_NAME_LENGTH}
          onChange={(event) => setName(event.target.value)}
          placeholder="e.g. Payments team"
          // biome-ignore lint/a11y/noAutofocus: the form opens for this one field.
          autoFocus
        />
        <span className="field-hint">Required, and different from every other rule set's.</span>
      </label>
      <label className="field">
        <span className="field-label">Description</span>
        <textarea
          rows={2}
          value={description}
          onChange={(event) => setDescription(event.target.value)}
        />
        <span className="field-hint">Optional. What the set is for, or who owns it.</span>
      </label>
      <label className="field">
        <span className="field-label">Start with</span>
        <select
          value={source ?? ""}
          onChange={(event) =>
            setSource(event.target.value === "" ? null : Number(event.target.value))
          }
        >
          <option value="">No versions yet: add rules as its first version</option>
          {(versions.data ?? []).map((version) => (
            <option key={version.id} value={version.id}>
              A copy of {versionLabel(version)} ({version.ruleCount}{" "}
              {version.ruleCount === 1 ? "rule" : "rules"})
            </option>
          ))}
        </select>
        <span className="field-hint">
          A copy becomes this set's version 1, with exactly the same rules.
        </span>
      </label>
      {error && (
        <p className="banner error" role="alert">
          {error}
        </p>
      )}
      <div className="form-actions">
        <button type="submit" className="button primary" disabled={saving || !name.trim()}>
          {saving ? "Creating…" : "Create rule set"}
        </button>
        <button type="button" className="button" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </form>
  );
}
