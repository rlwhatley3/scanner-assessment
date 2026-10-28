import type { Model, ModelRef, ValueClassifier } from "../api.ts";

const DEFAULT_MIN_SCORE = 50;

/** The value classifier part of the rule form, as the inputs hold it. */
export interface ValueClassifierForm {
  enabled: boolean;
  model: ModelRef | null;
  minScore: string;
}

export function valueClassifierFormFrom(
  setting: ValueClassifier | null | undefined,
): ValueClassifierForm {
  const sha256 = setting?.model?.sha256;
  return {
    enabled: Boolean(setting),
    model: sha256 ? { ...(setting?.model?.id && { id: setting.model.id }), sha256 } : null,
    minScore: String(setting?.minScore ?? DEFAULT_MIN_SCORE),
  };
}

/** The value classifier JSON for the definition, or undefined when it's off. */
export function valueClassifierFrom(form: ValueClassifierForm): ValueClassifier | undefined {
  if (!form.enabled) return undefined;
  return {
    ...(form.model && { model: form.model }),
    ...(form.minScore.trim() && { minScore: Number(form.minScore) }),
  };
}

interface ValueClassifierFieldsProps {
  value: ValueClassifierForm;
  onChange: (value: ValueClassifierForm) => void;
  errors: { code: string; message: string }[];
  /** The models the API has loaded, or null while loading. */
  models: Model[] | null;
}

/** Lets a rule author run a model on the rule's matches to tell credentials from hashes, IDs,
 * and placeholders. */
export default function ValueClassifierFields({
  value,
  onChange,
  errors,
  models,
}: ValueClassifierFieldsProps) {
  const fitting = (models ?? []).filter((model) => model.uses.includes("value_classifier"));
  const current = value.model;
  const missing = current && !fitting.some((model) => model.sha256 === current.sha256);

  return (
    <fieldset className={`checksum-fields${errors.length > 0 ? " invalid" : ""}`}>
      <legend className="field-label">Value classifier</legend>
      <p className="field-hint">
        Optional. A model reads each value this rule matches and says whether it's a credential, a
        non-secret random string (a hash, ID, or encoded data), or a placeholder. Values it doesn't
        rate as a credential are still reported, with lower confidence; a strong credential score
        raises confidence.
      </p>
      <label className="field field-checkbox">
        <input
          type="checkbox"
          checked={value.enabled}
          onChange={(event) => {
            const enabled = event.target.checked;
            const first = fitting[0];
            const model =
              value.model ?? (enabled && first ? { id: first.id, sha256: first.sha256 } : null);
            onChange({ ...value, enabled, model });
          }}
        />
        Classify this rule's matches
      </label>

      {value.enabled && (
        <div className="field-row">
          <label className="field">
            <span className="field-label">Model</span>
            <select
              value={current?.sha256 ?? ""}
              onChange={(event) => {
                const model = fitting.find((option) => option.sha256 === event.target.value);
                onChange({
                  ...value,
                  model: model ? { id: model.id, sha256: model.sha256 } : null,
                });
              }}
            >
              <option value="">{models === null ? "Loading…" : "Choose…"}</option>
              {missing && current && (
                <option value={current.sha256}>
                  {current.id ?? current.sha256.slice(0, 12)} (not available)
                </option>
              )}
              {fitting.map((model) => (
                <option key={model.sha256} value={model.sha256}>
                  {model.id} · {model.sha256.slice(0, 12)}…
                </option>
              ))}
            </select>
            <span className="field-hint">Models the API has loaded that classify values.</span>
          </label>
          <label className="field">
            <span className="field-label">Minimum credential score</span>
            <input
              type="number"
              min={0}
              max={100}
              value={value.minScore}
              onChange={(event) => onChange({ ...value, minScore: event.target.value })}
            />
            <span className="field-hint">
              0–100. Values scoring below this as a credential get lower confidence.
            </span>
          </label>
        </div>
      )}

      {errors.map((error) => (
        <span key={error.message} className="field-error">
          {error.message}
        </span>
      ))}
    </fieldset>
  );
}
