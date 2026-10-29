import { useEffect, useMemo, useState } from "react";
import {
  ApiError,
  checkRule,
  type DetectionType,
  deleteRule,
  listModels,
  type Model,
  type Rule,
  type RuleCheck,
  type RuleDefinition,
  type Severity,
  saveRule,
} from "../api.ts";
import { DETECTION_LABELS, SEVERITY_LABELS } from "../severity.tsx";
import { useLoad } from "../useLoad.ts";
import ChecksumFields, {
  type ChecksumForm,
  checksumFormFrom,
  checksumFrom,
} from "./ChecksumFields.tsx";
import PasswordShapeFields, {
  type PasswordShapeForm,
  passwordShapeFormFrom,
  passwordShapeFrom,
} from "./PasswordShapeFields.tsx";
import RuleSetMembership from "./RuleSetMembership.tsx";
import { SecretShape, SeverityChoice } from "./SimpleFields.tsx";
import { type Shape, shapeFields, shapeOf } from "./shape.ts";
import TryRule from "./TryRule.tsx";
import ValueClassifierFields, {
  type ValueClassifierForm,
  valueClassifierFormFrom,
  valueClassifierFrom,
} from "./ValueClassifierFields.tsx";

interface FormState {
  name: string;
  enabled: boolean;
  detectionType: DetectionType | "";
  severity: Severity | "";
  pattern: string;
  prefix: string;
  keyNames: string;
  minEntropy: string;
  checksum: ChecksumForm;
  passwordShape: PasswordShapeForm;
  valueClassifier: ValueClassifierForm;
  remediation: string;
  model: { id?: string; sha256: string } | null;
  threshold: string;
}

function fromDefinition(definition: RuleDefinition): FormState {
  return {
    name: definition.name ?? "",
    enabled: definition.enabled !== false,
    detectionType: definition.detectionType ?? "",
    severity: definition.severity ?? "",
    pattern: definition.pattern ?? "",
    prefix: definition.prefix ?? "",
    keyNames: (definition.keyNames ?? []).join(", "),
    minEntropy: definition.minEntropy == null ? "" : String(definition.minEntropy),
    checksum: checksumFormFrom(definition.checksum),
    passwordShape: passwordShapeFormFrom(definition.passwordShape),
    valueClassifier: valueClassifierFormFrom(definition.valueClassifier),
    remediation: definition.remediation ?? "",
    model: definition.model?.sha256
      ? { ...(definition.model.id && { id: definition.model.id }), sha256: definition.model.sha256 }
      : null,
    threshold: definition.threshold == null ? "" : String(definition.threshold),
  };
}

const FORM_KEYS = [
  "name",
  "enabled",
  "detectionType",
  "severity",
  "pattern",
  "prefix",
  "keyNames",
  "minEntropy",
  "checksum",
  "passwordShape",
  "valueClassifier",
  "remediation",
  "model",
  "threshold",
];

/** Fields the form has no input for, carried through a save unchanged. */
function otherFields(definition: RuleDefinition): RuleDefinition {
  return Object.fromEntries(Object.entries(definition).filter(([key]) => !FORM_KEYS.includes(key)));
}

/** The canonical JSON for the form: empty fields are left out, enabled only when false. */
function toDefinition(form: FormState, others: RuleDefinition = {}): RuleDefinition {
  const keyNames = form.keyNames
    .split(",")
    .map((name) => name.trim())
    .filter(Boolean);
  const checksum = checksumFrom(form.checksum);
  const passwordShape = passwordShapeFrom(form.passwordShape);
  const valueClassifier = valueClassifierFrom(form.valueClassifier);
  return {
    ...others,
    ...(form.name.trim() && { name: form.name.trim() }),
    ...(!form.enabled && { enabled: false }),
    ...(form.detectionType && { detectionType: form.detectionType }),
    ...(form.severity && { severity: form.severity }),
    ...(form.pattern && { pattern: form.pattern }),
    ...(form.prefix.trim() && { prefix: form.prefix.trim() }),
    ...(keyNames.length > 0 && { keyNames }),
    ...(form.minEntropy.trim() && { minEntropy: Number(form.minEntropy) }),
    ...(checksum && { checksum }),
    ...(passwordShape && { passwordShape }),
    ...(valueClassifier && { valueClassifier }),
    ...(form.remediation.trim() && { remediation: form.remediation.trim() }),
    ...(form.model && { model: form.model }),
    ...(form.threshold.trim() && { threshold: Number(form.threshold) }),
  };
}

function modelOption(model: Model): { sha256: string; label: string } {
  return { sha256: model.sha256, label: `${model.id} · ${model.sha256.slice(0, 12)}…` };
}

/** Model rules run a model instead of a pattern. */
function usesModel(detectionType: DetectionType | ""): boolean {
  return detectionType === "model_assessment" || detectionType === "model_detection";
}

const CHECK_DELAY_MS = 400;

interface RuleFormProps {
  rule: Rule;
  onSaved: (rule: Rule) => void;
  onDeleted: () => void;
  onDirtyChange: (dirty: boolean) => void;
}

export default function RuleForm({ rule, onSaved, onDeleted, onDirtyChange }: RuleFormProps) {
  const [form, setForm] = useState(() => fromDefinition(rule.definition));
  const [check, setCheck] = useState<RuleCheck | null>(null);
  const [saving, setSaving] = useState(false);
  const [notice, setNotice] = useState<{ tone: "error" | "success"; message: string } | null>(null);

  const others = useMemo(() => otherFields(rule.definition), [rule.definition]);
  const definition = useMemo(() => toDefinition(form, others), [form, others]);
  const saved = useMemo(
    () => JSON.stringify(toDefinition(fromDefinition(rule.definition), others)),
    [rule.definition, others],
  );
  const createsNoFindings =
    form.detectionType === "placeholder_vs_real" || form.detectionType === "model_assessment";
  const isModel = usesModel(form.detectionType);
  const models = useLoad(listModels, []);
  // Models that fit this rule type, plus the rule's own model if the API hasn't loaded it.
  const modelOptions = useMemo(() => {
    const fitting = (models.data ?? []).filter(
      (model) =>
        (form.detectionType === "model_assessment" || form.detectionType === "model_detection") &&
        model.uses.includes(form.detectionType),
    );
    const current = form.model;
    if (current && !fitting.some((model) => model.sha256 === current.sha256)) {
      const label = `${current.id ?? current.sha256.slice(0, 12)} (not available)`;
      return [{ sha256: current.sha256, label }, ...fitting.map(modelOption)];
    }
    return fitting.map(modelOption);
  }, [models.data, form.detectionType, form.model]);
  const dirty = JSON.stringify(definition) !== saved;
  const errors = check?.errors ?? [];
  // Optional tuning starts folded away unless the rule already uses some of it.
  const [fineTuneOpen, setFineTuneOpen] = useState(() =>
    Boolean(
      form.prefix ||
        form.minEntropy ||
        form.keyNames ||
        rule.definition.checksum ||
        rule.definition.passwordShape ||
        rule.definition.valueClassifier,
    ),
  );
  const fineTuneErrors = ["prefix", "min_entropy", "key_names", "checksum", "password_shape"]
    .concat(isModel ? [] : ["value_classifier"])
    .some((field) => errors.some((error) => error.field === field));

  // The simple editor asks plain questions; advanced settings show every field.
  const [advanced, setAdvanced] = useState(false);
  const [shape, setShape] = useState<Shape>(() => shapeOf(form));

  useEffect(() => onDirtyChange(dirty), [dirty, onDirtyChange]);

  // Drafts are not validated until they join a rule set version; other rules check as you type.
  useEffect(() => {
    if (rule.drafting) {
      setCheck(null);
      return;
    }
    const controller = new AbortController();
    const timer = setTimeout(() => {
      checkRule(rule.id, definition, controller.signal).then(setCheck, () => {});
    }, CHECK_DELAY_MS);
    return () => {
      clearTimeout(timer);
      controller.abort();
    };
  }, [rule.id, rule.drafting, definition]);

  const fieldErrors = (field: string) => errors.filter((error) => error.field === field);
  const fieldWarnings = (field: string) =>
    (check?.warnings ?? []).filter((warning) => warning.field === field);

  function update<K extends keyof FormState>(key: K, value: FormState[K]) {
    setForm((current) => ({ ...current, [key]: value }));
    setNotice(null);
  }

  /** Writes the pattern for a shape described in the simple editor. */
  function updateShape(next: Shape) {
    setShape(next);
    const fields = shapeFields(next);
    if (fields) setForm((current) => ({ ...current, ...fields }));
    setNotice(null);
  }

  function toggleAdvanced(on: boolean) {
    // Back in the simple editor, describe whatever the advanced fields now hold.
    if (!on) setShape(shapeOf(form));
    setAdvanced(on);
  }

  async function save() {
    setSaving(true);
    setNotice(null);
    try {
      const updated = await saveRule(rule.id, definition);
      setNotice({ tone: "success", message: "Saved." });
      onSaved(updated);
    } catch (error) {
      if (error instanceof ApiError && error.errors.length > 0) {
        setCheck({ errors: error.errors, warnings: [] });
      }
      setNotice({
        tone: "error",
        message: error instanceof Error ? error.message : "Could not save the rule.",
      });
    } finally {
      setSaving(false);
    }
  }

  async function remove() {
    if (!window.confirm("Delete this rule? This cannot be undone.")) return;
    try {
      await deleteRule(rule.id);
      onDeleted();
    } catch (error) {
      setNotice({
        tone: "error",
        message: error instanceof Error ? error.message : "Could not delete the rule.",
      });
    }
  }

  const inVersions = rule.versionIds.length > 0;

  return (
    <div className="rule-editor">
      <form
        className="rule-form"
        onSubmit={(event) => {
          event.preventDefault();
          save();
        }}
      >
        <header className="rule-form-header">
          <div>
            <h2>{definition.name ?? `Untitled rule ${rule.id}`}</h2>
            <p className="muted">
              {rule.drafting
                ? "Not used in scans yet. Save it, then add it to a rule set below."
                : "A rule tells the scanner what kind of secret to look for."}
            </p>
          </div>
          <label className="switch">
            <input
              type="checkbox"
              checked={advanced}
              onChange={(event) => toggleAdvanced(event.target.checked)}
            />
            Advanced settings
          </label>
        </header>

        {!advanced && (
          <>
            <Field label="What do you call it?" errors={fieldErrors("name")}>
              <input
                value={form.name}
                placeholder="e.g. Acme API token"
                onChange={(event) => update("name", event.target.value)}
              />
            </Field>
            <SecretShape
              shape={shape}
              onChange={updateShape}
              detectionType={form.detectionType}
              pattern={form.pattern}
              onAdvanced={() => toggleAdvanced(true)}
            />
            {!createsNoFindings && (
              <SeverityChoice
                value={form.severity}
                onChange={(value) => update("severity", value)}
              />
            )}
            <Field
              label="What should someone do if one is found?"
              errors={fieldErrors("remediation")}
            >
              <textarea
                rows={2}
                placeholder="e.g. Revoke the token in the Acme dashboard and create a new one."
                value={form.remediation}
                onChange={(event) => update("remediation", event.target.value)}
              />
            </Field>
            <label className="switch">
              <input
                type="checkbox"
                checked={form.enabled}
                onChange={(event) => update("enabled", event.target.checked)}
              />
              Turned on (scans use it)
            </label>
            {errors.length > 0 && (
              <div className="banner error" role="alert">
                <b>Fix this before saving:</b>
                <ul>
                  {errors.map((error) => (
                    <li key={`${error.field}-${error.code}`}>{error.message}</li>
                  ))}
                </ul>
              </div>
            )}
          </>
        )}

        {advanced && (
          <>
            <Field label="Name" errors={fieldErrors("name")}>
              <input value={form.name} onChange={(event) => update("name", event.target.value)} />
            </Field>

            <div className="field-row">
              <Field label="Detection type" errors={fieldErrors("detection_type")}>
                <select
                  value={form.detectionType}
                  onChange={(event) => update("detectionType", event.target.value as DetectionType)}
                >
                  <option value="">Choose…</option>
                  {Object.entries(DETECTION_LABELS).map(([value, label]) => (
                    <option key={value} value={value}>
                      {label}
                    </option>
                  ))}
                </select>
              </Field>
              <Field
                label="Severity"
                hint={
                  createsNoFindings ? "Not used: this rule type creates no findings." : undefined
                }
                errors={fieldErrors("severity")}
              >
                <select
                  value={form.severity}
                  onChange={(event) => update("severity", event.target.value as Severity)}
                >
                  <option value="">Choose…</option>
                  {Object.entries(SEVERITY_LABELS).map(([value, label]) => (
                    <option key={value} value={value}>
                      {label}
                    </option>
                  ))}
                </select>
              </Field>
              <label className="field field-checkbox">
                <input
                  type="checkbox"
                  checked={form.enabled}
                  onChange={(event) => update("enabled", event.target.checked)}
                />
                Enabled
              </label>
            </div>

            {isModel ? (
              <div className="field-row">
                <Field
                  label="Model"
                  hint={
                    models.error
                      ? `Could not load the model list: ${models.error}`
                      : "Models the API has loaded that fit this rule type."
                  }
                  errors={fieldErrors("model")}
                >
                  <select
                    value={form.model?.sha256 ?? ""}
                    onChange={(event) => {
                      const model = models.data?.find(
                        (option) => option.sha256 === event.target.value,
                      );
                      update("model", model ? { id: model.id, sha256: model.sha256 } : null);
                    }}
                  >
                    <option value="">{models.loading ? "Loading…" : "Choose…"}</option>
                    {modelOptions.map((option) => (
                      <option key={option.sha256} value={option.sha256}>
                        {option.label}
                      </option>
                    ))}
                  </select>
                </Field>
                <Field
                  label="Threshold"
                  hint="0–100. A model score at or above this counts as a secret."
                  errors={fieldErrors("threshold")}
                >
                  <input
                    type="number"
                    min={0}
                    max={100}
                    step={1}
                    value={form.threshold}
                    onChange={(event) => update("threshold", event.target.value)}
                  />
                </Field>
              </div>
            ) : null}

            {form.detectionType === "model_detection" && (
              <ValueClassifierFields
                value={form.valueClassifier}
                onChange={(valueClassifier) => update("valueClassifier", valueClassifier)}
                errors={fieldErrors("value_classifier")}
                models={models.data}
              />
            )}

            {isModel ? null : (
              <Field
                label="Pattern"
                hint="A regular expression. A named group “value” narrows the finding to the secret; “key” is checked against key names."
                errors={fieldErrors("pattern")}
                warnings={fieldWarnings("pattern")}
              >
                <textarea
                  className="mono"
                  rows={3}
                  spellCheck={false}
                  value={form.pattern}
                  onChange={(event) => update("pattern", event.target.value)}
                />
              </Field>
            )}

            <Field
              label="Remediation"
              hint="Shown with each finding as how to fix it."
              errors={fieldErrors("remediation")}
            >
              <textarea
                rows={2}
                value={form.remediation}
                onChange={(event) => update("remediation", event.target.value)}
              />
            </Field>

            {isModel ? null : (
              <details
                className="fine-tune"
                open={fineTuneOpen || fineTuneErrors}
                onToggle={(event) => setFineTuneOpen(event.currentTarget.open)}
              >
                <summary>
                  Fine-tune detection
                  <span className="muted small">
                    {" "}
                    · optional: prefix, entropy, key names, checksum, password shape, value
                    classifier
                  </span>
                </summary>

                <div className="field-row">
                  <Field
                    label="Prefix"
                    hint="Public prefix shown as the redacted preview, e.g. AKIA."
                    errors={fieldErrors("prefix")}
                  >
                    <input
                      className="mono"
                      value={form.prefix}
                      onChange={(event) => update("prefix", event.target.value)}
                    />
                  </Field>
                  <Field
                    label="Minimum entropy"
                    hint="0–8 bits per character. Higher skips values that don't look random."
                    errors={fieldErrors("min_entropy")}
                  >
                    <input
                      type="number"
                      min={0}
                      max={8}
                      step={0.1}
                      value={form.minEntropy}
                      onChange={(event) => update("minEntropy", event.target.value)}
                    />
                  </Field>
                </div>

                <Field
                  label="Key names"
                  hint="Comma-separated, e.g. password, secret, token. A match assigned to one of these is more likely a secret."
                  errors={fieldErrors("key_names")}
                >
                  <input
                    value={form.keyNames}
                    onChange={(event) => update("keyNames", event.target.value)}
                  />
                </Field>

                <ChecksumFields
                  value={form.checksum}
                  onChange={(checksum) => update("checksum", checksum)}
                  errors={fieldErrors("checksum")}
                />

                <PasswordShapeFields
                  value={form.passwordShape}
                  onChange={(passwordShape) => update("passwordShape", passwordShape)}
                  errors={fieldErrors("password_shape")}
                />

                {form.detectionType !== "unsafe_handling" &&
                  form.detectionType !== "placeholder_vs_real" && (
                    <ValueClassifierFields
                      value={form.valueClassifier}
                      onChange={(valueClassifier) => update("valueClassifier", valueClassifier)}
                      errors={fieldErrors("value_classifier")}
                      models={models.data}
                    />
                  )}
              </details>
            )}
          </>
        )}

        {notice && (
          <p
            className={`banner ${notice.tone}`}
            role={notice.tone === "error" ? "alert" : "status"}
          >
            {notice.message}
          </p>
        )}

        <div className="form-actions">
          <button
            type="submit"
            className="button primary"
            disabled={!dirty || saving || (!rule.drafting && errors.length > 0)}
          >
            {saving ? "Saving…" : "Save"}
          </button>
          {dirty && <span className="muted">Unsaved changes</span>}
          <button
            type="button"
            className="button subtle-danger"
            onClick={remove}
            disabled={inVersions}
            title={
              inVersions
                ? "This rule is in a rule set version. Leave it out of the next version instead."
                : undefined
            }
          >
            Delete
          </button>
        </div>
      </form>

      {!createsNoFindings && <TryRule ruleId={rule.id} definition={definition} />}
      <RuleSetMembership rule={rule} dirty={dirty} onChanged={() => onSaved(rule)} />
    </div>
  );
}

interface FieldProps {
  label: string;
  hint?: string;
  errors: { code: string; message: string }[];
  warnings?: { message: string }[];
  children: React.ReactNode;
}

function Field({ label, hint, errors, warnings = [], children }: FieldProps) {
  return (
    // biome-ignore lint/a11y/noLabelWithoutControl: every caller passes its control as `children`.
    <label className={`field${errors.length > 0 ? " invalid" : ""}`}>
      <span className="field-label">{label}</span>
      {children}
      {hint && <span className="field-hint">{hint}</span>}
      {errors.map((error) => (
        <span
          key={error.message}
          className={`field-error${error.code === "invalid_regex" ? " mono" : ""}`}
        >
          {error.message}
        </span>
      ))}
      {warnings.map((warning) => (
        <span key={warning.message} className="field-warning">
          {warning.message}
        </span>
      ))}
    </label>
  );
}
