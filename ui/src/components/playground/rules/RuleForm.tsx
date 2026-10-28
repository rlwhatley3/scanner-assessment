import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import {
  ApiError,
  checkRule,
  type DetectionType,
  deleteRule,
  type Rule,
  type RuleCheck,
  type RuleDefinition,
  type Severity,
  saveRule,
} from "../api.ts";
import { DETECTION_LABELS, SEVERITY_LABELS } from "../severity.tsx";
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
  remediation: string;
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
    remediation: definition.remediation ?? "",
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
  "remediation",
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
    ...(form.remediation.trim() && { remediation: form.remediation.trim() }),
  };
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
  const isPlaceholder = form.detectionType === "placeholder_vs_real";
  const dirty = JSON.stringify(definition) !== saved;

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

  const errors = check?.errors ?? [];
  const fieldErrors = (field: string) => errors.filter((error) => error.field === field);
  const fieldWarnings = (field: string) =>
    (check?.warnings ?? []).filter((warning) => warning.field === field);

  function update<K extends keyof FormState>(key: K, value: FormState[K]) {
    setForm((current) => ({ ...current, [key]: value }));
    setNotice(null);
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
              ? "Draft: not checked until you add it to a rule set version."
              : "Changes apply to the next rule set version you save; existing versions keep their copy."}
            {inVersions && (
              <>
                {" "}
                In{" "}
                {rule.versionIds.map((id, index) => (
                  <span key={id}>
                    {index > 0 && ", "}
                    <Link to={`/playground/rule-sets/${id}`}>version {id}</Link>
                  </span>
                ))}
                .
              </>
            )}
          </p>
        </div>
      </header>

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
          hint={isPlaceholder ? "Not used: placeholder rules create no findings." : undefined}
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
          hint="0–8 bits per character. Optional."
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
        hint="Comma-separated, e.g. password, secret, token. Optional."
        errors={fieldErrors("key_names")}
      >
        <input value={form.keyNames} onChange={(event) => update("keyNames", event.target.value)} />
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

      <Field label="Remediation" errors={fieldErrors("remediation")}>
        <textarea
          rows={2}
          value={form.remediation}
          onChange={(event) => update("remediation", event.target.value)}
        />
      </Field>

      {notice && (
        <p className={`banner ${notice.tone}`} role={notice.tone === "error" ? "alert" : "status"}>
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
