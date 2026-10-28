import type { PasswordShape } from "../api.ts";

/** The engine's limits for a password shape's minimum score. */
export const PASSWORD_SHAPE_MAX_SCORE = 10;
const DEFAULT_MIN_SCORE = 2;

/** The password shape part of the rule form, as the inputs hold it. */
export interface PasswordShapeForm {
  enabled: boolean;
  minScore: string;
}

export function passwordShapeFormFrom(shape: PasswordShape | null | undefined): PasswordShapeForm {
  return {
    enabled: Boolean(shape),
    minScore: String(shape?.minScore ?? DEFAULT_MIN_SCORE),
  };
}

/** The password shape JSON for the definition, or undefined when it's off. */
export function passwordShapeFrom(form: PasswordShapeForm): PasswordShape | undefined {
  return form.enabled ? { minScore: Number(form.minScore) } : undefined;
}

interface PasswordShapeFieldsProps {
  value: PasswordShapeForm;
  onChange: (value: PasswordShapeForm) => void;
  errors: { code: string; message: string }[];
}

const SIGNALS: [string, number][] = [
  ["Mixes symbols into letters", 2],
  ["Swaps letters for look-alike digits or symbols (p4ss, s3cret)", 2],
  ["Contains a word common in passwords (pw, pass, admin…)", 2],
  ["Ends in a short number (Summer2024)", 1],
  ["Uses irregular capitals (endsWITHCAPS, aLtErNaTiNg)", 1],
  ["Mixes upper- and lowercase letters with digits", 1],
];

/** Lets a rule author keep only values that look like a password a person made up. */
export default function PasswordShapeFields({ value, onChange, errors }: PasswordShapeFieldsProps) {
  return (
    <fieldset className={`checksum-fields${errors.length > 0 ? " invalid" : ""}`}>
      <legend className="field-label">Password shape</legend>
      <p className="field-hint">
        Optional. Catches passwords people make up, even under a name that doesn't suggest a secret
        (like <code>safe_bet: "…"</code>). Each value is scored on the signals below. Values that
        are clearly something else never count: URLs, paths, emails, numbers, versions, IDs, hashes,
        long random tokens, and names in a regular style such as <code>snake_case</code> or{" "}
        <code>camelCase</code>. A very common password scores the maximum.
      </p>
      <label className="field field-checkbox">
        <input
          type="checkbox"
          checked={value.enabled}
          onChange={(event) => onChange({ ...value, enabled: event.target.checked })}
        />
        Only report values that look like a made-up password
      </label>

      {value.enabled && (
        <>
          <table className="data-table">
            <thead>
              <tr>
                <th>Signal</th>
                <th>Points</th>
              </tr>
            </thead>
            <tbody>
              {SIGNALS.map(([signal, points]) => (
                <tr key={signal}>
                  <td>{signal}</td>
                  <td>{points}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <label className="field">
            <span className="field-label">Minimum score</span>
            <input
              type="number"
              min={1}
              max={PASSWORD_SHAPE_MAX_SCORE}
              value={value.minScore}
              onChange={(event) => onChange({ ...value, minScore: event.target.value })}
            />
            <span className="field-hint">
              1–{PASSWORD_SHAPE_MAX_SCORE}. Lower catches more but flags more ordinary values; 2 is
              the built-in rule's setting. With no key names, this rule only reports values no other
              rule already found.
            </span>
          </label>
        </>
      )}

      {errors.map((error) => (
        <span key={error.message} className="field-error">
          {error.message}
        </span>
      ))}
    </fieldset>
  );
}
