import type { Checksum, ChecksumEncoding } from "../api.ts";
import {
  CHECKSUM_LABELS,
  CRC32_MAX_LENGTH,
  CRC32_MIN_LENGTH,
  CRC32_PRESETS,
  ENCODING_LABELS,
  MARVIN32_PRESETS,
} from "../checksum.ts";

/** The checksum part of the rule form, as the inputs hold it. */
export interface ChecksumForm {
  algorithm: Checksum["algorithm"] | "";
  encoding: ChecksumEncoding;
  prefixLength: string;
  length: string;
  seed: string;
}

const GITHUB_SETUP = CRC32_PRESETS[0].setup;

export function checksumFormFrom(checksum: Checksum | null | undefined): ChecksumForm {
  const crc32 = checksum?.algorithm === "crc32" ? checksum : { ...GITHUB_SETUP };
  return {
    algorithm: checksum?.algorithm ?? "",
    encoding: crc32.encoding,
    prefixLength: String(crc32.prefixLength),
    length: String(crc32.length),
    seed: checksum?.algorithm === "marvin32" ? checksum.seed : MARVIN32_PRESETS[0].seed,
  };
}

/** The checksum JSON for the definition, or undefined for none. */
export function checksumFrom(form: ChecksumForm): Checksum | undefined {
  switch (form.algorithm) {
    case "":
      return undefined;
    case "crc32":
      return {
        algorithm: "crc32",
        encoding: form.encoding,
        prefixLength: Number(form.prefixLength),
        length: Number(form.length),
      };
    case "marvin32":
      return { algorithm: "marvin32", seed: form.seed };
    default:
      return { algorithm: form.algorithm };
  }
}

interface ChecksumFieldsProps {
  value: ChecksumForm;
  onChange: (value: ChecksumForm) => void;
  errors: { code: string; message: string }[];
}

/** Lets a rule author say whether the token format has a built-in check, and how it works. */
export default function ChecksumFields({ value, onChange, errors }: ChecksumFieldsProps) {
  const set = (patch: Partial<ChecksumForm>) => onChange({ ...value, ...patch });
  const preset = CRC32_PRESETS.find(
    ({ setup }) =>
      setup.encoding === value.encoding &&
      String(setup.prefixLength) === value.prefixLength &&
      String(setup.length) === value.length,
  );

  return (
    <fieldset className={`checksum-fields${errors.length > 0 ? " invalid" : ""}`}>
      <legend className="field-label">Checksum</legend>
      <p className="field-hint">
        Optional. Some token formats carry a built-in check: a few characters are computed from the
        rest. If this rule's format has one, the scanner tests every match. Real values pass;
        made-up ones (examples, test values, typos) almost always fail. Findings then say “Checksum
        valid” or “Checksum fails”. The check runs on the pattern's “value” group, or the whole
        match.
      </p>

      <label className="field">
        <span className="field-label">Type</span>
        <select
          value={value.algorithm}
          onChange={(event) => set({ algorithm: event.target.value as ChecksumForm["algorithm"] })}
        >
          <option value="">None</option>
          {Object.entries(CHECKSUM_LABELS).map(([algorithm, label]) => (
            <option key={algorithm} value={algorithm}>
              {label}
            </option>
          ))}
        </select>
      </label>

      {value.algorithm === "crc32" && (
        <>
          <p className="field-hint">
            The token is read as <b>prefix</b> + <b>covered part</b> + <b>checksum</b>, where the
            checksum is the CRC32 of the covered part written in the chosen digits.
          </p>
          <label className="field">
            <span className="field-label">Start from</span>
            <select
              value={preset?.label ?? ""}
              onChange={(event) => {
                const chosen = CRC32_PRESETS.find((option) => option.label === event.target.value);
                if (chosen) {
                  set({
                    encoding: chosen.setup.encoding,
                    prefixLength: String(chosen.setup.prefixLength),
                    length: String(chosen.setup.length),
                  });
                }
              }}
            >
              <option value="">Custom</option>
              {CRC32_PRESETS.map((option) => (
                <option key={option.label} value={option.label}>
                  {option.label}
                </option>
              ))}
            </select>
          </label>
          <div className="field-row">
            <label className="field">
              <span className="field-label">Digits</span>
              <select
                value={value.encoding}
                onChange={(event) => set({ encoding: event.target.value as ChecksumEncoding })}
              >
                {Object.entries(ENCODING_LABELS).map(([encoding, label]) => (
                  <option key={encoding} value={encoding}>
                    {label}
                  </option>
                ))}
              </select>
            </label>
            <label className="field">
              <span className="field-label">Prefix length</span>
              <input
                type="number"
                min={0}
                value={value.prefixLength}
                onChange={(event) => set({ prefixLength: event.target.value })}
              />
              <span className="field-hint">Leading characters not covered, e.g. 4 for ghp_.</span>
            </label>
            <label className="field">
              <span className="field-label">Checksum length</span>
              <input
                type="number"
                min={CRC32_MIN_LENGTH[value.encoding]}
                max={CRC32_MAX_LENGTH}
                value={value.length}
                onChange={(event) => set({ length: event.target.value })}
              />
              <span className="field-hint">
                Characters at the end that hold it: {CRC32_MIN_LENGTH[value.encoding]}–
                {CRC32_MAX_LENGTH} for this digit style.
              </span>
            </label>
          </div>
        </>
      )}

      {value.algorithm === "marvin32" && (
        <>
          <p className="field-hint">
            Each kind of Azure key is checked with its own seed. Pick the service this rule's keys
            come from.
          </p>
          <div className="field-row">
            <label className="field">
              <span className="field-label">Key kind</span>
              <select
                value={MARVIN32_PRESETS.some(({ seed }) => seed === value.seed) ? value.seed : ""}
                onChange={(event) => {
                  if (event.target.value) set({ seed: event.target.value });
                }}
              >
                <option value="">Custom</option>
                {MARVIN32_PRESETS.map((option) => (
                  <option key={option.seed} value={option.seed}>
                    {option.label}
                  </option>
                ))}
              </select>
            </label>
            <label className="field">
              <span className="field-label">Seed</span>
              <input
                value={value.seed}
                maxLength={8}
                onChange={(event) => set({ seed: event.target.value })}
              />
              <span className="field-hint">Exactly 8 characters, e.g. Default0.</span>
            </label>
          </div>
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
