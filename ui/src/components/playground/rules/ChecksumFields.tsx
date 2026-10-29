import { useEffect, useState } from "react";
import { ApiError, type ChecksumEncoding, type TryChecksumResponse, tryChecksum } from "../api.ts";
import {
  CALCULATION_LABELS,
  CHECKSUM_LABELS,
  CRC32_MAX_LENGTH,
  CRC32_MIN_LENGTH,
  CRC32_PRESETS,
  ENCODING_LABELS,
  HASH_LABELS,
  IN_HOUSE_ALGORITHMS,
  isInHouse,
  MARVIN32_PRESETS,
} from "../checksum.ts";
import { type ChecksumForm, checksumFrom, withCalculation } from "./checksumForm.ts";

/** The Type choice that opens the three questions for a format the author describes. */
const DESCRIBE = "describe";

interface ChecksumFieldsProps {
  value: ChecksumForm;
  onChange: (value: ChecksumForm) => void;
  errors: { code: string; message: string }[];
}

/** Lets a rule author say whether the token format has a built-in check, and how it works. */
export default function ChecksumFields({ value, onChange, errors }: ChecksumFieldsProps) {
  const set = (patch: Partial<ChecksumForm>) => onChange({ ...value, ...patch });
  const inHouse = isInHouse(value.algorithm);
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
          value={inHouse ? DESCRIBE : value.algorithm}
          onChange={(event) => {
            const choice = event.target.value;
            if (choice === DESCRIBE) onChange(withCalculation(value, "crc32"));
            else set({ algorithm: choice as ChecksumForm["algorithm"] });
          }}
        >
          <option value="">None</option>
          {Object.entries(CHECKSUM_LABELS)
            .filter(([algorithm]) => !isInHouse(algorithm))
            .map(([algorithm, label]) => (
              <option key={algorithm} value={algorithm}>
                {label}
              </option>
            ))}
          <option value={DESCRIBE}>Describe it yourself (in-house formats, GitHub, GitLab)</option>
        </select>
      </label>

      {inHouse && (
        <>
          <div className="checksum-question">
            <span className="field-label">1. Which part is the checksum?</span>
            <div className="field-row">
              <label className="field">
                <span className="field-label">The last</span>
                <input
                  type="number"
                  min={1}
                  value={value.length}
                  onChange={(event) => set({ length: event.target.value })}
                />
                <span className="field-hint">
                  characters.
                  {value.algorithm === "crc32" &&
                    ` ${CRC32_MIN_LENGTH[value.encoding]}–${CRC32_MAX_LENGTH} for these digits.`}
                </span>
              </label>
              <label className="field">
                <span className="field-label">Skip the first</span>
                <input
                  type="number"
                  min={0}
                  value={value.prefixLength}
                  onChange={(event) => set({ prefixLength: event.target.value })}
                />
                <span className="field-hint">
                  characters it doesn't cover, e.g. 5 for acme_. 0 if it covers everything before
                  it.
                </span>
              </label>
            </div>
          </div>

          <div className="checksum-question">
            <label className="field">
              <span className="field-label">2. How is it calculated?</span>
              <select
                value={value.algorithm}
                onChange={(event) =>
                  onChange(
                    withCalculation(
                      value,
                      event.target.value as (typeof IN_HOUSE_ALGORITHMS)[number],
                    ),
                  )
                }
              >
                {IN_HOUSE_ALGORITHMS.map((algorithm) => (
                  <option key={algorithm} value={algorithm}>
                    {CALCULATION_LABELS[algorithm]}
                  </option>
                ))}
              </select>
            </label>

            {value.algorithm === "crc32" && (
              <label className="field">
                <span className="field-label">Start from</span>
                <select
                  value={preset?.label ?? ""}
                  onChange={(event) => {
                    const chosen = CRC32_PRESETS.find(
                      (option) => option.label === event.target.value,
                    );
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
            )}

            {value.algorithm === "check_digit" && (
              <div className="field-row">
                <label className="field">
                  <span className="field-label">Weights</span>
                  <input
                    value={value.weights}
                    onChange={(event) => set({ weights: event.target.value })}
                  />
                  <span className="field-hint">
                    Multipliers, from the right end of the covered part, e.g. 3, 1. They repeat when
                    they run out.
                  </span>
                </label>
                <label className="field">
                  <span className="field-label">Modulus</span>
                  <input
                    type="number"
                    min={2}
                    value={value.modulus}
                    onChange={(event) => set({ modulus: event.target.value })}
                  />
                  <span className="field-hint">The total is divided by this, e.g. 10 or 11.</span>
                </label>
                <label className="field">
                  <span className="field-label">The check is</span>
                  <select
                    value={value.check}
                    onChange={(event) =>
                      set({ check: event.target.value as ChecksumForm["check"] })
                    }
                  >
                    <option value="complement">What makes the total divide evenly</option>
                    <option value="remainder">The remainder</option>
                  </select>
                </label>
              </div>
            )}

            {value.algorithm === "hash" && (
              <div className="field-row">
                <label className="field">
                  <span className="field-label">Hash</span>
                  <select
                    value={value.hash}
                    onChange={(event) => set({ hash: event.target.value as ChecksumForm["hash"] })}
                  >
                    {Object.entries(HASH_LABELS).map(([hash, label]) => (
                      <option key={hash} value={hash}>
                        {label}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="field">
                  <span className="field-label">Keep the first</span>
                  <input
                    type="number"
                    min={1}
                    max={8}
                    value={value.bytes}
                    onChange={(event) => set({ bytes: event.target.value })}
                  />
                  <span className="field-hint">bytes of the hash (1–8).</span>
                </label>
              </div>
            )}
          </div>

          <div className="checksum-question">
            {value.algorithm === "check_digit" ? (
              <label className="field">
                <span className="field-label">3. How is it written?</span>
                <input
                  value={value.alphabet}
                  onChange={(event) => set({ alphabet: event.target.value })}
                />
                <span className="field-hint">
                  The characters it uses, in order. Each one is worth its position: 0123456789X
                  makes X worth 10.
                </span>
              </label>
            ) : (
              <label className="field">
                <span className="field-label">3. How is it written?</span>
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
            )}
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

      {value.algorithm !== "" && <ExampleCheck form={value} />}

      {errors.map((error) => (
        <span key={error.message} className="field-error">
          {error.message}
        </span>
      ))}
    </fieldset>
  );
}

type ExampleResult =
  | { state: "idle" }
  | { state: "checking" }
  | { state: "done"; example: string; result: TryChecksumResponse }
  | { state: "failed"; message: string };

/** One example token, checked as the author types. It is never saved with the rule. */
function ExampleCheck({ form }: { form: ChecksumForm }) {
  const [example, setExample] = useState("");
  const [result, setResult] = useState<ExampleResult>({ state: "idle" });
  const checksum = JSON.stringify(checksumFrom(form));

  useEffect(() => {
    if (example === "" || checksum === undefined) {
      setResult({ state: "idle" });
      return;
    }
    const controller = new AbortController();
    setResult({ state: "checking" });
    const timer = setTimeout(() => {
      tryChecksum(JSON.parse(checksum), example, controller.signal)
        .then((response) => setResult({ state: "done", example, result: response }))
        .catch((error: unknown) => {
          if (controller.signal.aborted) return;
          setResult({
            state: "failed",
            message: error instanceof ApiError ? error.message : "Couldn't check the example.",
          });
        });
    }, 300);
    return () => {
      clearTimeout(timer);
      controller.abort();
    };
  }, [checksum, example]);

  return (
    <div className="checksum-example">
      <label className="field">
        <span className="field-label">Try a real example (optional)</span>
        <input
          value={example}
          spellCheck={false}
          autoComplete="off"
          placeholder="Paste one token to check"
          onChange={(event) => setExample(event.target.value)}
        />
        <span className="field-hint">Checked once to show whether it passes; never saved.</span>
      </label>
      {result.state === "checking" && <span className="muted">Checking…</span>}
      {result.state === "failed" && <span className="field-error">{result.message}</span>}
      {result.state === "done" && (
        <div className="checksum-result">
          <span className={result.result.valid ? "checksum-pass" : "checksum-fail"}>
            {result.result.valid ? "✓ Passes" : "✗ Doesn't pass"}
          </span>
          {result.result.layout && (
            <code className="checksum-parts">
              <span className="part-prefix" title="Not covered">
                {result.example.slice(0, result.result.layout.coveredStart)}
              </span>
              <span className="part-covered" title="Covered by the checksum">
                {result.example.slice(
                  result.result.layout.coveredStart,
                  result.result.layout.checksumStart,
                )}
              </span>
              <span className="part-checksum" title="The checksum">
                {result.example.slice(result.result.layout.checksumStart)}
              </span>
            </code>
          )}
          {result.result.layout && (
            <span className="field-hint checksum-legend">
              <span className="part-prefix">skipped</span>{" "}
              <span className="part-covered">covered</span>{" "}
              <span className="part-checksum">checksum</span>
            </span>
          )}
        </div>
      )}
    </div>
  );
}
