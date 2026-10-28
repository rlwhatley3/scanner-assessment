# Detection engine

A pure Rust library that scans text against a rule set. It does no I/O: callers (the API now, a CLI later) pass in the text and rules, and get back findings and log events. Nothing it returns contains the scanned text or a matched value.

```rust
let result = scan(scan_id, text, &rule_set)?;
// result.findings, result.truncated, result.log
```

Rule sets with [model rules](#model-rules) use `scan_with_models` and need the `ml` feature.

## The rule set contract

The API hands the engine one rule set version as JSON in this shape, and the engine parses it into a `RuleSet`:

```json
{
  "rules": [
    {
      "id": 1,
      "definition": {
        "name": "AWS access key",
        "enabled": true,
        "detectionType": "direct_credential",
        "severity": "high",
        "pattern": "\\bAKIA[0-9A-Z]{16}\\b",
        "prefix": "AKIA",
        "keyNames": [],
        "minEntropy": null,
        "remediation": "Deactivate this key in AWS IAM..."
      }
    }
  ]
}
```

- `id` is the rule's database id, and `definition` is the snapshot stored with that rule set version.
- Every `definition` field is optional, so a half-filled draft still parses and gets field-level errors. Missing `enabled` means enabled.
- Unknown or misspelled fields are rejected at every level, so a contract mismatch fails loudly instead of being ignored.

The built-in rule set lives in [`rule_sets/default.json`](rule_sets/default.json) in exactly this shape, so loading it exercises the same contract the API uses.

## Rule types

| Type | What its matches do |
|---|---|
| `direct_credential` | Create a finding: a secret value in a known format |
| `likely_credential` | Create a finding: a random-looking value assigned to a suspicious name |
| `unsafe_handling` | Create a finding: code that handles a secret unsafely, with no secret value involved |
| `placeholder_vs_real` | Create no finding. A match that falls inside another rule's finding marks that finding as a likely example. Severity and remediation don't apply |
| `model_assessment` | Create no finding. A model rates each finding's value as likely real or likely an example. Takes a model and threshold instead of a pattern. Severity and remediation don't apply |
| `model_detection` | Create a finding: a span a model flags as a secret, including ones no pattern describes. Takes a model and threshold instead of a pattern |

## How it works

1. **Reject bad input.** Empty text, text over 1 MB, or a rule set with no enabled rules that create findings is an error, not a scan.
2. **Check and compile each enabled rule.** Required fields, value ranges, duplicate names, and whether the pattern compiles (with a size limit). A rule that fails is skipped and reported as a `rule_error` finding pointing at the exact field. The other rules still run, and the scan counts as partial.
3. **Match.** Each rule's regex runs over the text. A rule can narrow a match with a named `value` group (the secret itself) and a named `key` group (the name it's assigned to), then filter on `keyNames` and `minEntropy`. Placeholder vs. real rules run too, and any finding with one of their matches inside it is marked as a likely example.
4. **Cap.** Matches are sorted by position. Beyond 200, the rest are dropped and `truncated` is set.
5. **Group overlaps.** Matches whose ranges overlap share an `overlap_group`, so every caller draws them as one highlight.
6. **Describe each match** with its location (byte offsets, plus 1-based line and column counted in characters, for `\n`, `\r\n`, and lone `\r`), scores, a redacted preview, a "why flagged" note built only from signals, and the rule's remediation hint.

Rust's `regex` crate runs in linear time, so no pattern can backtrack catastrophically.

## Model rules

Model rules add a model's judgment on top of the pattern rules. A rule set without them scans exactly as before. They run only when the engine is built with the `ml` feature (`cargo build --features ml`), which runs ONNX models on the CPU with [tract](https://github.com/sonos/tract), a pure-Rust runtime.

```json
{
  "name": "ML: real vs example",
  "detectionType": "model_assessment",
  "model": { "id": "triage-small", "sha256": "…64 hex characters…" },
  "threshold": 80
}
```

- **The hash identifies the model.** Callers read model files themselves (the engine does no I/O), pass the bytes to `Models::load`, which returns their SHA-256, and pass the `Models` to `scan_with_models`. A rule set version names the exact model it scanned with.
- **Results stay discrete.** A model's output is rounded to a 0–100 score before the threshold is applied, so tiny floating-point differences can't flip a result, and the same text, rule set version, and model always give the same findings.
- **A model problem is a rule error, not a failed scan.** A model that wasn't loaded, doesn't fit its rule type, or fails while running makes that rule a `rule_error` (field `model`, code `model_unavailable` or `model_failed`), and the scan is partial. Without the `ml` feature, every model rule reports that the engine was built without model support.
- **Checked like other rules:** `model.sha256` must be 64 hexadecimal characters and `threshold` 0–100; neither needs a pattern. A detection rule needs a severity; an assessment rule doesn't.

### What a model reads and returns

Every model takes one row of token ids, `int64[1, L]`, with `L` fixed by the model (the batch size may be left open). `0` pads, `1` and `2` mark where a value starts and ends, and each byte `b` of the text is `b + 3`.

| Rule type | Input | Output | What the engine does with it |
|---|---|---|---|
| `model_assessment` | The finding's value between markers `1` and `2`, with as much text on either side as fits `L`, split evenly | One score, `float[1, 1]`: how likely the value is a real secret | Adds a `modelAssessments` entry (rule, score, and `likely_real` or `likely_example`) and a line to "why flagged". Never changes the finding's confidence or placeholder score |
| `model_detection` | `L` bytes of text, no markers; windows start every `L / 2` bytes | One score per byte, `float[1, L]`: how likely that byte is part of a secret | Each byte keeps its highest score from any window. Runs of bytes at or above the threshold, widened to whole characters, become findings; runs under 8 bytes are dropped. The finding's confidence is the run's highest score |

- **Assessments run after the 200-finding cap,** so a flood of matches can't multiply model runs. Findings with no value (unsafe handling) get no assessment. Detection findings are assessed too.
- **Detection reads the whole text,** about `2 × bytes / L` model runs per scan, so it is the slowest rule type: a 1 MB input with `L = 256` means about 8,000 model runs.

### Training a model

The engine ships no model; any ONNX model with the shapes above works. The quickest start is a small byte-level convolutional network trained in PyTorch on synthetic data (real-shaped values in config and code lines labeled real, documentation and test values labeled examples, and secrets planted in ordinary text for detection), then exported to ONNX with a fixed `L`. A model trained only on synthetic data learns the generator, so it proves the pipeline but needs real labeled data before its verdicts can be trusted.

The tests in `tests/models.rs` build tiny hand-written ONNX models in code, so they need no model files.

## Built-in rules

These are seeded as the first rule set version from [`rule_sets/default.json`](rule_sets/default.json). Each one is ordinary data that users can edit, disable, or remove.

| Rule | Detection type | Severity | Catches | Misses / limits |
|---|---|---|---|---|
| AWS access key | Direct credential | High | `AKIA` followed by 16 uppercase letters or digits | Other AWS key prefixes (`ASIA` temporary keys); secret access keys, which have no fixed format |
| GitHub token | Direct credential | High | `ghp_` followed by 36 letters or digits | Other GitHub token types (`gho_`, `ghs_`, `github_pat_`) |
| Private key block | Direct credential | High | A `-----BEGIN … PRIVATE KEY-----` block, through its END line when present, otherwise just the header | Keys stored without PEM armor (raw base64, JWKs) |
| Secret-looking assignment | Likely credential | Medium | A value of 8+ characters assigned with `=` or `:` to a name containing `password`, `passwd`, `secret`, `api_key`, `apikey`, or `token`, with at least 3.0 bits of entropy per character | Short or low-randomness secrets; secrets under other names. Values starting with `$`, `{`, or `(` are treated as references (`${DB_PASSWORD}`) and skipped |
| Secret written to a log | Unsafe handling | Medium | `console.log`/`info`/`warn`/`error`/`debug`, `print`, `println!`, `logger.*`, or `log.*` with a secret-sounding name among its arguments | Calls split across lines; secrets passed through a renamed variable |
| Known placeholder values | Placeholder vs. real | n/a | `your_key_here`, `changeme`, `xxxx`, `example`, `dummy`, or `test` (any case) inside another rule's finding, which then scores as a likely example | Fake values not on the list; a real secret that happens to contain `test` scores as an example |

## Scores

- **Confidence (0–100):** how sure the engine is that this is a secret of the rule's kind. Direct credentials score 95, unsafe handling 70, and likely credentials 50–90, rising with entropy above the rule's threshold.
- **Placeholder vs. real (0–100, higher = more likely an example):** 95 when a placeholder vs. real rule matches inside the value, 70 when it has very little randomness (under 2 bits per character), otherwise 5. There is no score for unsafe handling, which has no value.

## Trade-offs

- **Regex plus entropy first, machine learning as an optional extra:** the built-in rules are predictable, explainable, and fast, so every finding can say exactly why it was flagged. The cost is false positives on documentation and fixtures (softened by the placeholder score) and misses on secrets with no known format and low randomness. Model rules target both, but only when a rule set includes them, and their verdicts sit beside the pattern rules' scores instead of replacing them.
- **Narrow formats over broad ones:** the direct-credential rules match exact, well-known formats, so they rarely fire by mistake. The assignment rule casts the wider net and is ranked lower.
- **Signals only in explanations:** "why flagged" notes and log events never quote the input, so they're safe to store and log. The cost is that an explanation can't say *which* key name triggered it.
