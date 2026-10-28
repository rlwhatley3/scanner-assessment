# Detection engine

A pure Rust library that scans text against a rule set. It does no I/O: callers (the API now, a CLI later) pass in the text and rules, and get back findings and log events. Nothing it returns contains the scanned text or a matched value.

```rust
let result = scan(scan_id, text, &rule_set)?;
// result.findings, result.truncated, result.log
```

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

## How it works

1. **Reject bad input.** Empty text, text over 1 MB, or a rule set with no enabled rules that create findings is an error, not a scan.
2. **Check and compile each enabled rule.** Required fields, value ranges, duplicate names, and whether the pattern compiles (with a size limit). A rule that fails is skipped and reported as a `rule_error` finding pointing at the exact field. The other rules still run, and the scan counts as partial.
3. **Match.** Each rule's regex runs over the text. A rule can narrow a match with a named `value` group (the secret itself) and a named `key` group (the name it's assigned to), then filter on `keyNames` and `minEntropy`. Placeholder vs. real rules run too, and any finding with one of their matches inside it is marked as a likely example.
4. **Cap.** Matches are sorted by position. Beyond 200, the rest are dropped and `truncated` is set.
5. **Group overlaps.** Matches whose ranges overlap share an `overlap_group`, so every caller draws them as one highlight.
6. **Describe each match** with its location (byte offsets, plus 1-based line and column counted in characters, for `\n`, `\r\n`, and lone `\r`), scores, a redacted preview, a "why flagged" note built only from signals, and the rule's remediation hint.

Rust's `regex` crate runs in linear time, so no pattern can backtrack catastrophically.

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

- **Regex plus entropy, not machine learning:** predictable, explainable, and fast, so every finding can say exactly why it was flagged. The cost is false positives on documentation and fixtures (softened by the placeholder score) and misses on secrets with no known format and low randomness.
- **Narrow formats over broad ones:** the direct-credential rules match exact, well-known formats, so they rarely fire by mistake. The assignment rule casts the wider net and is ranked lower.
- **Signals only in explanations:** "why flagged" notes and log events never quote the input, so they're safe to store and log. The cost is that an explanation can't say *which* key name triggered it.
