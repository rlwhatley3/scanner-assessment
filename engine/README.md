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
        "checksum": null,
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
3. **Read the format.** The text is read as JSON, YAML, `.env`, or plain text (see [File format parsing](#file-format-parsing)). This finds its comments and its real key/value pairs.
4. **Match.** Each rule's regex runs over the text. A rule can narrow a match with a named `value` group (the secret itself) and a named `key` group (the name it's assigned to), then filter on `keyNames` and `minEntropy`. Likely-credential rules also check the parsed key/value pairs. A rule with a `checksum` checks each match against it. Placeholder vs. real rules run too, and any finding with one of their matches inside it is marked as a likely example.
5. **Cap.** Matches are sorted by position. Beyond 200, the rest are dropped and `truncated` is set.
6. **Group overlaps.** Matches whose ranges overlap share an `overlap_group`, so every caller draws them as one highlight.
7. **Describe each match** with its location (byte offsets, plus 1-based line and column counted in characters, for `\n`, `\r\n`, and lone `\r`), scores, a redacted preview, a "why flagged" note built only from signals, and the rule's remediation hint.

Rust's `regex` crate runs in linear time, so no pattern can backtrack catastrophically.

## Built-in rules

These are seeded as the first rule set version from [`rule_sets/default.json`](rule_sets/default.json). Each one is ordinary data that users can edit, disable, or remove.

| Rule | Detection type | Severity | Catches | Misses / limits |
|---|---|---|---|---|
| AWS access key | Direct credential | High | `AKIA` followed by 16 uppercase letters or digits | Other AWS key prefixes (`ASIA` temporary keys); secret access keys, which have no fixed format |
| GitHub token | Direct credential | High | `ghp_`, `gho_`, `ghu_`, `ghs_`, or `ghr_` followed by 36 letters or digits, checked with GitHub's CRC32 checksum | Fine-grained tokens (`github_pat_`), which use a different format |
| Private key block | Direct credential | High | A `-----BEGIN … PRIVATE KEY-----` block, through its END line when present, otherwise just the header | Keys stored without PEM armor (raw base64, JWKs) |
| Secret-looking assignment | Likely credential | Medium | A value of 8+ characters assigned with `=` or `:` to a name containing `password`, `passwd`, `secret`, `api_key`, `apikey`, or `token`, with at least 3.0 bits of entropy per character | Short or low-randomness secrets; secrets under other names. Values starting with `$`, `{`, or `(` are treated as references (`${DB_PASSWORD}`) and skipped |
| Secret written to a log | Unsafe handling | Medium | `console.log`/`info`/`warn`/`error`/`debug`, `print`, `println!`, `logger.*`, or `log.*` with a secret-sounding name among its arguments | Calls split across lines; secrets passed through a renamed variable |
| Known placeholder values | Placeholder vs. real | n/a | `your_key_here`, `changeme`, `xxxx`, `example`, `dummy`, or `test` (any case) inside another rule's finding, which then scores as a likely example | Fake values not on the list; a real secret that happens to contain `test` scores as an example |

## Scores

- **Confidence (0–100):** how sure the engine is that this is a secret of the rule's kind.
  - Direct credentials: 95, or 99 when the checksum passes and 50 when it fails.
  - Likely credentials: 50–90, rising with entropy above the rule's threshold.
  - Unsafe handling: 70, or 30 when it's commented out.
- **Placeholder vs. real (0–100, higher = more likely an example):** 95 when a placeholder vs. real rule matches inside the value. 70 when any other example signal is present: very little randomness (under 2 bits per character), a failed checksum, or the value sitting in a comment. Otherwise 5. There is no score for unsafe handling, which has no value.

Every match also reports `inComment` and `checksumValid` (absent when the rule has no checksum), and the scan result reports the `format` the text was read as.

## Checksums

Some token formats carry a checksum, so a match can be checked offline, with no network call: a real-format token passes, and a made-up one (an example, a test value, random text) almost always fails.

A rule describes its token format's checksum in its `checksum` field. A token is read as `prefix + covered part + checksum`:

```json
"checksum": { "algorithm": "crc32", "encoding": "base62", "prefixLength": 4, "length": 6 }
```

| Field | Values | Meaning |
|---|---|---|
| `algorithm` | `crc32` | How the checksum is computed from the covered part |
| `encoding` | `base62` (digits `0-9A-Za-z`), `hex` (either case) | How the value is written |
| `prefixLength` | 0 or more | Characters at the start the checksum doesn't cover, such as `ghp_` |
| `length` | 6–16 for base62, 8–16 for hex | Characters at the end holding the checksum, zero-padded |

**Seeded setups:** the built-in rules carry the common ones, so a rule author can copy them:

| Built-in rule | Setup |
|---|---|
| GitHub token (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`) | `crc32`, `base62`, prefix 4, length 6 ([GitHub](https://github.blog/engineering/behind-githubs-new-authentication-token-formats/)) |
| npm token (`npm_`) | `crc32`, `base62`, prefix 4, length 6 ([npm uses GitHub's format](https://github.blog/security/announcing-npms-new-access-token-format)) |

**Custom setups:** a rule for an in-house token format describes its own, e.g. `acme_` followed by the covered part and an 8-digit hex CRC32 is `{ "algorithm": "crc32", "encoding": "hex", "prefixLength": 5, "length": 8 }`. A length too short to hold the full value, or longer than 16, is a rule error on the `checksum` field.

A failed checksum lowers confidence and raises the placeholder score; it never drops the finding. GitHub and npm haven't published test tokens, so the seeded setups follow their descriptions and existing open-source validators. If a setup were ever subtly wrong, real tokens would still be reported, just at lower confidence. The same holds for a mistaken custom setup.

## File format parsing

Before matching, the text is read as the format it is:

| Format | Detected when | What's parsed |
|---|---|---|
| JSON | It starts with `{` or `[` and parses as JSON | Every `"key": "string value"` pair, at any depth, even split across lines |
| `.env` | At least half the lines are `KEY=value` (optionally `export KEY=value`) | `KEY=value` pairs; `#` comment lines and trailing ` # comments` |
| YAML | At least half the lines are `key: value` | `key: value` pairs; `#` comment lines and trailing ` # comments` |
| Text | Anything else | `#` and `//` comment lines only |

Quotes are stripped from parsed values, and a `#` inside quotes is not a comment. All positions stay exact byte ranges into the original text.

What it changes:
- **Fewer misses:** likely-credential rules also check parsed values under suspicious key names, so a quoted value containing `$` or `;`, or a JSON key and value on separate lines, is still caught. A value found both ways is reported once.
- **Fewer false alarms:** a secret inside a comment is still reported, but it scores as a likely example, since comments are where examples live. Commented-out code that logs a secret drops to low confidence, since it doesn't run.

Source code isn't parsed into a syntax tree. That would need a parser per language (e.g. tree-sitter), so code is only scanned as text, with its `//` and `#` comment lines recognized.

## Trade-offs

- **Regex plus entropy, checksums, and format parsing, not machine learning:** predictable, explainable, and fast, so every finding can say exactly why it was flagged. Checksums and format parsing reduce false positives and misses without leaving the machine. The cost is remaining false positives on documentation and fixtures (softened by the placeholder score) and misses on secrets with no known format and low randomness.
- **No live verification:** asking a provider whether a secret works (as TruffleHog does) is the strongest signal, but it sends the secret off the machine, which this design rules out.
- **Narrow formats over broad ones:** the direct-credential rules match exact, well-known formats, so they rarely fire by mistake. The assignment rule casts the wider net and is ranked lower.
- **Signals only in explanations:** "why flagged" notes and log events never quote the input, so they're safe to store and log. The cost is that an explanation can't say *which* key name triggered it.
