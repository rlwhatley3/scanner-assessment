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
        "checksum": null,
        "passwordShape": null,
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
3. **Read the format.** The text is read as JSON, YAML, `.env`, or plain text (see [File format parsing](#file-format-parsing)). This finds its comments and its real key/value pairs.
4. **Match.** Each rule's regex runs over the text. A rule can narrow a match with a named `value` group (the secret itself) and a named `key` group (the name it's assigned to), then filter on `keyNames` and `minEntropy`. Likely-credential rules also check the parsed key/value pairs. A rule with a `checksum` checks each match against it. Placeholder vs. real rules run too, and any finding with one of their matches inside it is marked as a likely example.
5. **Cap.** Matches are sorted by position. Beyond 200, the rest are dropped and `truncated` is set.
6. **Group overlaps.** Matches whose ranges overlap share an `overlap_group`, so every caller draws them as one highlight.
7. **Describe each match** with its location (byte offsets, plus 1-based line and column counted in characters, for `\n`, `\r\n`, and lone `\r`), scores, a redacted preview, a "why flagged" note built only from signals, and the rule's remediation hint.

Rust's `regex` crate runs in linear time, so no pattern can backtrack catastrophically.

## Model rules

Models add judgment on top of the pattern rules in two ways: as **model rules** (`model_assessment`, `model_detection`), and as a pattern rule's **[value classifier setting](#value-classifier-setting)**, which checks that rule's own matches the way a checksum does. A [trained value classifier](#the-value-classifier) and a [trained secret detector](#the-secret-detector) ship with the engine. A rule set without models scans exactly as before. They run only when the engine is built with the `ml` feature (`cargo build --features ml`), which runs ONNX models on the CPU with [tract](https://github.com/sonos/tract), a pure-Rust runtime.

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
- **Detection reads the whole text,** about `2 × bytes / L` model runs per scan, so it is the slowest rule type: a 1 MB input with `L = 256` means about 8,000 model runs. With the bundled detector that takes about 3.5 seconds in a release build (see [below](#the-secret-detector)).

### Value classifier setting

A pattern rule can run a model on its own matches to say what each matched value is: a credential, a non-secret random string (a hash, digest, ID, or encoded data), or a placeholder.

```json
"valueClassifier": {
  "model": { "id": "value-classifier", "sha256": "…64 hex characters…" },
  "minScore": 50
}
```

- **Input and output:** the same value-between-markers input as a model assessment, but built from the value's own line only, so the name it's assigned to counts and other lines don't. The output is three scores, `float[1, 3]`, that sum to 1: credential, non-secret, placeholder.
- **What it changes:** a value whose credential score (0–100) is below `minScore` keeps its finding, but its confidence drops to 30, the same as commented-out code, and "why flagged" says what the value looks like instead. A credential score above the rule's own confidence raises it halfway toward that score, up to 95, so a model alone is never surer than a known format. A value rated a placeholder also counts as an example signal for the placeholder score. The finding records the scores as `valueClass`.
- **Where it helps:** rules that match by randomness or password shape, which can't tell a password from a commit hash, UUID, or digest under a secret-sounding name. Fixed-format rules (`AKIA…`, `ghp_…`) don't need it.
- **Checked like a checksum:** `model.sha256` must be 64 hexadecimal characters and `minScore` 0–100. A model that wasn't loaded or doesn't return three scores makes the rule a `rule_error` (field `value_classifier`), so none of its matches are reported. Each value is classified once per model, after the 200-finding cap. Rules with no value (unsafe handling) ignore the setting.

### The value classifier

[`models/value-classifier.onnx`](models/value-classifier.onnx) is a trained model for the value classifier setting (about 140 KB, `L = 128`, SHA-256 `e620ed64…1459`). The engine exports it as `VALUE_CLASSIFIER_ONNX`, with `value_classifier_setting()` naming it at a minimum score of 50. The engine's built-in rule set doesn't use it, since that runs without models. The API loads it at startup, lists it at `GET /api/models` (and the MCP `list_models` tool), and turns it on for every likely-credential built-in rule (secret-looking assignment, password-shaped value, Bearer tokens, session cookies) when it seeds a new database. [`ml/`](../ml/README.md) has the code that trains it and how to retrain it.

It judges the matched value and the name it's assigned to, not the file around it: it doesn't try to tell a test from production config. It is a small byte-level convolutional network trained only on synthetic data, so its held-out accuracy (99%) says little about real repositories. Known limits:

- A hex string under a secret-sounding name is genuinely ambiguous (an API key or a hash), and it may call it either way.
- Some values get the wrong "not a credential" class: a resource path can come back as a placeholder rather than a non-secret. The outcome, lower confidence, is still right.
- Credentials whose format looks like an ID, such as API keys that are UUIDs, will be rated non-secret.
- Retraining changes the file's hash. Rule set versions that name the old hash keep naming it, so their rules report the classifier as unavailable until a new version uses the new setting.

`tests/value_classifier.rs` runs it through the engine on hand-written cases: passwords and keys, hashes and UUIDs under secret-sounding names, URLs and paths, and placeholders.

### The secret detector

[`models/secret-detector.onnx`](models/secret-detector.onnx) is a trained `model_detection` model (about 170 KB, `L = 256`, SHA-256 `cb18c8a0…21c8`). It reads raw text and scores every byte, so it can flag secrets no pattern rule describes: a token from a vendor with no rule, a password passed to a function, a key in a chat message. Like the classifier it is not part of the built-in rule set; the engine exports it as `SECRET_DETECTOR_ONNX` with a ready-made rule, `secret_detector_rule()` (severity medium, threshold 50). The API loads it at startup and lists it at `GET /api/models` as fitting `model_detection`, but does not seed a rule for it. [`ml/`](../ml/README.md#secret-detector-training) has the code that trains it.

It is a byte-level convolutional network trained only on synthetic documents. On held-out generated documents it has precision 0.96 and recall 0.96 at threshold 50; on the hand-written batch that was never used to tune it, it found 11 of 12 secrets with 2 of 14 findings wrong and flagged nothing in 8 texts without secrets. [`ml/README.md`](../ml/README.md#how-good-the-detector-is) has the full numbers and what they do and don't show.

- **Spans are approximate.** A finding covers the bytes the model scored at or above the threshold, so it can stop a few characters short of a secret or run into a quote. A private key's finding covers its `-----BEGIN` line and first line of key data, not the whole block.
- **It misses secrets that only their name gives away when the name is bland**, such as a bare hex key in `maps = "…"`, and sometimes flags text right next to a secret (table borders, the setting on the line above) as a finding of its own.
- **No test or example context.** A real-looking value in a test or README is flagged; placeholders are only recognized by how they look.
- **Speed.** A 1 MB scan takes about 3.5 seconds in a release build and about 30 seconds in a debug build (Apple M1 Pro, one thread; `tests/secret_detector.rs` has the timing, run with `--ignored`). The time goes into the convolutions, not per-run overhead, so batching windows would gain little; a smaller network or running windows on several threads would.
- **Retraining changes the file's hash.** Rule set versions that name the old hash report the detector rule as unavailable until a new version names the new one.

`tests/secret_detector.rs` runs it through the engine on the three hand-written batches and asserts exactly what it gets wrong today.

The tests in `tests/models.rs` build tiny hand-written ONNX models in code, so they need no model files.

## Built-in rules

These are seeded as the first rule set version from [`rule_sets/default.json`](rule_sets/default.json). Each one is ordinary data that users can edit, disable, or remove.

| Rule | Detection type | Severity | Catches | Misses / limits |
|---|---|---|---|---|
| AWS access key | Direct credential | High | `AKIA` followed by 16 uppercase letters or digits | Other AWS key prefixes (`ASIA` temporary keys); secret access keys, which have no fixed format |
| GitHub token | Direct credential | High | `ghp_`, `gho_`, `ghu_`, `ghs_`, or `ghr_` followed by 36 letters or digits, checked with GitHub's CRC32 checksum | Fine-grained tokens (`github_pat_`), which use a different format |
| Private key block | Direct credential | High | A `-----BEGIN … PRIVATE KEY-----` block (or PGP's `PRIVATE KEY BLOCK`), through its END line when present, otherwise just the header | Keys without PEM armor have their own rules below |
| Secret-looking assignment | Likely credential | Medium | A value of 8+ characters assigned with `=` or `:` to a name containing `password`, `passwd`, `passphrase`, `_pass`, `_pwd`, `secret`, `api_key`, `apikey`, `api-key`, `token`, `signing_key`, `encryption_key`, or `master_key` (with or without the underscore), with at least 3.0 bits of entropy per character | Short or low-randomness secrets; secrets under other names. Values starting with `$`, `{`, or `(` are treated as references (`${DB_PASSWORD}`) and skipped |
| Secret written to a log | Unsafe handling | Medium | `console.log`/`info`/`warn`/`error`/`debug`, `print`, `println!`, `logger.*`, or `log.*` with a secret-sounding name (including `passphrase`, `api-key`, and `private key`) among its arguments | Calls split across lines; secrets passed through a renamed variable |
| Known placeholder values | Placeholder vs. real | n/a | `your_key_here`, `changeme` or `change_me`, `xxxx`, `example`, `dummy`, `test`, or a URL password of literally `password` (`:password@`), in any case, inside another rule's finding, which then scores as a likely example | Fake values not on the list; a real secret that happens to contain `test` scores as an example |
| npm token | Direct credential | High | `npm_` followed by 36 letters or digits, checked with the same CRC32 checksum as GitHub | Legacy npm tokens (UUIDs), which npm retired |
| GitLab personal access token | Direct credential | High | Routable `glpat-` tokens (37 to 310 characters after the prefix), checked with GitLab's base36 CRC32 checksum | Other GitLab token types (`gldt-`, `glrt-`, ...) |
| GitLab personal access token (legacy format) | Direct credential | High | `glpat-` followed by exactly 20 characters, the format before routable tokens; it has no checksum | Same as above |
| Payment card number | Direct credential | High | Visa (13 or 16 to 19 digits), Mastercard (16), Amex (15), Diners Club (14), and Discover, JCB, and UnionPay (16 to 19) numbers, plain or in space- or dash-separated groups, and a grouped number broken once across lines at a group boundary; checked with Luhn | Maestro and other networks; a 17- to 19-digit number written in groups, which is reported as its first 16 digits, since a short trailing group can't be told apart from a CVV; a number broken inside a group or more than once, since a column of short numbers would otherwise read as a card; UnionPay cards issued without a Luhn digit score 50 |
| Bitcoin private key (WIF) | Direct credential | High | Wallet Import Format keys (51 or 52 Base58 characters starting with `5`, `K`, or `L`), checked with Base58Check | Raw hex private keys; other coins' formats |
| Password-shaped value | Likely credential | Low | A quoted assigned value, or any parsed key/value pair, that looks like a password a person made up (password shape, minimum score 2), under any name, e.g. `safe_bet: "myUnencryptedPWHERE"`. A fallback: it skips values another rule already reported | Made-up passwords in a regular naming style (`myFirstPassword` reads as camelCase), all-lowercase ones (`summer2024`), and plain words; see [Password shape](#password-shape) |
| Slack token | Direct credential | High | `xoxb-`, `xoxp-`, `xoxa-`, `xoxo-`, `xoxs-`, or `xoxr-` followed by a numeric id and the rest of the token | App-level (`xapp-`) and config (`xoxe-`) tokens; placeholder-style values with no numeric id (`xoxb-your-token`) are skipped on purpose |
| Slack webhook URL | Direct credential | High | `https://hooks.slack.com/services/T…/B…/…` | Workflow and trigger webhook URLs |
| Stripe live secret key | Direct credential | High | `sk_live_` followed by 24 or more letters or digits | Test-mode keys (`sk_test_`), which only reach test data |
| Stripe live restricted key | Direct credential | High | `rk_live_` followed by 24 or more letters or digits | Same as above |
| SendGrid API key | Direct credential | High | `SG.` followed by a 22-character and a 43-character part | |
| Google API key | Direct credential | High | `AIza` followed by 35 characters | OAuth client secrets and access tokens (`ya29.`) |
| OpenAI API key | Direct credential | High | `sk-proj-`, `sk-svcacct-`, and `sk-admin-` keys, and legacy `sk-` keys with the `T3BlbkFJ` marker | Legacy keys without the marker |
| Anthropic API key | Direct credential | High | `sk-ant-api…-` and `sk-ant-admin…-` keys | |
| GitHub fine-grained token | Direct credential | High | `github_pat_` followed by a 22-character and a 59-character part | No checksum check: GitHub doesn't document one for this format |
| AWS secret access key | Direct credential | High | 40 base64 characters assigned to a name like `aws_secret_access_key`, `secretAccessKey`, or `secret_key` | A secret key under any other name. Without the name, 40 random characters can't be told from other values |
| Sentry DSN | Direct credential | Low | The 32-character key in a `https://…@….sentry.io/…` DSN. Low, since browser apps ship it publicly | Self-hosted Sentry hosts |
| Credentials in a URL | Direct credential | High | `scheme://user:password@` in any URL (databases, Redis, git over HTTPS), up to the `@`. Values starting with `$`, `%`, `{`, or `<` are treated as templates and skipped | Passwords that contain a `/` or `@` that isn't percent-encoded |
| Basic auth header | Direct credential | High | The base64 value after `Authorization: Basic` (or `"Authorization": "Basic …"`) | Basic credentials passed another way (`curl -u`) |
| Bearer token in a header | Likely credential | Medium | A value after `Authorization: Bearer` with at least 3.0 bits of entropy per character. Variables (`Bearer $TOKEN`) are skipped | Tokens in other headers (`X-Api-Key`) |
| JSON Web Token | Direct credential | Medium | Three base64url parts, the first two starting with `eyJ` (base64 of `{"`) | Unsigned or encrypted (JWE) tokens; whether the token has expired |
| Password hash | Direct credential | Medium | bcrypt (`$2b$…`), argon2 (`$argon2id$…`), and SHA-crypt (`$5$`, `$6$`) hashes, which can be cracked offline | Unsalted hex digests (MD5, SHA-1), which look like any other hex value |
| Password in a SQL statement | Direct credential | High | The quoted value after `PASSWORD` or `IDENTIFIED BY` (`CREATE ROLE`, `ALTER USER`, MySQL `CREATE USER`), 3 characters or more | Passwords passed through variables or bind parameters |
| Password in a connection string | Direct credential | High | `Password=` or `Pwd=` in a `Server=…;`, `Data Source=…;`, or `Host=…;` connection string | Connection strings that don't start with a server, data source, or host field |
| Azure account or shared access key | Direct credential | High | `AccountKey=` (88 base64 characters) or `SharedAccessKey=` (44) in an Azure connection string | SAS tokens (`sig=` in a URL) |
| JSON Web Key with private material | Direct credential | High | A JWK object with a `kty` and a private (`d`) or symmetric (`k`) member, in either order | JWKs split across nested objects or escaped inside a string |
| PuTTY private key | Direct credential | High | A `PuTTY-User-Key-File-2:` or `-3:` file, through its `Private-MAC:` line | |
| Private key without PEM armor | Direct credential | High | Base64 RSA (PKCS#1 and PKCS#8), EC (P-256, P-384), and Ed25519 keys with the PEM header removed, after `=`, `:`, a quote, or a space | Keys on a line of their own with nothing before them (a PEM block's body is skipped this way on purpose); other curves |
| Keystore file in base64 | Direct credential | Medium | A base64 PKCS#12 (`.p12`/`.pfx`) or Java keystore (JKS). Medium, since a keystore usually has a password | Binary keystore files, which aren't text |
| Kubernetes Secret with inline data | Direct credential | High | A `kind: Secret` manifest's `data:` or `stringData:` entries, with `kind` before or after them. Templated values (`{{ … }}`, `${…}`) and empty values are skipped | Secrets in JSON; it doesn't decode the base64 values to check what's inside. The finding covers the manifest, so a placeholder word anywhere in it (such as `test` in its name) scores the whole finding as an example |
| Registry auth (base64 user and password) | Direct credential | High | `_auth=` in `.npmrc` and `"auth": "…"` in Docker's `config.json`, 12 or more base64 characters | `.npmrc` lines starting with `//` are read as comments, so those findings score as likely examples |
| .netrc password | Direct credential | High | The value after `password` in a `machine … login … password …` or `default …` entry | Entries whose fields are in another order |
| Session cookie | Likely credential | Medium | A `Cookie:` or `Set-Cookie:` value whose name contains `sess`, `sid`, `auth`, `token`, or `jwt`, with at least 3.0 bits of entropy per character | Session cookies under other names |
| Pre-signed storage URL | Direct credential | Medium | An S3 or GCS URL with an `X-Amz-Signature` or `X-Goog-Signature` | Whether the URL has expired; Azure SAS URLs |

## Scores

- **Confidence (0–100):** how sure the engine is that this is a secret of the rule's kind.
  - Direct credentials: 95, or 99 when the checksum passes and 50 when it fails.
  - Likely credentials: 50–90, rising with how random the value is for its length: its entropy compared with the most a value that long can have (log2 of its length, when every character differs). A short value with no repeated characters scores as high as a long random one. With a password shape setting, 35–80, rising with the shape score.
  - With a value classifier: a credential score above the rule's confidence raises it halfway toward that score, up to 95; a score below the setting's minimum lowers it to 30.
  - Unsafe handling: 70, or 30 when it's commented out.
- **Placeholder vs. real (0–100, higher = more likely an example):** 95 when a placeholder vs. real rule matches inside the value. 70 when any other example signal is present: very little randomness (under 2 bits per character), a failed checksum, or the value sitting in a comment. Otherwise 5. There is no score for unsafe handling, which has no value.

Every match also reports `inComment` and `checksumValid` (absent when the rule has no checksum), and the scan result reports the `format` the text was read as.

## Checksums

Some formats carry a checksum, so a match can be checked offline, with no network call: a real value passes, and a made-up one (an example, a test value, random text) almost always fails.

A rule picks a checksum `algorithm` in its `checksum` field:

| `algorithm` | Other fields | Used for |
|---|---|---|
| `crc32` | `encoding`, `prefixLength`, `length` (below) | Tokens that end in a CRC32 of the rest: GitHub, npm, GitLab, and in-house formats |
| `luhn` | none | The mod-10 check digit on payment card numbers. Whitespace (including a line break) and dashes between digit groups are ignored |
| `base58check` | none | Base58 with a 4-byte double-SHA-256 checksum, as in Bitcoin private keys (WIF) |

A `crc32` token is read as `prefix + covered part + checksum`:

```json
"checksum": { "algorithm": "crc32", "encoding": "base62", "prefixLength": 4, "length": 6 }
```

| Field | Values | Meaning |
|---|---|---|
| `encoding` | `base62` (digits `0-9A-Za-z`), `base36` (`0-9a-z`, either case), `hex` (either case) | How the value is written |
| `prefixLength` | 0 or more | Characters at the start the checksum doesn't cover, such as `ghp_` |
| `length` | 6–16 for base62, 7–16 for base36, 8–16 for hex | Characters at the end holding the checksum, zero-padded |

**Seeded setups:** the built-in rules carry the common ones, so a rule author can copy them:

| Built-in rule | Setup | Source |
|---|---|---|
| GitHub token (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`) | `crc32`, `base62`, prefix 4, length 6 | [GitHub](https://github.blog/engineering/behind-githubs-new-authentication-token-formats/) |
| npm token (`npm_`) | `crc32`, `base62`, prefix 4, length 6 | [npm uses GitHub's format](https://github.blog/security/announcing-npms-new-access-token-format) |
| GitLab personal access token (routable `glpat-`) | `crc32`, `base36`, prefix 0 (the CRC covers the whole token before it), length 7 | [GitLab's routable tokens design](https://handbook.gitlab.com/handbook/engineering/architecture/design-documents/cells/routable_tokens/) |
| Payment card number | `luhn` | ISO/IEC 7812 |
| Bitcoin private key (WIF) | `base58check` | [Bitcoin wiki: Wallet Import Format](https://en.bitcoin.it/wiki/Wallet_import_format) |

**Custom setups:** a rule for an in-house token format describes its own, e.g. `acme_` followed by the covered part and an 8-digit hex CRC32 is `{ "algorithm": "crc32", "encoding": "hex", "prefixLength": 5, "length": 8 }`. A length too short to hold the full value, or longer than 16, is a rule error on the `checksum` field.

A failed checksum lowers confidence and raises the placeholder score; it never drops the finding. GitHub, npm, and GitLab haven't published test tokens, so those setups follow their descriptions and existing open-source validators. If a setup were ever subtly wrong, real tokens would still be reported, just at lower confidence. The same holds for a mistaken custom setup.

**Not seeded:** Microsoft/Azure identifiable keys carry a checksum, but its algorithm couldn't be confirmed. Ethereum addresses (EIP-55) and IBANs (mod-97) have checksums, but they're public identifiers, not secrets, so flagging them would only add noise.

## Password shape

Key names catch `password = …`, but a password can sit under any name. A rule's `passwordShape` setting (`{ "minScore": 2 }`) judges the value alone, and keeps it only when it looks like a password a person made up:

| Signal | Points |
|---|---|
| Mixes symbols (`!@#$%^&*?~+=`) into letters | 2 |
| Swaps letters for look-alike digits or symbols (`p4ss`, `s3cret`, `p@ss`) | 2 |
| Contains a word common in passwords (`pw`, `pass`, `admin`, `qwerty`, `1234`, ...) | 2 |
| Ends in a short number (`Summer2024`) | 1 |
| Uses irregular capitals (a run of 3+ capitals at the end, or alternating case) | 1 |
| Mixes upper- and lowercase letters with digits | 1 |

A value equal to one of about 60 very common passwords that include a digit or symbol (`password1`, `p@ssw0rd`, `hunter2`) scores the maximum, 10. Plain words such as `password` or `admin` are left out of that list: as config values they are usually names (a role, a key, a resource kind), not passwords.

Values never count when they are clearly something else:
- **Lengths:** under 8 characters (6 for the common list), over 64, or containing whitespace.
- **Not secrets:** URLs, paths, emails, numbers, dates, versions, IP addresses, UUIDs, hex strings, hex colors (`#FF5733`), and template references (`${…}`, `{{…}}`).
- **Regular names:** `snake_case`, `kebab-case`, `dotted.names`, `ALL_CAPS`, `camelCase`, and `PascalCase`.
- **Machine-made tokens:** 20+ characters with at least 4 bits of entropy per character. Format and key-name rules are for those.

A likely-credential rule with a password shape also checks every parsed key/value pair, whatever its key, unless its `keyNames` narrows it. With no key names it is a fallback: it doesn't report a value that overlaps another rule's finding, so a password under `password:` is reported once, by the assignment rule.

Its "why flagged" note lists the signals that fired and never quotes the value. The trade-off is reach versus noise: the exclusions keep ordinary config values out, but a made-up password that happens to look like a regular name, or is all lowercase, is missed.

The samples under `tests/` pin this down, and engine tests scan them: `made-up-passwords.yaml`, `.json`, and `.env` must report exactly their made-up passwords, once each; `password-lookalikes.yaml` and `clean-lookalikes.yaml` must report nothing from this rule; and the other samples add no password-shape findings.

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

- **Regex plus entropy, checksums, and format parsing first, machine learning as an optional extra:** the built-in rules are predictable, explainable, and fast, so every finding can say exactly why it was flagged. Checksums and format parsing reduce false positives and misses without leaving the machine. The cost is remaining false positives on documentation and fixtures (softened by the placeholder score) and misses on secrets with no known format and low randomness. Models target both, but only when a rule set includes them: model rules' verdicts sit beside the other rules' scores, and a value classifier only moves a match's confidence, never drops it.
- **No live verification:** asking a provider whether a secret works (as TruffleHog does) is the strongest signal, but it sends the secret off the machine, which this design rules out.
- **Narrow formats over broad ones:** the direct-credential rules match exact, well-known formats, so they rarely fire by mistake. The assignment rule casts the wider net and is ranked lower.
- **Signals only in explanations:** "why flagged" notes and log events never quote the input, so they're safe to store and log. The cost is that an explanation can't say *which* key name triggered it.
