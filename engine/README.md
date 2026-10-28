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
| npm token | Direct credential | High | `npm_` followed by 36 letters or digits, checked with the same CRC32 checksum as GitHub | Legacy npm tokens (UUIDs), which npm retired |
| GitLab personal access token | Direct credential | High | Routable `glpat-` tokens (37 to 310 characters after the prefix), checked with GitLab's base36 CRC32 checksum | Other GitLab token types (`gldt-`, `glrt-`, ...) |
| GitLab personal access token (legacy format) | Direct credential | High | `glpat-` followed by exactly 20 characters, the format before routable tokens; it has no checksum | Same as above |
| Payment card number | Direct credential | High | Visa (13 or 16 to 19 digits), Mastercard (16), Amex (15), Diners Club (14), and Discover, JCB, and UnionPay (16 to 19) numbers, plain or in space- or dash-separated groups, and a grouped number broken once across lines at a group boundary; checked with Luhn | Maestro and other networks; a 17- to 19-digit number written in groups, which is reported as its first 16 digits, since a short trailing group can't be told apart from a CVV; a number broken inside a group or more than once, since a column of short numbers would otherwise read as a card; UnionPay cards issued without a Luhn digit score 50 |
| Bitcoin private key (WIF) | Direct credential | High | Wallet Import Format keys (51 or 52 Base58 characters starting with `5`, `K`, or `L`), checked with Base58Check | Raw hex private keys; other coins' formats |
| Password-shaped value | Likely credential | Low | A quoted assigned value, or any parsed key/value pair, that looks like a password a person made up (password shape, minimum score 2), under any name, e.g. `safe_bet: "myUnencryptedPWHERE"`. A fallback: it skips values another rule already reported | Made-up passwords in a regular naming style (`myFirstPassword` reads as camelCase), all-lowercase ones (`summer2024`), and plain words; see [Password shape](#password-shape) |

## Scores

- **Confidence (0–100):** how sure the engine is that this is a secret of the rule's kind.
  - Direct credentials: 95, or 99 when the checksum passes and 50 when it fails.
  - Likely credentials: 50–90, rising with entropy above the rule's threshold. With a password shape setting, 35–80, rising with the shape score.
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

- **Regex plus entropy, checksums, and format parsing, not machine learning:** predictable, explainable, and fast, so every finding can say exactly why it was flagged. Checksums and format parsing reduce false positives and misses without leaving the machine. The cost is remaining false positives on documentation and fixtures (softened by the placeholder score) and misses on secrets with no known format and low randomness.
- **No live verification:** asking a provider whether a secret works (as TruffleHog does) is the strongest signal, but it sends the secret off the machine, which this design rules out.
- **Narrow formats over broad ones:** the direct-credential rules match exact, well-known formats, so they rarely fire by mistake. The assignment rule casts the wider net and is ranked lower.
- **Signals only in explanations:** "why flagged" notes and log events never quote the input, so they're safe to store and log. The cost is that an explanation can't say *which* key name triggered it.
