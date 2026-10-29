# Rule authoring guide

Every built-in rule is ordinary data built from the mechanisms below, so anything the built-in set catches, you can catch with a rule of your own: a new provider's token, an in-house format, or a narrower version of a built-in rule. Each section says what a mechanism does, when to use it, and why it exists.

## Overview

A rule is a JSON `definition`. Every field is optional while drafting; unknown fields are rejected so a typo fails loudly instead of being ignored.

| Field | Used by | What it does |
|---|---|---|
| `name` | all | Shown on findings. Unique within a rule set, ignoring case |
| `enabled` | all | `false` keeps the rule in the version but skips it. Default `true` |
| `detectionType` | all | What a match means and how it is scored (see `detection-types`) |
| `severity` | rule types that create findings | `high`, `medium`, or `low` |
| `pattern` | all except model rules | A Rust regex (see `patterns`) |
| `prefix` | any pattern rule | The public start of the format, shown as the redacted preview |
| `keyNames` | any pattern rule | Names the value must be assigned to (see `key-names`) |
| `minEntropy` | any pattern rule except `unsafe_handling` | Minimum randomness of the value (see `entropy`) |
| `checksum` | any pattern rule | How to verify the value offline (see `checksums`) |
| `passwordShape` | any pattern rule; built for `likely_credential` | Only count values that look like a password a person made up (see `password-shape`) |
| `remediation` | rule types that create findings | What to do about a finding |
| `model`, `threshold` | `model_assessment`, `model_detection` | The model to run and its cut-off (see `models`) |
| `valueClassifier` | any pattern rule; built for `likely_credential` | A model that says whether each matched value is a credential, a non-secret string, or a placeholder, and moves confidence to match (see `models`) |

How a scan uses a rule, in order:

1. The rule is checked. A rule that fails becomes a `rule_error` finding and the other rules still run.
2. The text is read as JSON, YAML, `.env`, or plain text, which finds comments and key/value pairs.
3. The pattern runs. The `value` group (or the whole match) is the candidate. `keyNames`, `minEntropy`, and `passwordShape` can each drop it.
4. `likely_credential` rules also check parsed key/value pairs.
5. `checksum` marks each candidate as valid or not; it never drops one.
6. Placeholder rules mark candidates that contain a known fake value.
7. Candidates are sorted, and at most 200 are kept.
8. Rules with a `valueClassifier` classify each kept value.
9. Candidates are scored and overlaps are grouped.

Scan text is never stored, and no finding contains the matched value. Only positions, scores, and the `prefix` are returned.

## Workflow

1. `create_rule` with a definition. It is stored as a draft and not validated, so you can build it up over several `update_rule` calls.
2. `check_rules` with the rule ids you plan to save together. It runs the checks that saving a version runs (required fields, ranges, pattern compilation, duplicate names) and saves nothing. Error spans point at the exact spot in the pattern.
3. `create_rule_set_version` with the rule ids. Each rule's current definition is snapshotted, so later edits never change a saved version. To build on the built-in rules, start a set with `create_rule_set` copying the built-in version, then save a new version that adds your rule ids.
4. `create_scan_session` on that version, then test it: `run_test_suite` with generated data and files of your own (see `testing`), or `run_scan` with known positives and known negatives. Read each finding's `whyFlagged`, `confidence`, and `placeholderScore` to see which mechanism fired.
5. Adjust and save another version. Versions are numbered within their set and can be archived, never edited.

Why test with negatives: most rule mistakes are false positives on ordinary text (IDs, hashes, URLs, prose). Scan the kind of file the rule will meet, not only the secret.

## Testing

Two tools test a rule set version against labeled data and report expected versus actual. Both are deterministic: the engine decides every result, and nothing in them is a model's opinion.

`generate_test_data` builds cases for each enabled pattern rule from the rule's own pattern, and checks each against the rule before keeping it:

| Kind | What it is | Expect |
|---|---|---|
| `positive` | A match that passes the rule's key names, entropy, and password shape, with a valid checksum when the rule has one | `secret` |
| `assignment` | For a `likely_credential` rule with `keyNames`: a value under one of the names in `.env`, YAML, and JSON files | `secret` |
| `broken_checksum` | The positive with one covered character changed. A second copy sits under `APP_TOKEN=` in the `.env` file, where rules that go by names can match it too | `example` |
| `placeholder` | The positive with a value from the set's placeholder rules inside it | `example` |
| `wrong_prefix`, `one_short` | The positive with a prefix character changed, or one character short | `not_secret` for that rule |
| `low_entropy` | The value with too little randomness for `minEntropy` | `example` |
| `neutral_key` | An assignment value under a name that isn't a key name | `not_secret` for that rule |
| `lookalike` | Ordinary values in `lookalikes.yaml`: a commit SHA, UUIDs, a digest, a URL, a path, a reference such as `${DB_PASSWORD}`, two of them under secret-sounding names | `not_secret` for every rule |

The same version and seed always give the same data, so a run can regenerate it instead of storing it. Every value is made up. `skipped` lists the cases that couldn't be made and why, which can point at a rule problem: a pattern that still matches with its prefix changed doesn't require the prefix, and a format no placeholder fits inside can't have its examples marked by a placeholder rule.

`run_test_suite` scans documents in a scan session and compares each case with the findings that overlap it. Pass `generated` (a seed and optional rule ids) to scan the generated data without sending its text, `documents` to scan realistic files of your own, or both. In your own documents, label each case by its exact `value` (and `occurrence`, from 1, when it repeats), with `expect` and optionally the rule (`ruleId` or `ruleName`). Each document is saved as a scan in the session, so its text is never stored and the session's suppressions apply; the labels exist only in the report.

How each case is judged:

- `secret`: `caught` when its rule (any rule, if none is named) reports it, `caught_as_example` when every such finding has `placeholderScore` 70 or more, otherwise `missed`.
- `example`: `not_reported`, `flagged_as_example` when every overlapping finding has `placeholderScore` 70 or more, or `scored_as_real` when any finding, from any rule, scores it as real.
- `not_secret`: `ignored`, or `false_alarm` when its rule (any rule, if none is named) reports it.

The counts are grouped the same way. `summary` and each entry in `rules` have `secrets` (`caught` + `caughtAsExample` + `missed`), `examples` (`flaggedAsExample` + `notReported` + `scoredAsReal`), and `notSecrets` (`ignored` + `falseAlarms`), each with its own `cases`, and the three add up to `cases`. Only secrets can be caught or missed: a rule with 5 cases and 2 caught has missed nothing if its other 3 are examples it marked and lookalikes it ignored. A rule's groups hold only the cases labeled for it; its findings on `not_secret` cases labeled for no rule, such as the lookalikes, are its `unassignedFalseAlarms`.

Findings on no case are listed as unlabeled. `diagnostics` name rule problems the run showed:

| Code | Meaning |
|---|---|
| `parsed_pair_only` | A `likely_credential` rule with `keyNames` reported values its pattern didn't match, because key names also check every parsed pair under those names (see `key-names`) |
| `no_value_group` | A rule without a `value` group scored a match under 80 because its span holds syntax as well as the secret, which dilutes randomness (see `pitfalls`) |
| `example_scored_as_real` | An example was scored as real, often by an overlapping rule: a failed checksum or a placeholder only marks the findings of the rule that checks it |
| `classifier_only_lowered` | A value classifier rated reported values as not credentials. It lowers confidence to 30 and never drops a finding |
| `model_unavailable` | A rule names a model hash this server hasn't loaded, usually after the model was retrained. The message lists the loaded models' hashes |
| `prefix_not_enforced` | The rule still finds the value with its `prefix` changed |
| `suppressed`, `truncated` | A scan left matches out, so cases may read as missed |

Why both kinds of data: generated cases cover each rule's mechanisms exhaustively (the checksum, the prefix, the length, the placeholders), but only a file someone would really write, such as a README, a CI config, a Python settings module, or a CSV export, shows how rules meet real context and each other. Generate first, then add realistic files with the same values in them.

## Detection types

| Type | Creates findings | Needs | Use it for |
|---|---|---|---|
| `direct_credential` | yes | `pattern`, `severity` | A value whose format alone says it is a secret: a provider prefix, a fixed structure, a checksum, or a syntax that only holds credentials (`Authorization: Basic …`, `scheme://user:pass@`) |
| `likely_credential` | yes | `pattern`, `severity` | A value with no known format that is probably a secret because of its name, its randomness, or its shape |
| `unsafe_handling` | yes | `pattern`, `severity` | Code that mishandles a secret, such as logging it. There is no value, so entropy and placeholder scores don't apply |
| `placeholder_vs_real` | no | `pattern` | Known fake values. A match inside another finding marks that finding as a likely example |
| `model_assessment` | no | `model`, `threshold` | A model's opinion of whether each finding's value is real or an example |
| `model_detection` | yes | `model`, `threshold`, `severity` | Spans a model flags as secrets, including formats no pattern describes |

Why the split matters: the type decides which rules run where (likely credentials also check parsed key/value pairs, unsafe handling has no value to score) and which kinds of evidence a match can have. It doesn't set the confidence: every match starts at 50 and its own evidence moves it, weighed the same for every type (see `scoring`). Pick `direct_credential` when a match is a secret almost every time; otherwise pick `likely_credential` and let entropy or shape do the filtering.

Choosing severity: `high` for anything that grants access as written (keys, tokens, passwords, private keys). `medium` for credentials that expire or need something else to use (JWTs, pre-signed URLs, password hashes, keystores with a password). `low` for values that are public by design or weak signals (Sentry DSNs, password-shaped values under ordinary names).

## Patterns

`pattern` is a [Rust `regex`](https://docs.rs/regex/latest/regex/#syntax) pattern. It runs in linear time, so no pattern can hang a scan, but that also means there are **no lookarounds and no backreferences**.

Named groups:
- `value`: the secret itself. The finding's location, entropy, checksum, password shape, and placeholder check all use this group. Without it, the whole match is the value.
- `key`: the name the value is assigned to, checked against `keyNames`; without it, `keyNames` is checked against the whole match. In a rule with no `value` group (unsafe handling), `key` marks the secret name the match mentions, and confidence weighs where it sits (see `scoring`).

Why `value` matters: it lets a pattern require context without reporting the context. Since Rust regex has no lookbehind, put the required context outside the group: `(?i)\bauthorization["']?\s*[:=]\s*["']?basic\s+(?P<value>[A-Za-z0-9+/]{8,}={0,2})` reports only the base64 credential, not the header name.

Flags go inline at the start: `(?i)` ignores case, `(?m)` makes `^` and `$` match at line breaks, `(?s)` lets `.` match a line break. Without `(?s)`, use `[\s\S]` to cross lines.

Rules:
- A group name can appear only once in a pattern. When two alternatives need the same `value` group, put the alternation outside it: `(?:A|B)(?P<value>…)`, or inside it: `(?P<value>A…|B…)`.
- `\b` is a boundary between a word character (`[A-Za-z0-9_]`) and anything else. It doesn't work next to `-`, `/`, `+`, `.`, or `=`. For formats that end in those characters, end with `(?:[^A-Za-z0-9_-]|$)` after the `value` group, or leave the end open when the length is fixed.
- A pattern that can match empty text is a warning (`matches_empty`), and an empty `value` is skipped.
- A pattern too large to compile (over 1 MB compiled) is a `too_large` error. Large alternations of literal words are the usual cause.

`prefix` is the public start of the format, such as `ghp_` or `AKIA`. Findings show it as the redacted preview (`ghp_…`). It is never taken from the match, so set it only when every match starts with it, and only to text that is safe to show.

`remediation` is the action shown with each finding. Name the console page or command that rotates the secret, and say where the replacement should live. Why: the person reading a finding usually needs to act on it, not just know about it.

## Key names

`keyNames` is a list of names. A candidate counts only if its `key` group (or the whole match) contains one of them as a substring, ignoring case. They are lowercased when the rule is checked.

For `likely_credential` rules, key names also turn on parsed key/value checking: every key/value pair read from JSON, YAML, or `.env` whose key contains a key name is a candidate too, even when the pattern alone misses it (a quoted value with `;` in it, or a JSON key and value on separate lines). A parsed value needs at least 8 characters (6 with a password shape), and values starting with `$`, `{`, or `(` are skipped as references such as `${DB_PASSWORD}`. A value found both ways is reported once.

When to use it: values with no format of their own, where the name is the evidence (`DB_PASSWORD=…`). Why substring matching: it catches `db_password`, `POSTGRES_PASSWORD`, and `passwordHash` with one name. The trade-off is reach: a short name such as `pass` also matches `passthrough`. Use a separator to narrow it (`_pass` matches `DB_PASS` but not `bypass`), and avoid names whose values are usually paths or URLs (`private_key_path`, `credentials_file`), since entropy doesn't tell a path from a secret.

## Entropy

`minEntropy` drops a candidate whose value has fewer bits of Shannon entropy per character than this, from 0 to 8. It applies to every pattern rule type except `unsafe_handling`, which has no value.

Typical values, in bits per character: an English word about 2.5–3, a made-up password about 3–3.5, hex at most 4, base64 tokens 4.5–6. A value can't score above log2 of its length, so short values score low whatever they are. That is why confidence uses a different measure: it compares a value's entropy with that ceiling, so a 12-character value with no repeated characters counts as just as random as a long random token, while `minEntropy` stays an absolute floor.

When to use it: likely-credential rules that would otherwise match ordinary settings. The built-in assignment rule uses 3.0, which keeps `password: changeme` out and keeps `password: q8Z!fP2xL7mR` in. Why it is a threshold and not a format: it is the one signal that works on secrets with no format at all. Its limit: it can't tell a random secret from a random identifier (a git SHA, a UUID), so pair it with key names, context, or a `valueClassifier`.

Separately, a value under 2 bits per character counts as an example signal in the placeholder score, whatever the rule's threshold. A value under 8 characters can't always reach 2 bits (3 characters top out at 1.6), so it also has to be under two thirds of what its length allows: `417` is not an example signal, `000` is.

## Checksums

Some formats carry a checksum, so a match can be checked offline: a real value passes, and a made-up one almost always fails. `checksum` picks an `algorithm`:

| `algorithm` | Other fields | Built-in users |
|---|---|---|
| `crc32` | `encoding`, `prefixLength`, `length` | GitHub and npm tokens (`base62`, prefix 4, length 6); GitLab routable tokens (`base36`, prefix 0, length 7) |
| `luhn` | none | Payment card numbers. Spaces, dashes, and line breaks between digit groups are ignored |
| `base58check` | none | Bitcoin private keys (WIF) |
| `bech32` | none | None built in; for age secret keys (`AGE-SECRET-KEY-1`) and Nostr private keys (`nsec1`) |
| `bech32m` | none | None built in; for Taproot (`bc1p`) addresses and other BIP-350 strings |
| `bip39` | none | None built in; for 12- to 24-word seed phrases from the English list |
| `marvin32` | `seed` | None built in; for Microsoft identifiable keys (Azure Storage `Default0`, Cosmos DB `MastRW00`, Functions `Functi00`, Cache for Redis `Access00`) |
| `verhoeff` | none | None built in; for Aadhaar numbers. Spaces and dashes between digit groups are ignored |
| `mod11` | none | None built in; for ISBN-10 and UK NHS numbers. Spaces and dashes are ignored |
| `mod97` | none | None built in; for IBANs. Spaces are ignored |

A `crc32` value is read as `prefix + covered part + checksum`. The checksum is the CRC32 of the covered part, written in `encoding` (`base62` is `0-9A-Za-z`; `base36` and `hex` match either case) and zero-padded to `length` characters. `prefixLength` is how many characters at the start are not covered. For example, `acme_` followed by the covered part and an 8-digit hex CRC32 is `{"algorithm": "crc32", "encoding": "hex", "prefixLength": 5, "length": 8}`. `length` must be at least 6 for base62, 7 for base36, or 8 for hex (enough to hold a full CRC32), and at most 16.

The others need no setup beyond `marvin32`'s seed:

- `bech32` and `bech32m` read `hrp` + `1` + data + a 6-character checksum (BIP-173 and BIP-350), all upper or all lower case. The checksum covers the `hrp` too, so put the whole string, prefix included, in the `value` group.
- `bip39` reads 12, 15, 18, 21, or 24 whitespace-separated words from the English list; the last word carries a SHA-256 checksum of the rest. Only 4 to 8 bits are checksum, so 1 in 16 random 12-word phrases from the list passes: let the pattern require the word count, and expect the list itself to do most of the filtering.
- `marvin32` reads base64 (standard or URL-safe, padded or not) whose last 4 bytes are the Marvin32 hash of the bytes before them. `seed` is the key kind's 8-character name; each Azure service uses its own, so a rule covers one key kind. The service's 4-character signature (such as `+ASt` or `AzCa`) isn't checked by the checksum: write it into the pattern.
- `verhoeff` and `mod11` check a final check digit; `mod11` weights the digits 1, 2, 3, ... from the right and reads a final `X` as 10.
- `mod97` is ISO 7064 MOD 97-10 as IBANs use it: the country code and check digits move to the end, letters count as 10 to 35, and the result must be 1 mod 97.

What it changes: a valid checksum is the strongest evidence a match can have (a match with no other evidence goes from 50 to 97), and the "why flagged" note says so. A failed one is equally strong evidence against (50 to 3) and counts as an example signal. It never drops a finding. Why: a wrong checksum setup, or a provider changing its format, must not hide real secrets. The checksum runs on the `value` group, so make sure that group holds exactly the token.

When to use it: whenever a provider documents one. It is the strongest offline signal there is.

## Password shape

`passwordShape: {"minScore": n}` counts a value only if it looks like a password a person made up, scoring at least `n` points from 1 to 10. Signals include look-alike substitutions (`p4ss`), common password words, a trailing short number (`Summer2024`), irregular capitals, and mixed letters and digits. About 60 very common passwords score the maximum.

Values never count when they are clearly something else: under 8 characters (6 for the common list) or over 64, whitespace, URLs, paths, emails, numbers, dates, versions, IPs, UUIDs, hex, colors, template references, regular naming styles (`snake_case`, `camelCase`, `ALL_CAPS`, ...), and machine-made tokens (20+ characters with 4+ bits of entropy).

On any pattern rule it filters the pattern's matches. Its score also counts as evidence in place of randomness, since a password a person made up isn't random: a score of 3 is even, and each point above it raises confidence. On a `likely_credential` rule it also checks parsed key/value pairs: with no `keyNames`, a password-shape rule checks every parsed key/value pair, whatever its key, and acts as a fallback: it doesn't report a value another rule already found. With `keyNames`, it checks only pairs under those names.

When to use it: human-chosen passwords under names that don't say "password" (`safe_bet: "Tr0ub4dor&3"`), which neither entropy nor key names catch. Why a fallback: it is a weak signal, so it fills gaps instead of doubling findings. The built-in rule uses `minScore` 2 at low severity.

## Placeholders

A `placeholder_vs_real` rule's pattern runs over the whole text, but its matches only matter when one falls entirely inside another rule's finding. That finding then scores 95 on `placeholderScore` (likely an example), and its "why flagged" note says it contains a known placeholder value. These rules never create findings, and severity and remediation don't apply.

When to use it: the fake values your docs and fixtures use (`your_key_here`, `changeme`, `EXAMPLE`). Why containment: a placeholder word elsewhere on the line says nothing about the secret, but one inside the value does. Keep entries specific. A common word like `password` would mark any finding whose span contains a `password:` key, such as a whole Kubernetes Secret manifest, so the built-in rule uses `:password@` (a URL password of literally `password`) instead.

The other example signals, which score 70, need no rule: very little randomness (see `entropy`), a failed checksum, or the value sitting in a comment.

## Models

Models add judgment to pattern rules in two ways. Both name a model by `{"id": "readable name", "sha256": "64 hex characters"}`; the hash is what counts, so a rule set version names the exact model it scanned with. `list_models` shows the models this server has loaded and what each can be used for.

**`valueClassifier` on a pattern rule** (`{"model": {…}, "minScore": 0–100}`): a model reads each value the rule matched, from the value's own line, and says whether it is a `credential`, a `non_secret` string (a hash, digest, ID, URL, or encoded data), or a `placeholder`. It never drops a finding:

- A credential score below `minScore` lowers confidence to 30, and "why flagged" says what the value looks like instead.
- A credential score above the rule's own confidence raises it halfway toward that score, up to 95, so a model alone is never surer than a known format.
- A `placeholder` verdict counts as an example signal in the placeholder score.
- The finding records the scores as `valueClass`.

When to use it: rules that match by randomness or password shape, which can't tell a password from a git SHA or UUID under a secret-sounding name. It also works on a `model_detection` rule, where a second model's agreement cuts the detector's false alarms: spans it doesn't rate as credentials drop to confidence 30. Fixed formats (`AKIA…`, `ghp_…`) don't need it. This server loads the `value-classifier` model at startup and seeds it, at `minScore` 50, on the built-in `likely_credential` rules of a new database. It judges the value and its name, not the file, so it doesn't decide whether text is a test or documentation.

**Model rules** take `model` and `threshold` (0–100) instead of a pattern:

- `model_assessment` rates each finding's value as `likely_real` or `likely_example`, adds a `modelAssessments` entry and a "why flagged" line, and never changes the finding's scores.
- `model_detection` reads the whole text and turns runs of bytes scoring at or above the threshold into findings, which catches secrets no pattern describes. It is the slowest rule type.

A model this server hasn't loaded, or one whose shape doesn't fit (`list_models` says which uses each model fits), makes the rule a `rule_error` (field `model` or `value_classifier`, code `model_unavailable`) and the scan is partial. You can still draft, check, and version such rules here. Retraining a model changes its hash, so versions that name the old hash report it as unavailable until a new version names the new one.

## Scoring

- **Confidence (0–100):** how likely this match is what its rule describes, from the evidence about this match. The rule's type doesn't set it: every match starts at 50, and each kind of evidence moves it the same amount whichever rule found it. Weights are log-odds, so a weight of 1 takes an even match to 73, 2 to 88, and 3.5 to 97; the result stays between 1 and 99.

  | Evidence | Weight |
  |---|---|
  | Checksum valid / fails | +3.5 / −3.5 |
  | Starts with the rule's `prefix` | +2 |
  | Assigned to one of the rule's `keyNames` | +1 |
  | Fixed syntax around the `value` group (a header name, not a `key` group) | +1 |
  | Randomness: entropy as a share of the most a value its length can have | −1.5 (none) to +1.5 (every character differs) |
  | Password shape score, in place of randomness | +0.35 per point above 3 |
  | No value: the secret name in `key` is code (`dbPassword`, `{token}`, `${token}`, or `$TOKEN` outside single quotes) | +1.5 |
  | No value: the secret name labels the value logged with it (`"password:", pw`, `"token=%s" % t`, `f"secret: {s}"`) | +1.5 |
  | No value: the secret name is a word in a longer message logged with another value (`"password reset for", user`) | +0.5 |
  | No value: the secret name is only a word in a quoted message | −2 |
  | No value: the match is commented out | −2.5 |

  Model detection: the model's highest score in the span. A `valueClassifier` then lowers it to 30 (credential score below `minScore`) or raises it halfway toward a higher credential score, up to 95. "Why flagged" lists each piece of evidence.
- **`valueClass`:** with a `valueClassifier`, the label (`credential`, `non_secret`, or `placeholder`) and a 0–100 score for each. Null otherwise.
- **Placeholder score (0–100, higher is more likely an example):** 95 when a placeholder rule matches inside the value, 70 with any other example signal, otherwise 5. None for unsafe handling.
- **`whyFlagged`** is built only from these signals and never quotes the input, so it is safe to show and log.

Why two scores: confidence answers "is this the kind of secret the rule describes?", and the placeholder score answers "is it a real one or an example?". A documented example key is a perfect format match and still not a leak.

## Parsing

Before matching, the text is read as JSON (starts with `{` or `[` and parses), `.env` (at least half the lines are `KEY=value`), YAML (at least half are `key: value`), or plain text. Quotes are stripped from parsed values, and all positions stay exact byte offsets into the original text.

- **Comments** (`#` and `//` lines, and trailing ` # comments` in YAML and `.env`): a finding inside one is still reported, but it counts as an example signal, and commented-out unsafe handling loses confidence (−2.5), since it doesn't run. Note that `.npmrc` lines start with `//`, so they read as comments.
- **Overlaps:** findings whose ranges overlap share an `overlapGroup`, so a token assigned to `token:` can be found by both a format rule and the assignment rule and is drawn as one highlight.
- **Limits:** text over 1 MB is rejected, and beyond 200 findings the rest are dropped and `truncated` is set. A rule that hits the cap is usually too broad.

Source code isn't parsed into a syntax tree, so code is scanned as text.

## Validation

`check_rules`, `create_rule_set_version`, and updates to a rule already in a version return errors as `{ruleId, field, code, message, span}`, where `field` is the definition field in snake case (`min_entropy`, `password_shape`, ...):

| Code | Meaning |
|---|---|
| `required` | A field this rule type needs is missing: `name`, `detectionType`, `severity` (for types that create findings), `pattern` (for pattern rules), or `model` and `threshold` (for model rules) |
| `invalid_regex` | The pattern doesn't compile. `span` is the byte range of the problem in the pattern |
| `too_large` | The pattern compiles to more than 1 MB |
| `out_of_range` | `minEntropy` outside 0–8, `passwordShape.minScore` outside 1–10, a `crc32` length too short or over 16, or `threshold` outside 0–100 |
| `invalid_format` | A model hash that isn't 64 hexadecimal characters |
| `duplicate_name` | Another rule in the set has the same name, ignoring case and surrounding space |
| `model_unavailable`, `model_failed` | Only at scan time: the model wasn't loaded, doesn't fit the rule type, or failed |

Warnings don't block saving: `matches_empty` means the pattern can match empty text. Why errors point at fields: a rule author, or a model calling these tools, can fix the exact spot without guessing.

## Recipes

How each kind of built-in rule is put together, so you can build the same kind for a new format. Read the built-in definitions with `get_rule_set_version` for the full patterns.

**A provider prefix and a fixed character set** (AWS access keys, Slack, Stripe, SendGrid, Google, OpenAI, Anthropic, GitHub fine-grained tokens): `direct_credential`, a pattern anchored on the prefix with the exact length or alphabet, and `prefix`. Why direct: a vendor prefix plus the right shape is almost never anything else. Start with `\b` and the prefix, and match the documented length exactly, so near-misses (`AKIA` plus 15 characters) don't count.

**A prefix plus a checksum** (GitHub, npm, GitLab routable tokens): the same, plus `checksum`. Why: the checksum separates real tokens from documentation examples and test strings that have the right shape.

**A checksum with no prefix** (payment cards with `luhn`, Bitcoin WIF keys with `base58check`): the pattern describes the number ranges or alphabet, and the checksum does the filtering. Why: without a prefix the shape alone matches order IDs and timestamps; the checksum makes it safe to report as direct.

**A value only its surrounding syntax identifies** (AWS secret keys by name, Basic auth headers, passwords in URLs, SQL `PASSWORD '…'`, connection-string `Password=`, `.netrc`, registry `_auth`): `direct_credential` with the syntax outside a `value` group. Why direct: the syntax only ever holds a credential, even though the value itself has no format. Skip templates in the value's first character (`[^$%{<]`), so `${PASSWORD}` and `%s` aren't reported.

**A secret-sounding name and a random value** (the built-in "Secret-looking assignment"): `likely_credential`, a pattern with `key` and `value` groups, `keyNames`, and `minEntropy` 3.0. Why likely: the name is evidence, not proof, and the entropy threshold keeps ordinary settings out. This server adds a `valueClassifier` to it, which lowers the confidence of hashes and IDs under secret-sounding names.

**Context and randomness without a name** (Bearer headers, session cookies): `likely_credential` with a `value` group and `minEntropy`, no `keyNames`. Why: the header or cookie syntax says a token is there, and entropy keeps out variables and short placeholders.

**A multi-line block** (PEM private keys, PuTTY keys, Kubernetes Secrets): match the header, then `[\s\S]*?` lazily up to the closing line, and make the closing part optional (`(?:…)?`) so a truncated block still reports its header. Use `(?m)` with `^` to anchor YAML keys to the start of a line. Why lazy: a greedy `[\s\S]*` would run on to the last closing line in the file.

**A binary structure written as base64** (private keys without PEM armor, PKCS#12 and Java keystores): the first bytes of a DER or keystore file are fixed, so their base64 is too (`MIIEowIBAAKC` for an RSA key, `/u3+7Q` for a Java keystore). Match that prefix and the base64 run after it. Require a character such as `=`, `:`, or a quote before it, so the body of a PEM block, which the PEM rule already reports, isn't reported twice. Why it works: base64 maps every 3 bytes to 4 fixed characters, so a fixed byte header always encodes the same way.

**A JSON structure** (JWKs with private members): match within one object with `\{[^{}]*?…[^{}]*\}`, and list both field orders as alternatives, since JSON doesn't fix the order.

**A password a person made up** (the built-in "Password-shaped value"): `likely_credential`, a pattern for quoted assigned values, `passwordShape` with no `keyNames`, at low severity, plus this server's `valueClassifier`. Why: it is the only mechanism that catches human passwords under ordinary names, and as a fallback it adds no duplicate findings.

**Unsafe code** (the built-in "Secret written to a log"): `unsafe_handling` with a pattern for the call and a secret-sounding name in its arguments, captured as the `key` group. Why a separate type: there is no value to score, and the fix is a code change, not a rotation. Why the `key` group: confidence then tells `log(dbPassword)` (code, 82) from `log("token refresh scheduled")` (a word in a message, 12). Without it the match has no evidence either way and stays at 50.

**Your own fake values** (the built-in "Known placeholder values"): `placeholder_vs_real` with an alternation of the exact strings your docs and fixtures use.

## Pitfalls

- **A rule that drowns its own findings.** Broad patterns (any 32 hex characters, any base64 run) match hashes, IDs, and digests. Anchor on a prefix, a name, or a syntax, and test on a clean file.
- **A finding span much wider than the secret.** Placeholder containment and entropy both use the `value` span. A span that includes keys or names can be marked as an example by a word in them. Narrow it with a `value` group when the format allows.
- **Severity that overstates the risk.** Public-by-design values (Sentry DSNs, publishable keys, identifiers such as account SIDs) are low or not worth a rule.
- **Encrypted data.** Ansible Vault files, Sealed Secrets, and SOPS files are the safe way to commit secrets; flagging them only adds noise.
- **Existing databases.** The built-in rules are seeded once, into an empty database. New built-in rules reach an existing database only through a new rule set version, so add them the same way you add your own.
