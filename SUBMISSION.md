# Submission

Use this document to guide your project walkthrough.

## Phase 1: Discovery & design

### 1. Who is the user, and what are they trying to accomplish?

**Sophisticated**: devs, engineers, IT departments, personnel knowledgeable about secrets, their handling, and their relevance. They understand the risks associated with mismanagement of creds.

- **Goal:** maximize security while minimizing friction.
- **Positives:** they already understand the root goal of the practice, and as long as the friction point is lower than manual management, they will be ok with it.
- **Negatives:** they may be highly opinionated about how, when, and where the scans occur logically.

**Unsophisticated**: little to no knowledge of secrets, their usage, or why it matters to keep them secret. e.g. new AI users self-building a piece of software for their small business.

- **Goal:** they want to create their tool with as little friction as possible.
- **Positives:** they only care about the ease of its use, not the technicals.
- **Negatives:** they may not understand the importance of this type of security. Adoption will depend on the product making the importance relevant to them, and the friction point extremely low.

### 2. User flow

Use case 1: scan a source file. An engineer pastes a configuration file that may contain a live credential and runs the known rule-sets against it.

1. Create or reopen a **scan session**, then click **New scan**. If the current scan has text that was pasted but never scanned, prompt "Discard current scan?"; confirm clears, cancel keeps it. Scans that already ran need no prompt, since their results are already saved to the session.
2. Empty scan: paste the config file text. Scan is disabled until text is present. Scan text is never persisted (not to disk, not to browser storage).
3. Click **Scan**. While scanning, a "Do not refresh or close this page" warning is shown. The button reads **Cancel** for 5 seconds; a click in that window aborts. After 5 seconds the button returns to a running state; clicking it again re-arms Cancel for another 5 seconds (arm, then confirm).
4. Outcomes:
   - **Findings:** highlight the matched area in the text and show the rule it violates.
   - **Clean:** show a notification that nothing relevant was found.
   - **Partial:** findings from the rules that ran, plus a warning naming the rule(s) that failed.
   - **Cancelled:** back to ready, text intact, no results.
   - **Error:** API unreachable, 5xx, or input rejected. Error message shown, text intact, Scan re-enabled.
5. Text is read-only after a scan. To fix an issue and rescan, start a New scan in the same scan session and paste the fixed content into a fresh input. In-place editing (with results marked stale) is not ruled out for later.
6. Reload: no scan is open. Scan text does not persist; scan results do. A past scan session can be reopened: it shows each scan's broken rules and locations, but no content, and new scans can be added to it. Rule set versions in the rule set version control UI also persist.
7. One active scan session at a time, and one scan at a time: due to non-persistence of potentially live creds.

The rule set is versioned in the **rule set version control UI**, shown as a small timeline: persisted locally, each version viewable with its attached scan results, re-usable as the basis for a new version, and archivable (hidden from the timeline, not deleted).

**States**

| State | Trigger | What the user sees |
|---|---|---|
| No scan | Page load / reload | Rule set version control UI, past scan sessions, New scan button |
| Empty | New scan | Empty text box, Scan disabled |
| Ready | Text present | Scan enabled |
| Scanning | Scan clicked | Cancel button (5 s window), progress indicator, do-not-refresh warning |
| Cancelled | Cancel confirmed | Ready, text intact, no results |
| Findings | Scan done, 1+ matches | Highlights in text + rule violated per highlight |
| Clean | Scan done, 0 matches | "Nothing relevant found" notification |
| Partial | Scan done, 1+ rules failed | Findings from rules that ran + warning naming broken rule(s) |
| Error | API unreachable / 5xx / bad input | Error message, text intact, Scan re-enabled |

**Edge cases to handle or document**

- Input: empty or whitespace-only text; very large paste or one extremely long line; non-UTF-8 or binary pasted by accident; mixed line endings; Unicode near a match shifting highlight offsets.
- Matching: two rules match the same or overlapping text; the same secret appears multiple times; a match spans a line break; an obvious placeholder (`YOUR_API_KEY_HERE`) matches a pattern; a real credential with unusual formatting that no rule catches.
- Scan lifecycle: Cancel clicked as results arrive; browser reload mid-scan; API returns results for a different (stale) request.
- Rules: no rules enabled, so "clean" would be misleading; a rule's regex is invalid or catastrophically slow; rule set version changed between two scans of the same text.
- Output safety: highlight or list shows the full secret value on screen; error messages echo the input back.

**Still undefined:** which actions exist on a finding. Clicking and overlap are defined in entry 4.

### 3. Frontend, API, and detection-engine boundaries

**Frontend (`ui/`):** the scan UI and the rule set version control UI. Sends scan text and the rule set to the API over loopback. Contains no detection logic.

**API (`server/`):** keeps its current structure, with local storage for rule set versions. Calls the engine in-process (a function call, not a network hop). Never logs request content. Passes each scan's id to the engine as its log id and writes the engine's log events, so a scan's logs can be found by its id.

**Engine (`engine/`, top-level Rust crate):** a pure library with no HTTP, disk, or network access. `server/` depends on it by path; a future CLI will too.

- Validates and compiles rules, returning per-rule errors instead of failing the whole scan.
- Returns both byte offsets and line/column for every finding.
- Emits log events tagged with the scan id, containing redacted values only, never the full match. The caller decides where they are written.
- Covers four detection types:
  - **Direct credentials:** a secret value is present (`AKIA...`, `ghp_...`, `-----BEGIN PRIVATE KEY-----`, `password=hunter2`).
  - **Likely credentials:** high-entropy strings next to suspicious key names, with no known format.
  - **Placeholder vs. real:** classify a match as an example value (`YOUR_KEY_HERE`, `xxxx`) or as likely real. These rules list known fake values and never create findings of their own: a match inside another rule's finding raises that finding's placeholder score.
  - **Unsafe handling, no value present:** code or config that handles a secret unsafely (logging it, putting it in a URL, passing it on the command line). An unsafe handling finding points at a risky pattern, not a secret value, so the finding shape must support both.

**CLI (later):** pulls rule-sets from a hosted API, reads files itself, calls the engine in-process, and returns a well-documented, stable response shape to its local caller (shell, CI step, pre-commit hook). Scan text never goes over a wire.

```
browser (has the text)  --loopback-->  API (server/)  --function call-->  engine/
                        <--findings--                 <--findings + log events--
CLI (reads files)  -----------------------function call------------------>  engine/
CLI  <--rule-sets--  hosted API
```

**Exposure (accepted, documented):** FE to API traffic is loopback only and never leaves the machine. In dev it makes two loopback hops: browser to the Vite dev server (`127.0.0.1:5173`), then Vite's `/api` proxy to the API (`127.0.0.1:3001`). Scan text is still visible in browser devtools and readable by local processes that can observe loopback traffic. I think a production version would need to be its own app with I/O privileges, reading files directly and running the engine in-process, rather than a browser talking to a local API.

### 4. What a finding contains, and how it is represented in the source text

**Storage model**

```
scan session (id, rule set version, last ran)    : one active at a time, reopenable
  └─ scan (id, truncated)
       └─ finding (rule, kind: match | rule_error, violation JSON, violation_pretty)

rule set version (id, parent, archived)
  └─ rule set version rule (definition snapshot) ──► rule (id, definition JSON, drafting)
```

Every table also carries `created_at` and `updated_at`.

A scan session uses one rule set version and has many scans. Fixing an issue and rescanning creates a new scan in the same session, so all scans stay tied to the session. Scan sessions, scans, and findings are never deleted: together they record what was scanned with which rule set version, so they can be created and read but not removed. A scan's id doubles as its log id: the engine tags its log events with it. A rule that fails to run is recorded as a finding of kind `rule_error` on that rule, so a scan is partial when it has one, and clean when it has no findings at all.

Never stored: the pasted text, matched values, or a plain hash of either. A hash of the whole input was considered for recognizing repeat inputs, but it changes as soon as a single character is edited (for example, when the user fixes the issue), so it adds risk without being useful.

*Changed in Phase 3:* each match's value now gets a fingerprint, so a suppression can recognize the same value in a later scan of its session. It is a keyed, deliberately slow hash (Argon2id, with a secret key kept in its own file outside the database), never the value. A hash can't be worked backwards; the only way to a value is to hash guesses and compare. Without the key, guesses can't be checked at all. With it, each guess costs milliseconds and megabytes instead of nanoseconds, so short passwords can't be found by brute force. See [Fingerprints and suppressions](engine/README.md#fingerprints-and-suppressions).

**A finding contains**

| Field | Form | Source |
|---|---|---|
| Rule id and name | Text | Rule |
| Detection type | Label (direct credential, likely credential, unsafe handling) | Engine |
| Severity | Label | Fixed per rule by the rule author |
| Confidence | Score, 0–100: how likely the match is what its rule describes, from that match's own evidence (checksum, prefix, key name, randomness, where a logged secret name sits), weighed the same for every rule type | Engine, per finding |
| Placeholder vs. real | Score, 0–100 | Engine, per finding |
| Location | Line/column and byte offsets | Engine |
| Redacted preview | Format prefix declared by the rule (e.g. `AKIA…`), or nothing if the rule has no known prefix | Rule |
| Why flagged | A note explaining the scores using signals only (e.g. entropy, suspicious key name, not a known placeholder), never input text | Engine, per finding |
| Remediation hint | Static text | Rule |

These fields live in the finding's `violation` JSON. `violation_pretty` holds the human-readable summary shown in lists, and `kind` says whether the finding is a match or a rule error.

**Redacted preview:** taken from the rule definition, not from the match, so no byte of a matched value reaches storage, logs, CLI output, or the API response. The same format is used in all four. It is needed wherever the text is unavailable or output could leak: engine log events, the past scan session view, CLI output, and the API scan response. The live scan view does not need it, since the frontend highlights its own copy of the text. Trade-off: two findings from the same rule on the same line can only be told apart by column in the past scan session view.

**Represented in the source text**

- **Color by severity,** with fixed defaults and no user config: high = red, medium = amber, low = blue.
- **Severity icon** next to each highlight and in the findings list, so severity is not conveyed by color alone.
- **Overlap:** overlapping findings get one highlight in a distinct color not used for any severity (purple). Clicking it selects and shows all the findings it covers. The engine decides which findings overlap and gives each overlapping set a shared group id (in the finding's `violation` details), so the UI and the future CLI group them the same way; the UI only draws the groups.
- **Multi-line matches** (e.g. a private key block) are highlighted as a whole block.
- **Linking** works both ways: clicking a highlight selects its finding in the list, and clicking a finding scrolls to its highlight.
- **Past scan sessions** have no text, so findings are shown as a list with rule, location, scores, preview, and notes.

### 5. Assumptions about rules, configuration errors, and scan results

**Rules**

- Rules exist on their own and are added into rule set versions, managed in the rule set version control UI and persisted locally. Adding a rule to a version stores a snapshot of its definition with that version, so an old version keeps what it scanned with even if the rule is edited later.
- A **built-in default rule set** is seeded as the first rule set version, with at least one rule for each detection type (direct credentials, likely credentials, unsafe handling, placeholder vs. real). The defaults are just seeded config: every rule can be edited, disabled, or removed, and users can add their own. Re-using the first version restores the defaults, unless it has been archived.
- Rules are edited through **forms**, never raw text, and always saved as canonical **JSON**.
- Rule ids are assigned by the system, unique, and stable across rule set versions, like a database primary key. A rule keeps its id when renamed or edited; a deleted rule's id is never reused. Users never see or edit ids.
- A rule gets its real id as soon as it is added in the form, with `drafting` set to true, and is stored right away, so drafts survive a reload. Drafts get no validation. Adding a rule into a rule set version validates it and clears `drafting`. Errors point at the rule's real id, so a new rule needs no temporary key.
- Severity is fixed per rule by the rule author.

A rule row holds `id`, `drafting`, and a `definition` JSON column. Every other field below lives inside `definition`, filled in from the rule form's separate fields.

| Field | Purpose |
|---|---|
| `id` | Assigned by the system |
| `drafting` | True until the rule is added into a rule set version |
| `name` | Shown in findings |
| `enabled` | Disable without deleting |
| `detectionType` | Direct credential, likely credential, or unsafe handling |
| `severity` | High, medium, or low |
| `pattern` | The regex to match |
| `prefix` | Optional public prefix, used for the redacted preview |
| `keyNames` | Optional suspicious key names (used by likely-credential rules) |
| `minEntropy` | Optional entropy threshold, 0–8 bits/char |
| `remediation` | Static hint text |

Known placeholder values (`YOUR_KEY_HERE`, `changeme`, ...) are rules of type placeholder vs. real, edited and versioned like any other rule. Severity and remediation don't apply to them.

**Configuration errors**

- **Validated in three places:**
  - inline in the form, field by field, as the user types, except on draft rules, which are not validated until they are applied;
  - on save: an invalid rule set version cannot be saved, so every saved version is valid;
  - in the engine at scan time, as a safety net for config from other sources (such as the CLI pulling from a hosted API). Errors are reported per rule and the scan returns a Partial outcome.
- **Errors:** a missing required field (name, detection type, severity, pattern); an invalid regex; a pattern too large to compile (the `regex` crate's size limit); a threshold out of range (entropy outside 0–8 bits/char, scores outside 0–100); two rules in the same version with the same name.
- **Warning, not an error:** a pattern that can match an empty string, which would flood results.
- **No rules enabled:** the scan is blocked. The Scan button is disabled with "No rules enabled in this rule set version," because "clean" would be misleading.
- **How a compile error reaches the user:**
  - *While editing:* validate and save both run the engine's compile step. The error comes back keyed by rule id and field and is shown under the pattern input, with the bad spot underlined when the engine knows it. Save stays disabled, so an uncompilable rule cannot get into a saved version from the form.
  - *At scan time:* a saved rule can still fail later (an engine update tightens a limit, or the CLI pulls a rule set the UI never validated). The engine skips that rule, runs the rest, and records the failure as a finding of kind `rule_error` on that rule, with the field, code, message, and byte span (when known) in its `violation` details, so a reopened session can still point at the exact field. The API returns it with the other findings. The UI shows the Partial outcome with a warning naming each broken rule and its error, on the live scan and when reopening the session. The CLI (later) prints the rule errors and exits with a distinct code, so CI cannot treat the scan as clean.
  - *Acting on it:* the Partial warning links straight to that rule in the rule set version control UI, with the form open on the error. Fixing it saves a new rule set version; the user then starts a new scan to rescan.
- Rust's `regex` crate runs in linear time, so catastrophic backtracking cannot happen. Size limits still apply to patterns and inputs.

**Scan results**

- **Deterministic:** the same text and the same rule set version always give the same results.
- **Repeated secret:** one finding per occurrence, since each location must be fixed.
- **Ordering:** by position in the text. The findings list can be sorted by severity in the UI.
- **Limits:** 1 MB maximum input, rejected with a clear message. Findings are capped at 200 per scan; anything over the cap is reported as truncated, never silently dropped. The cap exists because a too-broad rule can match almost every line, which would bloat storage, slow the response, and flood the page with highlights; hitting it usually means a bad rule, not hundreds of real secrets.
- **Tell the user about the cap before it happens:** the scan UI states the 200-finding cap up front (next to the Scan button), so a cut-short list is never a surprise. When the cap is hit, the results say the list was cut short.

### 6. What to build first, and what to deliberately leave out

**First**

1. **Engine crate:** rules and checking implementation, with unit tests for scanning and returned results. What this step finds drives the model structure and surfaces real needs before anything is formally modeled.
2. **Model the structures** for frontend use (backend).
3. **API endpoints** built around that model, with unit tests.
4. **Frontend UI.**

**Second**

1. Human end-to-end testing.

**Left out of the POC**

1. **A real storage database, CLI usage, and hosted API concepts.** A local SQLite file (`server/data/scanner.sqlite3`, git-ignored) stands in for a real database: rule set versions, rules, scan sessions, scans, and findings persist there. The whiteboard still saves as a JSON file.
2. **Editing in place:** input is copy/paste only for now, so it would not be helpful.
3. **Follow-up actions like dismiss or suppress:** again, input is copy/paste only, so these are not that helpful yet.
4. **File or repository scanning:** this becomes the most likely MVP point to tackle next.
5. **WASM in the browser:** it has use cases, like building a local pre-check model, but it is large and specialized. I think the better solution is a real local application anyway, and I really dislike this whole concept being in a browser.
6. **Auth and multiple users:** these go with the hosted API.
7. **Compiled-rule caching:** rule set versions never change once saved, so the compiled rules could be cached per version instead of recompiled on every scan. That's an optimization, not a requirement for the POC, but likely needed for a production app.

## Phase 2: Core implementation

Phase 2 notes so far. The UI and the rest of the API are still to come.

### Detection approach

The engine (`engine/`, documented in [engine/README.md](engine/README.md)) is a pure Rust library: no network, disk, or HTTP. It layers four techniques, all running locally:

1. **Regex rules** for known formats (AWS keys; GitHub, npm, GitLab, and Slack tokens; Stripe, SendGrid, Google, OpenAI, and Anthropic keys; private keys with or without PEM armor, JWKs, PuTTY keys, and keystores; payment card numbers; Bitcoin private keys), for credentials in a known syntax (URLs, auth headers, JWTs, connection strings, SQL, `.netrc`, registry auth, Kubernetes Secrets, cookies, pre-signed URLs, password hashes), and for risky code (secrets written to logs).
2. **Entropy** for likely credentials: a random-looking value (at least 3 bits per character) assigned to a name like `password`, `secret`, or `token`.
3. **Checksums:** some formats carry one, so the engine can tell a real value from a made-up one offline. GitHub, npm, and GitLab tokens end in a CRC32 of the rest, card numbers carry a Luhn check digit, and Bitcoin private keys use Base58Check. A valid checksum is the strongest evidence a finding can have and a failed one is equally strong evidence against; a failed one also marks the finding as a likely example. A failed checksum never hides a finding, because GitHub, npm, and GitLab haven't published test tokens to confirm the exact encoding against.
   - **Seeded and custom setups:** a checksum is a small description on the rule. `luhn` and `base58check` need nothing else; `crc32` also takes an encoding (`base62`, `base36`, or `hex`), a prefix length, and a checksum length. The built-in rules seed the common setups: GitHub, npm, GitLab (routable tokens, plus a separate rule for the older format, which has no checksum), payment cards, and Bitcoin private keys. A rule author can describe their own, e.g. for an in-house token format.
   - **Not seeded:** Microsoft/Azure identifiable keys (their checksum algorithm couldn't be confirmed); Ethereum addresses and IBANs (public identifiers, not secrets). A wrong custom setup only lowers confidence on real tokens, so it can't hide them, and a length too short to hold the value is rejected as a rule error.
4. **File format parsing:** the text is read as JSON, YAML, `.env`, or plain text. Parsed key/value pairs catch secrets a pattern alone misses (a quoted value containing `$` or `;`, a JSON key and value on separate lines). Comments are recognized, so a secret in a comment scores as a likely example, and commented-out code that logs a secret drops to low confidence. In a logging call, a secret name used as code (`log(dbPassword)`) raises confidence, and one that's only a word in a quoted message (`log("token refresh scheduled")`) lowers it.

**Placeholder vs. real is a rule type.** Known fake values (`changeme`, `example`, ...) are rules like any other, edited and versioned the same way. They never create findings of their own; when one matches inside another rule's finding, that finding scores as a likely example. This is the fourth detection type from Phase 1, coming back as a rule type instead of a separate list.

**Deliberately not used:**
- **Live verification:** asking the provider whether a secret works is the strongest signal, but it sends the secret off the machine. Not built for the POC; a production build could offer it for certain rules:
  - **Opt-in only:** off by default, chosen per scan (or a `--verify` flag in the CLI).
  - **Only rules with a safe, read-only check:** GitHub (`GET /user`), npm (`whoami`), and GitLab (`GET /api/v4/personal_access_tokens/self`). AWS only when the secret access key is found alongside the key ID. Never for payment cards or Bitcoin keys (checking would mean attempting a charge or transaction), and never for likely credentials or unsafe handling (no provider to ask).
  - **Built-in verifiers only:** a rule can turn on a verifier the app ships with, never point at its own URL, so a custom rule can't send secrets anywhere.
  - **Only confident findings:** e.g. GitHub tokens whose checksum passes, not ones in comments or ones that look like examples.
  - **Runs in the API or CLI, not the engine:** it happens during the scan request, while the text is still in memory, because findings never contain the secret itself. Results come back first and verification statuses fill in after, so a slow provider never holds up a scan.
  - **Stores a status, never the provider's response:** `active`, `inactive`, `unknown`, or `not attempted`, with when it was checked, in a separate `verifications` table. Active findings would sort first in the UI and get their own CI exit code.
- **AI or ML triage:** this would also send text off the machine unless the model ran locally, and it would make "why flagged" harder to explain.
- **Parsing source code into syntax trees:** this would need a parser per language, so code is scanned as text with its comment lines recognized.
- **Finding passwords under 8 characters:** the scanner doesn't try. A model detection rule drops any finding shorter than 8 bytes (`MIN_DETECTION_BYTES`), and the built-in password rules need 8 characters too (6 for about 60 very common passwords). A secrets scanner finds secrets that leaked; it isn't a password-strength check. A 4-character password can be guessed whether or not it's in the code, so finding it doesn't help anyone. Lowering the minimum was measured on 65 held-out CredData repositories: at 4 bytes, the detector found 42 of 108 short passwords but added about 1,300 false findings, and precision fell from 0.405 to 0.283.

### Models: what the secret detector was trained and evaluated on

The secret detector (`engine/models/secret-detector.onnx`) is a `model_detection` model that runs locally on the CPU, so no text leaves the machine. It scores every byte of the text for how likely it is part of a secret. Details are in [ml/README.md](ml/README.md#secret-detector-training).

It was trained on two sources, and each is evaluated on held-out data of its own. The numbers are kept separate so synthetic and real results aren't mixed.

**1. Synthetic documents** (`ml/detector_data.py`): 32,000 for training, 2,000 more from a different seed for evaluation. Every byte has a label.

- **Documents:** about twenty kinds of file: env, YAML, JSON, TOML, INI, properties, code in seven languages, shell, Dockerfile, XML, Terraform, logs, prose and chat, HTML, credential files, and Markdown with code blocks. A third of the documents contain no secret.
- **Secrets it plants (labeled 1):**
  - known vendor formats, and made-up vendor tokens (a random prefix and random characters)
  - generic hex, alphanumeric and base64 keys, salts, and composite tokens
  - passwords
  - the password in a connection string, a token after `Bearer` or in `--user`, a signature in a URL
  - webhook URLs, JWTs, private keys, and keys passed straight to functions
- **Hard negatives (labeled 0):**
  - hashes and digests, `0x` hashes, lockfile and checksum entries
  - UUIDs, IDs with prefixes, ARNs, build hashes, cursors
  - base64 image data, SRI strings, public keys, certificates, SSH keys
  - URLs, minified code
  - placeholders, references to secrets stored elsewhere, and settings named after secrets that hold none
- **No real secrets:** real-shaped values are random at generation time, so the repository contains no secret-looking string.

**2. CredData** ([Samsung/CredData](https://github.com/Samsung/CredData) at commit `fc9b64b`): source files from 337 public GitHub repositories (11,565 files, 997 MB), with 67,896 lines labeled by hand: 15,753 `T`, 48,061 `F`, 4,082 `X`. CredData had already replaced the real credentials with random values of the same shape. AWS keys keep their real prefix (`AKIA…`), never a documentation value, so these rows don't teach the model that example values are secrets.

- **Labels used:**
  - A `T` value is labeled 1 at CredData's value position. A multi-line private key is labeled from its start through its second line.
  - `F` lines, `X` lines and unlabeled text are labeled 0.
  - `T` rows with no value position, and multi-line `T` values that aren't keys, are left out of training.
- **Split by repository,** by a hash of each repository's id. No repository is in more than one split:
  - **Test:** 66 repositories with 6,183 `T`, 13,360 `F` and 562 `X` lines. Used only to report results.
  - **Validation:** 37 repositories with 1,454 `T`. Used to choose the threshold.
  - **Training:** the other 234 repositories. The model trains on 34,016 pieces from them:
    - pieces around every `T`, `F` and `X` line, with passwords of 8 bytes or more taken three times
    - at most 500 pieces from any one repository, so no repository dominates
- **Error analysis drove the last round:**
  - The previous model's false positives on the test repositories were sorted into groups: embedded base64 blobs, .NET `PublicKeyToken=` values, lockfile checksums, password hashes, SQL column lists, format strings, AWS documentation IDs.
  - Synthetic look-alikes of each group were added as negatives.
  - This used the test repositories' error groups, not their labels, but it is still a form of tuning against them, so the validation numbers below matter too.
- **Not committed:** no CredData file is in this repository, only the trained model and the code that reads a local checkout (`ml/creddata.py`). Each file keeps its source project's license: MIT 185 repositories, Apache-2.0 94, BSD-3-Clause 17, LGPL 16, ISC 4, BSD-2-Clause 4, CC0 3, GPL 1, EPL 1, other 4, no license file 8.

**Threshold:** chosen on the validation repositories. F1 peaks at threshold 50 there, with precision 0.702 and recall 0.694, so the default stays at 50. The chart is in `ml/detector-thresholds.svg`.

**Results**, at threshold 50, as precision / recall. A secret counts as found when a finding overlaps it; a finding counts as right when it overlaps a secret.

| Held-out data | Synthetic only | First CredData model | **Shipped model** |
|---|---|---|---|
| CredData test: the 65 repositories other than one holding 84% of the labels | 0.074 / 0.563 | 0.405 / 0.750 | **0.523 / 0.693** |
| CredData test: all 66 repositories | 0.280 / 0.694 | 0.611 / 0.844 | **0.550 / 0.932** |
| CredData validation: 37 repositories | (not separate then) | (trained on) | **0.702 / 0.694** |
| Synthetic documents (shipped and first-CredData models on the current, harder set) | 0.959 / 0.958 | 0.891 / 0.924 | **0.945 / 0.934** |
| Hand-written batch 3 (12 secrets, 8 clean texts) | 11 found, 2 wrong | 10 found, 0 wrong | **11 found, 0 wrong** |

- **Hand-written batches** (`engine/tests/secret_detector.rs`): each batch was written before the model it was first checked against.
  - Batches 1 and 2 were used to find gaps in the generator, so they aren't a fair test.
  - Batch 3 was never used to change anything. It is small, and the same person wrote it and the generator.
- **Ordinary code:** the first CredData row is the best guide, since one cryptography project dominates the second.
  - About half of the findings there are credentials at threshold 50 (about 7 in 10 at threshold 70), so findings are leads to review, not verdicts.
  - The shipped model trades some recall for precision against the first CredData model: F1 0.60 against 0.53.
  - Its precision–recall curve is close to the earlier model's, and ahead wherever precision is above about 0.65.
- **Passwords:** 108 of the 360 test passwords are under 8 bytes, below the engine's minimum finding, so none of those can be found. Of the 252 it could report, it finds 207.
- **Uncertainty:** errors cluster by repository, so the intervals come from resampling whole repositories.
  - On the 65 test repositories, the shipped model's precision is 0.523, with a 95% interval of 0.40 to 0.65.
  - Its gain over the first CredData model is still clear: precision +0.05 to +0.17 higher, F1 +0.02 to +0.12 higher.
- **Tried and not shipped: hard negatives.** Using the shipped model's unlabeled findings in the training repositories as negatives (v6) gave mixed results:
  - better on the test repositories: 0.680 / 0.658
  - worse on validation: 0.554 / 0.601, against 0.702 / 0.694
  Validation decides, so the shipped model stayed. Some unlabeled CredData text is probably real secrets, which makes those negatives noisy.
- **Value classifier overlap:** the value classifier splits CredData by its own hash, so most of these test repositories were in its training data. Numbers for the detector and classifier together on these repositories would not be on unseen data.

### Scan endpoint

`POST /api/scan-sessions/{id}/scans` loads the session's rule set version, runs the engine, and saves the scan and its findings. The text itself is never stored or logged. `GET /api/scan-sessions/{id}/scans/{scanId}` reads a saved scan back in the same shape.

Rules, rule sets, rule set versions, and scan sessions have REST routes too (`/api/rules`, `/api/rule-sets`, `/api/rule-set-versions`, `/api/scan-sessions`), including `POST /api/rules/check` to check rules as one set without saving. They cover everything the MCP tools do except reading the rule authoring guide, through the same storage module. Swagger UI at `/swagger-ui` lists them all.

- **Concurrency cap:** at most 4 scans run at once. Others wait their turn, so a burst of scans can't starve the rest of the API.
- **At scale:** scanning in the API process would compete with every other request. The intended production shape avoids that entirely: scanning runs on the client (a CLI or a real local app calling the engine in-process), and the hosted API only serves rule sets. If a hosted scanning service were ever needed, the next steps would be a separate worker pool, then a queue with independently scaled workers.

### MCP server

The API also serves an MCP server at `/mcp` (Streamable HTTP), so an AI agent can read and write the same data the UI will. It has 20 tools:

- **Rule authoring:** `rule_authoring_guide` explains every mechanism a rule can use (patterns and their `value` and `key` groups, detection types, key names, entropy, checksums, password shape, placeholders, model rules), when to use each and why, and how each built-in rule is assembled from them. It returns the whole guide or one section by topic, and the server's instructions tell agents to read it before writing rules. The guide lives in `server/src/rule_guide.md`.
- **Rules:** `list_rules`, `get_rule`, `create_rule`, `update_rule`, `delete_rule`, `check_rules`
- **Rule sets:** `list_rule_sets`, `get_rule_set`, `create_rule_set`, `update_rule_set`
- **Rule set versions:** `list_rule_set_versions`, `get_rule_set_version`, `create_rule_set_version`, `set_rule_set_version_archived`
- **Scan sessions and scans:** `list_scan_sessions`, `get_scan_session`, `create_scan_session`, `get_scan`, `run_scan`

The tools follow the same rules as the rest of the API, through a shared storage module (`server/src/store.rs`):

- New rules are drafts and aren't validated. `delete_rule` only deletes drafts; a rule in a version can be disabled or left out of the next version instead.
- `create_rule_set_version` takes the full list of rule ids, runs the engine's checks on them as a set, and saves nothing if any check fails. Otherwise it snapshots each rule's current definition and clears `drafting`. A saved version can only be archived or restored, and an archived version can't start a new session.
- `run_scan` uses the same code as the scan endpoint, so the text is never stored or logged, and findings never contain matched values.
- Scan sessions and scans can be created and read, but there are no tools to delete them, since scan results are kept as history.
- **Local only:** like the API, the server listens on loopback. It accepts only loopback `Host` headers, which protects against DNS rebinding, and it rejects any request that has an `Origin` header, so a web page can't drive the write tools through the user's browser.
- **Stateless:** each tool call is one request and one JSON response, with no MCP session to keep.

### Models: what the value classifier was trained and evaluated on

The value classifier (`engine/models/value-classifier.onnx`) runs locally on the CPU as a rule's `valueClassifier` setting. For each value a rule matches, it says whether it's a credential, a non-secret string (a hash, ID, or encoded data), or a placeholder, from the value's own line. Details are in [ml/README.md](ml/README.md).

It was trained on two sources, each evaluated on held-out data of its own:

- **Synthetic samples** (`ml/data.py`, 40,000): one config or code line setting a name to a value. Credentials in known formats and generic keys and passwords; non-secret hashes, digests, UUIDs, IDs, encoded data, URLs, and paths, sometimes under secret-sounding names; and placeholder and documentation values. Real-shaped values are random at generation time.
- **CredData** ([Samsung/CredData](https://github.com/Samsung/CredData) at commit `fc9b64b`), the same checkout the secret detector uses: single-line rows that mark their value, with `T` as credential, `F` as non-secret, and `X` as placeholder. Split by a hash of the repository ID into 241 training, 28 validation, and 63 test repositories. Each training repository contributes at most 400 values per class (18,806 in all). No CredData file is committed; each keeps its source project's license (by a count of license files: MIT 186 repositories, Apache-2.0 95, BSD 20, LGPL 10, GPL or AGPL 7, ISC 5, CC0 or Creative Commons 3, EPL 1, other 3, no license file 7).

**Results**, kept separate by source:

| Held-out data | Synthetic-only model | Shipped model (synthetic + CredData) |
|---|---|---|
| CredData, 63 test repositories | accuracy 0.491; 39% of credentials would get lower confidence | accuracy 0.854; 9% |
| CredData, the 62 test repositories other than the one with the most credentials | accuracy 0.541; 35% | accuracy 0.840; 11% |
| Synthetic | accuracy 0.986 | accuracy 0.974 |

The synthetic-only model's near-perfect synthetic score and poor CredData score show why the real data mattered: it had learned the generator, not real code.

### Known gaps

- **Built-in rule updates don't reach existing databases.** The built-in rule set is seeded only into an empty database, and saved rule set versions keep the rule copies they were made with. A changed built-in rule (such as the GitHub checksum) only reaches a database through a new rule set version, or by recreating the local database.
