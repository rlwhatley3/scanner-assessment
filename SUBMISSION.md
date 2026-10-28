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

1. Create or reopen a **scan session**, then click **New inspection**. If the current inspection has text that was pasted but never scanned, prompt "Discard current inspection?"; confirm clears, cancel keeps it. Scanned inspections need no prompt, since their results are already saved to the session.
2. Empty inspection: paste the config file text. Scan is disabled until text is present. Inspection text is never persisted (not to disk, not to browser storage).
3. Click **Scan**. While scanning, a "Do not refresh or close this page" warning is shown. The button reads **Cancel** for 5 seconds; a click in that window aborts. After 5 seconds the button returns to a running state; clicking it again re-arms Cancel for another 5 seconds (arm, then confirm).
4. Outcomes:
   - **Findings:** highlight the matched area in the text and show the rule it violates.
   - **Clean:** show a notification that nothing relevant was found.
   - **Partial:** findings from the rules that ran, plus a warning naming the rule(s) that failed.
   - **Cancelled:** back to ready, text intact, no results.
   - **Error:** API unreachable, 5xx, or input rejected. Error message shown, text intact, Scan re-enabled.
5. Text is read-only after a scan. To fix an issue and rescan, start a New inspection in the same scan session and paste the fixed content into a fresh input. In-place editing (with results marked stale) is not ruled out for later.
6. Reload: no inspection is open. Inspection text does not persist; inspection results do. A past scan session can be reopened: it shows each inspection's broken rules and locations, but no content, and new inspections can be added to it. Config versions in the config version control UI also persist.
7. One active scan session at a time, and one inspection at a time: due to non-persistence of potentially live creds.

Rule config is versioned in the **config version control UI**, shown as a small timeline: persisted locally, each version viewable with its attached scan results, re-usable as the basis for a new version, and archivable (hidden from the timeline, not deleted).

**States**

| State | Trigger | What the user sees |
|---|---|---|
| No inspection | Page load / reload | Config version control UI, past scan sessions, New inspection button |
| Empty | New inspection | Empty text box, Scan disabled |
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
- Rules: no rules enabled, so "clean" would be misleading; a rule's regex is invalid or catastrophically slow; config version changed between two scans of the same text.
- Output safety: highlight or list shows the full secret value on screen; error messages echo the input back.

**Still undefined:** which actions exist on a finding. Clicking and overlap are defined in entry 4.

### 3. Frontend, API, and detection-engine boundaries

**Frontend (`ui/`):** the inspection UI and the config version control UI. Sends inspection text and config to the API over loopback. Contains no detection logic.

**API (`server/`):** keeps its current structure, with local storage for config versions. Calls the engine in-process (a function call, not a network hop). Never logs request content. Generates a log id per scan, passes it to the engine, and writes the engine's log events so the two can be correlated.

**Engine (`engine/`, top-level Rust crate):** a pure library with no HTTP, disk, or network access. `server/` depends on it by path; a future CLI will too.

- Validates and compiles rules, returning per-rule errors instead of failing the whole scan.
- Returns both byte offsets and line/column for every finding.
- Emits log events tagged with the log id, containing redacted values only, never the full match. The caller decides where they are written.
- Covers four detection types:
  - **Direct credentials:** a secret value is present (`AKIA...`, `ghp_...`, `-----BEGIN PRIVATE KEY-----`, `password=hunter2`).
  - **Likely credentials:** high-entropy strings next to suspicious key names, with no known format.
  - **Placeholder vs. real:** classify a match as an example value (`YOUR_KEY_HERE`, `xxxx`) or as likely real.
  - **Unsafe handling, no value present:** code or config that handles a secret unsafely (logging it, putting it in a URL, passing it on the command line). An unsafe handling finding points at a risky pattern, not a secret value, so the finding shape must support both.

**CLI (later):** pulls rule-sets from a hosted API, reads files itself, calls the engine in-process, and returns a well-documented, stable response shape to its local caller (shell, CI step, pre-commit hook). Inspection text never goes over a wire.

```
browser (has the text)  --loopback-->  API (server/)  --function call-->  engine/
                        <--findings--                 <--findings + log events--
CLI (reads files)  -----------------------function call------------------>  engine/
CLI  <--rule-sets--  hosted API
```

**Exposure (accepted, documented):** FE to API traffic is loopback only and never leaves the machine. In dev it makes two loopback hops: browser to the Vite dev server (`127.0.0.1:5173`), then Vite's `/api` proxy to the API (`127.0.0.1:3001`). Inspection text is still visible in browser devtools and readable by local processes that can observe loopback traffic. I think a production version would need to be its own app with I/O privileges, reading files directly and running the engine in-process, rather than a browser talking to a local API.

### 4. What a finding contains, and how it is represented in the source text

**Storage model**

```
scan session (id)                        : one active at a time, reopenable
  └─ inspection (id, timestamp, config version, log id, outcome)
       └─ finding
       └─ rule errors
```

A scan session has many inspections; each inspection is one scan. Fixing an issue and rescanning creates a new inspection in the same session, so all inspections stay tied to the session id.

Never stored: the inspection text, matched values, or a hash of the input. A hash was considered for recognizing repeat inputs, but it changes as soon as a single character is edited (for example, when the user fixes the issue), so it adds risk without being useful.

**A finding contains**

| Field | Form | Source |
|---|---|---|
| Rule id and name | Text | Rule |
| Detection type | Label (direct credential, likely credential, unsafe handling) | Engine |
| Severity | Label | Fixed per rule by the rule author |
| Confidence | Score, 0–100 | Engine, per finding |
| Placeholder vs. real | Score, 0–100 | Engine, per finding |
| Location | Line/column and byte offsets | Engine |
| Redacted preview | Format prefix declared by the rule (e.g. `AKIA…`), or nothing if the rule has no known prefix | Rule |
| Why flagged | A note explaining the scores using signals only (e.g. entropy, suspicious key name, not a known placeholder), never input text | Engine, per finding |
| Remediation hint | Static text | Rule |

**Redacted preview:** taken from the rule definition, not from the match, so no byte of a matched value reaches storage, logs, CLI output, or the API response. The same format is used in all four. It is needed wherever the text is unavailable or output could leak: engine log events, the past scan session view, CLI output, and the API scan response. The live inspection view does not need it, since the frontend highlights its own copy of the text. Trade-off: two findings from the same rule on the same line can only be told apart by column in the past scan session view.

**Represented in the source text**

- **Color by severity,** with fixed defaults and no user config: high = red, medium = amber, low = blue.
- **Severity icon** next to each highlight and in the findings list, so severity is not conveyed by color alone.
- **Overlap:** overlapping findings get one highlight in a distinct color not used for any severity (purple). Clicking it selects and shows all the findings it covers.
- **Multi-line matches** (e.g. a private key block) are highlighted as a whole block.
- **Linking** works both ways: clicking a highlight selects its finding in the list, and clicking a finding scrolls to its highlight.
- **Past scan sessions** have no text, so findings are shown as a list with rule, location, scores, preview, and notes.

### 5. Assumptions about rules, configuration errors, and scan results

**Rules**

- Rules live in config versions, managed in the config version control UI and persisted locally.
- A **built-in default rule set** is seeded as the first config version, with at least one rule for each detection type (direct credentials, likely credentials, unsafe handling). The defaults are just seeded config: every rule can be edited, disabled, or removed, and users can add their own. Re-using the first version restores the defaults, unless it has been archived.
- Rules are edited through **forms**, never raw text, and always saved as canonical **JSON**.
- Rule ids are assigned by the system, unique, and stable across config versions, like a database primary key. A rule keeps its id when renamed or edited; a deleted rule's id is never reused. Users never see or edit ids.
- Severity is fixed per rule by the rule author.

| Field | Purpose |
|---|---|
| `id` | Assigned by the system |
| `name` | Shown in findings |
| `enabled` | Disable without deleting |
| `detectionType` | Direct credential, likely credential, or unsafe handling |
| `severity` | High, medium, or low |
| `pattern` | The regex to match |
| `prefix` | Optional public prefix, used for the redacted preview |
| `keyNames` | Optional suspicious key names (used by likely-credential rules) |
| `minEntropy` | Optional entropy threshold, 0–8 bits/char |
| `remediation` | Static hint text |

A list of known placeholder values (`YOUR_KEY_HERE`, `changeme`, ...) is set once per config version, not per rule, and is used to compute the placeholder vs. real score.

**Configuration errors**

- **Validated in three places:**
  - inline in the form, field by field, as the user types;
  - on save: an invalid config version cannot be saved, so every saved version is valid;
  - in the engine at scan time, as a safety net for config from other sources (such as the CLI pulling from a hosted API). Errors are reported per rule and the scan returns a Partial outcome.
- **Errors:** a missing required field (name, detection type, severity, pattern); an invalid regex; a pattern too large to compile (the `regex` crate's size limit); a threshold out of range (entropy outside 0–8 bits/char, scores outside 0–100); two rules in the same version with the same name.
- **Warning, not an error:** a pattern that can match an empty string, which would flood results.
- **No rules enabled:** the scan is blocked. The Scan button is disabled with "No rules enabled in this config version," because "clean" would be misleading.
- Rust's `regex` crate runs in linear time, so catastrophic backtracking cannot happen. Size limits still apply to patterns and inputs.

**Scan results**

- **Deterministic:** the same text and the same config version always give the same results.
- **Repeated secret:** one finding per occurrence, since each location must be fixed.
- **Ordering:** by position in the text. The findings list can be sorted by severity in the UI.
- **Limits:** 1 MB maximum input, rejected with a clear message. Findings are capped at 1,000 per scan; anything over the cap is reported as truncated, never silently dropped.
