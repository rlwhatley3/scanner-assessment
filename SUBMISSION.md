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

1. Click **New inspection**. If the current inspection has text or results, prompt "Discard current inspection?"; confirm clears, cancel keeps it.
2. Empty inspection: paste the config file text. Scan is disabled until text is present. Inspection text is never persisted (not to disk, not to browser storage).
3. Click **Scan**. While scanning, a "Do not refresh or close this page" warning is shown. The button reads **Cancel** for 5 seconds; a click in that window aborts. After 5 seconds the button returns to a running state; clicking it again re-arms Cancel for another 5 seconds (arm, then confirm).
4. Outcomes:
   - **Findings:** highlight the matched area in the text and show the rule it violates.
   - **Clean:** show a notification that nothing relevant was found.
   - **Partial:** findings from the rules that ran, plus a warning naming the rule(s) that failed.
   - **Cancelled:** back to ready, text intact, no results.
   - **Error:** API unreachable, 5xx, or input rejected. Error message shown, text intact, Scan re-enabled.
5. Text is read-only after a scan. Start a New inspection to change it. In-place editing (with results marked stale) is not ruled out for later.
6. Reload: no inspection is open. Config versions in the config version control UI persist; inspection text and results do not.
7. One inspection at a time: due to non-persistence of potentially live creds.

Rule config is versioned in the **config version control UI**, shown as a small timeline: persisted locally, each version viewable with its attached scan results, re-usable as the basis for a new version, and archivable (hidden from the timeline, not deleted).

**States**

| State | Trigger | What the user sees |
|---|---|---|
| No inspection | Page load / reload | Config version control UI, New inspection button |
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

**Still undefined:** what clicking a finding does, which actions exist on a finding, and how overlapping findings are displayed.

### 3. Frontend, API, and detection-engine boundaries

**Frontend (`ui/`):** the inspection UI and the config version control UI. Sends inspection text and config to the API over loopback. Contains no detection logic.

**API (`server/`):** keeps its current structure, with local storage for config versions. Calls the engine in-process (a function call, not a network hop). Never logs request content. Generates a log id per scan, passes it to the engine, and writes the engine's log events so the two can be correlated.

**Engine (`engine/`, top-level Rust crate):** a pure library with no HTTP, disk, or network access. `server/` depends on it by path; a future CLI will too.

- Validates and compiles rules, returning per-rule errors instead of failing the whole scan.
- Returns both byte offsets and line/column for every finding.
- Emits log events tagged with the log id, containing redacted values only, never the full match. The caller decides where they are written.
- Covers four detection tiers:
  1. **Direct credentials:** a secret value is present (`AKIA...`, `ghp_...`, `-----BEGIN PRIVATE KEY-----`, `password=hunter2`).
  2. **Likely credentials:** high-entropy strings next to suspicious key names, with no known format.
  3. **Placeholder vs. real:** classify a match as an example value (`YOUR_KEY_HERE`, `xxxx`) or as likely real.
  4. **Unsafe handling, no value present:** code or config that handles a secret unsafely (logging it, putting it in a URL, passing it on the command line). A tier 4 finding points at a risky pattern, not a secret value, so the finding shape must support both.

**CLI (later):** pulls rule-sets from a hosted API, reads files itself, calls the engine in-process, and returns a well-documented, stable response shape to its local caller (shell, CI step, pre-commit hook). Inspection text never goes over a wire.

```
browser (has the text)  --loopback-->  API (server/)  --function call-->  engine/
                        <--findings--                 <--findings + log events--
CLI (reads files)  -----------------------function call------------------>  engine/
CLI  <--rule-sets--  hosted API
```

**Exposure (accepted, documented):** FE to API traffic is loopback only and never leaves the machine, but inspection text is still visible in browser devtools and readable by local processes that can observe loopback traffic. I think a production version would need to be its own app with I/O privileges, reading files directly and running the engine in-process, rather than a browser talking to a local API.
