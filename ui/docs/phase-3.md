The team has started relying on your scanner and is bringing a larger codebase into the workflow. They also want to run scans from a command line and in automated checks. The new reports below arrive while the product is already in use.

### Findings are difficult to trust

- Documentation, examples, generated files, and test fixtures produce false positives. Real credentials with unusual formatting are missed. Several rules can report the same or overlapping text.
- Developers want to suppress known-safe findings. A suppression can become too broad, outlive the example it was written for, or hide a real credential after code changes.
- A finding can move or disappear while someone is reviewing it. Unicode, mixed newline styles, long lines, and edits during a scan make its file and range unreliable.
- Rule authors need useful diagnostics for invalid or expensive patterns, but a single broken rule must not make the rest of a scan's results misleading.

### Scans and repositories change underneath you

- A newer scan can finish before an older one and then be replaced by stale results. Inputs, rules, or options may change while a scan is running.
- Users navigate away, reload, cancel, or start another scan while work is pending. Some scans fail after processing only part of the repository, and the UI does not make it clear what was or was not scanned.
- Repositories can be large or actively changing. Files may be added, removed, renamed, or edited mid-scan. Some are unreadable, binary, generated, extremely large, or contain unusually long lines.
- Symbolic links can loop or point outside the selected repository. File paths can contain Unicode or characters that have special meaning in shells and output formats.
- Repeat scans are becoming slow. Cached or incremental results can be wrong after a file, rule, ignore setting, or suppression changes.

### Remediation has consequences

- Developers want to fix findings from the results view, but the source may have changed since the scan. A suggested edit can conflict with local work, overlap another finding, or target the wrong occurrence.
- Some findings can be safely handled automatically; others require review. Teams disagree about when a proposed fix is safe, how to preview it, and what to do when only part of a remediation succeeds.
- A user may cancel or lose connection while remediation is underway. The displayed results, source, and reported remediation status can end up describing different states.

### Automation needs a stable contract

- CLI and CI users need predictable behavior for no findings, many findings, invalid rules, unreadable files, partial scans, cancellation, and internal errors.
- Output is consumed by both people and scripts. A formatting change can break automation, while verbose diagnostics can expose sensitive values.
- Repeated runs may execute concurrently with different inputs or rule versions. Results and exit status must still make sense to their callers.

### Scanned content must stay safe

- Real credentials can appear in findings, errors, debug logs, temporary files, or caches after a failure.
- Scanning must remain local to the application. Large or interrupted scans should not leave behind confusing state or unexpectedly retained source content.

Decide what to address first, what behavior users should see, and what guarantees your design can actually provide. Make the remaining limitations and trade-offs visible in your submission.
