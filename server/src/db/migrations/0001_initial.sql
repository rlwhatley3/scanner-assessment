-- Inspection text, matched values, and input hashes are never stored.

CREATE TABLE rule_set_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    parent_id INTEGER REFERENCES rule_set_versions (id),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    archived INTEGER NOT NULL DEFAULT 0 CHECK (archived IN (0, 1)),
    -- Canonical JSON: an array of known placeholder values, and an array of rules.
    placeholders TEXT NOT NULL,
    rules TEXT NOT NULL
);

-- The one editable copy of the rule set, where edits and draft rules live until they are
-- applied as a new rule set version. Rules here may carry "draft": true; drafts are not
-- validated, and applying clears the flag, so saved versions never contain drafts.
CREATE TABLE rule_set_working_copy (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    base_version_id INTEGER REFERENCES rule_set_versions (id),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    placeholders TEXT NOT NULL,
    rules TEXT NOT NULL
);

-- Allocates rule ids. AUTOINCREMENT never reuses an id, even after its row is deleted.
CREATE TABLE rule_ids (
    id INTEGER PRIMARY KEY AUTOINCREMENT
);

CREATE TABLE scan_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- Cancelled and errored scans have no results, so they are not stored.
CREATE TABLE inspections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_session_id INTEGER NOT NULL REFERENCES scan_sessions (id),
    rule_set_version_id INTEGER NOT NULL REFERENCES rule_set_versions (id),
    log_id TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    outcome TEXT NOT NULL CHECK (outcome IN ('findings', 'clean', 'partial')),
    truncated INTEGER NOT NULL DEFAULT 0 CHECK (truncated IN (0, 1))
);

CREATE INDEX inspections_scan_session_id ON inspections (scan_session_id);
CREATE INDEX inspections_rule_set_version_id ON inspections (rule_set_version_id);

CREATE TABLE findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    inspection_id INTEGER NOT NULL REFERENCES inspections (id),
    rule_id INTEGER NOT NULL,
    rule_name TEXT NOT NULL,
    detection_type TEXT NOT NULL
        CHECK (detection_type IN ('direct_credential', 'likely_credential', 'unsafe_handling')),
    severity TEXT NOT NULL CHECK (severity IN ('high', 'medium', 'low')),
    confidence INTEGER NOT NULL CHECK (confidence BETWEEN 0 AND 100),
    -- Absent for unsafe handling findings, which point at a pattern rather than a value.
    placeholder_score INTEGER CHECK (placeholder_score BETWEEN 0 AND 100),
    start_line INTEGER NOT NULL,
    start_column INTEGER NOT NULL,
    end_line INTEGER NOT NULL,
    end_column INTEGER NOT NULL,
    start_byte INTEGER NOT NULL,
    end_byte INTEGER NOT NULL,
    -- Taken from the rule's declared prefix, never from the match.
    redacted_preview TEXT,
    why_flagged TEXT NOT NULL,
    remediation TEXT NOT NULL
);

CREATE INDEX findings_inspection_id ON findings (inspection_id);

CREATE TABLE rule_errors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    inspection_id INTEGER NOT NULL REFERENCES inspections (id),
    rule_id INTEGER NOT NULL,
    -- A missing name is itself a rule error.
    rule_name TEXT,
    -- The rule field the error belongs to, so a reopened session can point at it.
    field TEXT NOT NULL CHECK (field IN (
        'name', 'enabled', 'detection_type', 'severity', 'pattern',
        'prefix', 'key_names', 'min_entropy', 'remediation'
    )),
    code TEXT NOT NULL CHECK (code IN (
        'required', 'invalid_regex', 'too_large', 'out_of_range', 'duplicate_name'
    )),
    message TEXT NOT NULL,
    -- Byte range within the field's value (e.g. the bad spot in a pattern), when known.
    span_start INTEGER,
    span_end INTEGER,
    CHECK ((span_start IS NULL) = (span_end IS NULL)),
    CHECK (span_start IS NULL OR span_start <= span_end)
);

CREATE INDEX rule_errors_inspection_id ON rule_errors (inspection_id);
