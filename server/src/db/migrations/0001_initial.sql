-- Scan text is never stored.
-- Every table carries created_at and updated_at; the app sets updated_at when it writes a row.

CREATE TABLE rule_set_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    parent_id INTEGER REFERENCES rule_set_versions (id),
    -- Archived versions are hidden from the version timeline, not deleted.
    archived INTEGER NOT NULL DEFAULT 0 CHECK (archived IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- A rule exists on its own, with one id for life. It joins rule set versions through
-- rule_set_version_rules, so the same rule can appear in many versions, or in none yet.
CREATE TABLE rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    -- Name, pattern, severity, and the other rule fields, filled in from the rule form.
    -- A new draft starts empty.
    definition TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(definition)),
    -- New rules start as drafts; drafts are not validated until drafting is cleared.
    drafting INTEGER NOT NULL DEFAULT 1 CHECK (drafting IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- Adding a rule into a version creates one of these rows.
CREATE TABLE rule_set_version_rules (
    rule_set_version_id INTEGER NOT NULL REFERENCES rule_set_versions (id),
    rule_id INTEGER NOT NULL REFERENCES rules (id),
    -- The rule's definition as it was when added, so the version keeps what it scanned with
    -- even if the rule is edited later.
    definition TEXT NOT NULL CHECK (json_valid(definition)),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (rule_set_version_id, rule_id)
);

CREATE INDEX rule_set_version_rules_rule_id ON rule_set_version_rules (rule_id);

CREATE TABLE scan_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_set_version_id INTEGER NOT NULL REFERENCES rule_set_versions (id),
    -- Null until the session's first scan runs.
    last_ran TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_session_id INTEGER NOT NULL REFERENCES scan_sessions (id),
    -- True when the scan found more than the 200-finding cap and the rest were not saved.
    truncated INTEGER NOT NULL DEFAULT 0 CHECK (truncated IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX scans_scan_session_id ON scans (scan_session_id);

CREATE TABLE findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans (id),
    -- The rule this finding is about.
    rule_id INTEGER NOT NULL REFERENCES rules (id),
    -- 'match': the rule found something in the text.
    -- 'rule_error': the rule could not run (e.g. its pattern does not compile), which makes
    -- the scan partial.
    kind TEXT NOT NULL CHECK (kind IN ('match', 'rule_error')),
    -- Machine-readable details of the violation.
    violation TEXT NOT NULL CHECK (json_valid(violation)),
    -- Human-readable summary of the same violation.
    violation_pretty TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX findings_scan_id ON findings (scan_id);
CREATE INDEX findings_rule_id ON findings (rule_id);
