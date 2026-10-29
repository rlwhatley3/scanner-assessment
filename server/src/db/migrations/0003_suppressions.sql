-- A suppression marks one value found by one rule as known to be safe, in one scan session: later
-- scans in that session don't report it. The value itself is never stored: a scan recognizes it
-- by its fingerprint, a slow Argon2id hash of the matched value keyed with a local secret that
-- lives in its own file, not in this database (see crate::fingerprint_key). A plain hash of a
-- short password could be brute-forced. Without the key, a fingerprint says nothing about the
-- value; with it, each guess still costs milliseconds and megabytes.

CREATE TABLE suppressions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    -- It applies only to later scans in this session.
    scan_session_id INTEGER NOT NULL REFERENCES scan_sessions (id),
    rule_id INTEGER NOT NULL REFERENCES rules (id),
    -- 64 hex characters. A changed value has another fingerprint, so it is reported again.
    fingerprint TEXT NOT NULL CHECK (length(fingerprint) = 64),
    -- The finding the suppression was made from.
    finding_id INTEGER NOT NULL REFERENCES findings (id),
    reason TEXT NOT NULL CHECK (length(trim(reason)) > 0),
    -- It stops applying at this time, and the value is reported again. Every suppression has one.
    expires_at TEXT NOT NULL,
    -- Removing a suppression stops it applying but keeps the row, as a record of what was
    -- suppressed, why, and until when.
    removed_at TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX suppressions_scan_session_id ON suppressions (scan_session_id);

-- The match's fingerprint, never its value, so a suppression can be made from the finding. Null
-- for rule errors and for findings saved before suppressions existed, which can't be suppressed.
ALTER TABLE findings ADD COLUMN fingerprint TEXT;
-- Matches an active suppression covered, so they were neither saved nor returned. Only the
-- number is kept, so a scan can say that something was left out.
ALTER TABLE scans ADD COLUMN suppressed_count INTEGER NOT NULL DEFAULT 0;
