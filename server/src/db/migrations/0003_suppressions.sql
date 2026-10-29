-- A suppression marks one value found by one rule as known to be safe, in one scan session. The
-- value itself is never stored: a scan recognizes it again by its fingerprint, an HMAC-SHA256
-- of the matched value keyed with a local secret that lives in its own file, not in this
-- database (see store::fingerprint_key). A plain hash of a short password could be
-- brute-forced; without the key, a fingerprint says nothing about the value.

CREATE TABLE suppressions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    -- It applies only to later scans in this session.
    scan_session_id INTEGER NOT NULL REFERENCES scan_sessions (id),
    rule_id INTEGER NOT NULL REFERENCES rules (id),
    -- 64 hex characters. A changed value has another fingerprint, so its finding comes back.
    fingerprint TEXT NOT NULL CHECK (length(fingerprint) = 64),
    -- The finding the suppression was made from.
    finding_id INTEGER NOT NULL REFERENCES findings (id),
    reason TEXT NOT NULL CHECK (length(trim(reason)) > 0),
    -- It stops applying at this time. Every suppression has one.
    expires_at TEXT NOT NULL,
    -- Removing a suppression stops it applying but keeps the row, so past scans can still say
    -- why their findings were suppressed.
    removed_at TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX suppressions_scan_session_id ON suppressions (scan_session_id);

-- The match's fingerprint, never its value. Null for rule errors and for findings saved before
-- suppressions existed, which therefore can't be suppressed.
ALTER TABLE findings ADD COLUMN fingerprint TEXT;
-- The suppression that applied when the scan ran, if any. The finding is still saved and
-- counted; it is only marked.
ALTER TABLE findings ADD COLUMN suppression_id INTEGER REFERENCES suppressions (id);
CREATE INDEX findings_suppression_id ON findings (suppression_id);
