-- What each rule cost a scan, so a rule that slows scans can be named after the scan is done: a
-- JSON array of {ruleId, ruleName, micros, matches, floods}, one entry per rule that ran. Empty
-- for scans that didn't finish and scans from before this migration.
ALTER TABLE scans ADD COLUMN rule_timings TEXT NOT NULL DEFAULT '[]';

-- The scanned text's length in bytes, never the text itself, so a rule's match count can be read
-- as how often it matched. Null for scans from before this migration.
ALTER TABLE scans ADD COLUMN text_bytes INTEGER;
