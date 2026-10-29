-- Whether a scan finished. A scan's row is saved before the engine runs, so its id can tag the
-- engine's log events, and its findings are saved when the engine is done. If the request ends
-- first (the caller cancels, reloads, or disconnects, or the server stops), the findings are never
-- saved. Without a status, that scan would read as one that ran and found nothing.
--   running: the engine hasn't finished, or the scan was cut off and not yet marked.
--   completed: the findings are saved. Only a completed scan with no findings is clean.
--   interrupted: the scan ended before its findings were saved, so they are missing.
ALTER TABLE scans ADD COLUMN status TEXT NOT NULL DEFAULT 'completed'
    CHECK (status IN ('running', 'completed', 'interrupted'));

-- Scans cut off before this migration: no findings, nothing suppressed, and never updated after
-- the row was made. Saving a scan's results always updates it, even when there are none.
UPDATE scans SET status = 'interrupted'
WHERE suppressed_count = 0
  AND updated_at = created_at
  AND NOT EXISTS (SELECT 1 FROM findings f WHERE f.scan_id = scans.id);
