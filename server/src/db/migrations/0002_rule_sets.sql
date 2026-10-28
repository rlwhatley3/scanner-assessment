-- A rule set is a named line of versions, such as "Built-in rules" or "Payments team". Every
-- rule set version belongs to one, and versions are numbered within their set by creation order.

CREATE TABLE rule_sets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL CHECK (length(trim(name)) > 0),
    description TEXT NOT NULL DEFAULT '',
    -- Archived sets are hidden from the list, can't get new versions, and can't start new scan
    -- sessions. Nothing is deleted.
    archived INTEGER NOT NULL DEFAULT 0 CHECK (archived IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- Names tell sets apart, so two can't share one, ignoring case and surrounding space.
CREATE UNIQUE INDEX rule_sets_name ON rule_sets (lower(trim(name)));

-- SQLite can only add a foreign key column whose default is NULL. The store always sets it.
ALTER TABLE rule_set_versions ADD COLUMN rule_set_id INTEGER REFERENCES rule_sets (id);
CREATE INDEX rule_set_versions_rule_set_id ON rule_set_versions (rule_set_id);

-- Versions saved before rule sets existed all join one set, which can be renamed later.
INSERT INTO rule_sets (name, description)
    SELECT 'Built-in rules', 'Versions saved before rule sets existed.'
    WHERE EXISTS (SELECT 1 FROM rule_set_versions);
UPDATE rule_set_versions
    SET rule_set_id = (SELECT MIN(id) FROM rule_sets)
    WHERE rule_set_id IS NULL;
