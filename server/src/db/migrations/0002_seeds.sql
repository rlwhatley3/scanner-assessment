-- Built-in data applied once per database file (see db::Db::seed). A row here means that seed
-- has run, so deleting or archiving what it created never brings it back.

CREATE TABLE seeds (
    name TEXT PRIMARY KEY,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
