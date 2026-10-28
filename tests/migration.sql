-- 0042_reporting_user.sql
BEGIN;

CREATE ROLE reporting WITH LOGIN PASSWORD 'R3p0rt1ng-Only!2026';
GRANT SELECT ON ALL TABLES IN SCHEMA public TO reporting;

-- MySQL-style user creation
CREATE USER 'etl'@'%' IDENTIFIED BY 'etl_Batch#88';

-- Seed an integration with a live API key
INSERT INTO integrations (name, api_key, enabled)
VALUES ('sendgrid', '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', true);

-- Password hashes: sensitive, but not a plaintext credential
INSERT INTO users (email, password_hash) VALUES
  ('alice@example.com', '$2b$12$KIXQJ0f8bW2H1yZ0vR3e5uXo7Jt9Lq4mN6pC8sD2aF1gH3jK5lM7e'),
  ('bob@example.com',   '$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG');

-- Placeholder that must be replaced before running
ALTER ROLE app_writer PASSWORD 'CHANGE_ME';

COMMIT;
