-- Polyglot Postgres Migrations: 000002_add_requests_label.up.sql
-- Adds optional label column to app.requests for create_wallet requests

ALTER TABLE app.requests ADD COLUMN IF NOT EXISTS label TEXT DEFAULT '';
