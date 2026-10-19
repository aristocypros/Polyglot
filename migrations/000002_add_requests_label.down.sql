-- Polyglot Postgres Migrations: 000002_add_requests_label.down.sql
-- Removes optional label column from app.requests

ALTER TABLE app.requests DROP COLUMN IF EXISTS label;
