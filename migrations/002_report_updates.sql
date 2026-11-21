ALTER TABLE bank_run ADD COLUMN updated_at timestamptz NOT NULL DEFAULT clock_timestamp();
