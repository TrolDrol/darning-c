CREATE TABLE IF NOT EXISTS studio_model (
  project_id TEXT PRIMARY KEY REFERENCES bank_project(id) ON DELETE CASCADE,
  endpoint TEXT NOT NULL, model TEXT NOT NULL, key_cipher TEXT NOT NULL DEFAULT ''
);
