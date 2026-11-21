CREATE TABLE IF NOT EXISTS studio_node_model (
  project_id TEXT NOT NULL REFERENCES bank_project(id) ON DELETE CASCADE,
  name TEXT NOT NULL, endpoint TEXT NOT NULL, model TEXT NOT NULL,
  key_cipher TEXT NOT NULL DEFAULT '', fingerprint TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (project_id,name)
);
