CREATE TABLE IF NOT EXISTS studio_tg_pair (
    project_id TEXT PRIMARY KEY, username TEXT NOT NULL, digest TEXT NOT NULL UNIQUE,
    expires BIGINT NOT NULL, chat_id BIGINT, confirm_digest TEXT, attempts INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS studio_tg_chat (
    project_id TEXT PRIMARY KEY, username TEXT NOT NULL, chat_id BIGINT NOT NULL, binding TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS studio_tg_notice (
    id TEXT PRIMARY KEY, project_id TEXT NOT NULL, run_id TEXT NOT NULL REFERENCES studio_run(id) ON DELETE CASCADE,
    binding TEXT NOT NULL, source TEXT NOT NULL, ordinal INTEGER NOT NULL, finding TEXT NOT NULL, fingerprint TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'open', result TEXT NOT NULL DEFAULT '', updated_at BIGINT NOT NULL,
    UNIQUE(project_id,run_id,binding,ordinal)
);
CREATE INDEX IF NOT EXISTS studio_tg_pending ON studio_tg_notice(state,updated_at);
CREATE TABLE IF NOT EXISTS studio_tg_decision (
    project_id TEXT NOT NULL, source_key TEXT NOT NULL, fingerprint TEXT NOT NULL,
    username TEXT NOT NULL, updated_at BIGINT NOT NULL,
    PRIMARY KEY(project_id,source_key,fingerprint)
);
