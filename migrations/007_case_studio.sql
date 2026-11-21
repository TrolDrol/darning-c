CREATE TABLE IF NOT EXISTS studio_graph (
    project_id TEXT PRIMARY KEY REFERENCES bank_project(id) ON DELETE CASCADE,
    graph TEXT NOT NULL, saved_at BIGINT NOT NULL, schedule_time TEXT
);
CREATE TABLE IF NOT EXISTS studio_template (
    id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, name TEXT NOT NULL,
    description TEXT NOT NULL, graph TEXT NOT NULL, created_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS studio_run (
    id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES bank_project(id) ON DELETE CASCADE,
    status TEXT NOT NULL, graph TEXT NOT NULL, payload TEXT, report TEXT NOT NULL,
    created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS studio_run_queue ON studio_run(status,created_at);
CREATE INDEX IF NOT EXISTS studio_run_project ON studio_run(project_id,created_at);
