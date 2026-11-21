CREATE TABLE studio_shared_template (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    graph TEXT NOT NULL,
    created_at BIGINT NOT NULL
);
CREATE INDEX studio_shared_template_recent ON studio_shared_template(created_at, id);
ALTER TABLE studio_automation ADD COLUMN schedule_hold INTEGER NOT NULL DEFAULT 0;
