CREATE TABLE IF NOT EXISTS studio_trigger_pause (
    project_id TEXT NOT NULL REFERENCES bank_project(id) ON DELETE CASCADE,
    automation_id TEXT NOT NULL,
    PRIMARY KEY (project_id, automation_id)
);
