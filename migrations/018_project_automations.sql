CREATE TABLE studio_automation (
    project_id TEXT NOT NULL REFERENCES bank_project(id) ON DELETE CASCADE,
    id TEXT NOT NULL,
    name TEXT NOT NULL,
    graph TEXT NOT NULL,
    scheduled_graph TEXT,
    schedule_time TEXT,
    scheduled_at BIGINT,
    PRIMARY KEY (project_id, id)
);
CREATE INDEX studio_automation_schedule ON studio_automation(project_id) WHERE schedule_time IS NOT NULL;
ALTER TABLE studio_run ADD COLUMN automation_id TEXT NOT NULL DEFAULT 'default';
CREATE INDEX studio_run_automation ON studio_run(project_id,automation_id,created_at);
