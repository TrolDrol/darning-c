CREATE TABLE IF NOT EXISTS studio_event_subscription (
    project_id TEXT NOT NULL REFERENCES bank_project(id) ON DELETE CASCADE,
    automation_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    repository TEXT NOT NULL,
    graph TEXT NOT NULL,
    PRIMARY KEY (project_id, automation_id)
);
CREATE INDEX IF NOT EXISTS studio_event_route ON studio_event_subscription (project_id, kind, repository);
CREATE TABLE IF NOT EXISTS studio_event_receipt (
    project_id TEXT NOT NULL REFERENCES bank_project(id) ON DELETE CASCADE,
    source TEXT NOT NULL,
    delivery TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    result TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (project_id, source, delivery)
);
CREATE INDEX IF NOT EXISTS studio_event_received ON studio_event_receipt (created_at);
