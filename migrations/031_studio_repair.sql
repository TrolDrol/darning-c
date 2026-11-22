ALTER TABLE studio_run ADD COLUMN replay_options TEXT;

CREATE TABLE studio_repair (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES bank_project(id) ON DELETE CASCADE,
    origin_run TEXT NOT NULL,
    state TEXT NOT NULL,
    document TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    next_at BIGINT NOT NULL DEFAULT 0,
    claim TEXT,
    lease_until BIGINT NOT NULL DEFAULT 0
);
CREATE INDEX studio_repair_origin ON studio_repair(project_id,origin_run,created_at DESC);
CREATE INDEX studio_repair_queue ON studio_repair(next_at,lease_until,created_at)
    WHERE state IN ('queued','verifying','notifying','accepting','stopping');
