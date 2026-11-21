-- Automations identify their immutable graph by its content hash. Numeric
-- workflow versions belong to published rule sets.
ALTER TABLE bank_run ALTER COLUMN workflow_version DROP NOT NULL;
ALTER TABLE bank_run ADD CONSTRAINT bank_run_version_source CHECK (
    workflow_version IS NOT NULL OR coalesce(report->>'origin', '') = 'automation'
);
ALTER TABLE bank_run ADD CONSTRAINT bank_run_project_fk
    FOREIGN KEY (project_id) REFERENCES bank_project(id);
