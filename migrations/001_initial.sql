CREATE TABLE bank_workflow_version (
    number bigint PRIMARY KEY CHECK (number > 0),
    published_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    spec jsonb NOT NULL CHECK (jsonb_typeof(spec) = 'object')
);

CREATE TABLE bank_workflow (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    draft jsonb NOT NULL CHECK (jsonb_typeof(draft) = 'object'),
    version bigint NOT NULL REFERENCES bank_workflow_version(number)
);

CREATE TABLE bank_run (
    id text PRIMARY KEY,
    workflow_version bigint NOT NULL REFERENCES bank_workflow_version(number),
    dedupe_key text UNIQUE,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    report jsonb NOT NULL CHECK (jsonb_typeof(report) = 'object')
);

CREATE INDEX bank_run_history_idx ON bank_run (created_at DESC, id DESC);
CREATE INDEX bank_run_lineage_idx ON bank_run ((report->>'lineage'), created_at DESC, id DESC);

CREATE TABLE bank_job (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    run_id text NOT NULL REFERENCES bank_run(id) ON DELETE CASCADE,
    kind text NOT NULL,
    payload jsonb,
    attempt integer NOT NULL DEFAULT 0 CHECK (attempt >= 0),
    lease_token uuid,
    lease_until timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    available_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    finished_at timestamptz,
    CHECK ((lease_token IS NULL) = (lease_until IS NULL)),
    CHECK ((finished_at IS NULL) = (payload IS NOT NULL)),
    CHECK (finished_at IS NULL OR lease_token IS NULL)
);

CREATE UNIQUE INDEX bank_job_active_idx ON bank_job (run_id, kind) WHERE finished_at IS NULL;
CREATE INDEX bank_job_claim_idx ON bank_job (kind, available_at, id) WHERE finished_at IS NULL;
CREATE INDEX bank_job_expiry_idx ON bank_job (created_at, run_id) WHERE finished_at IS NULL;
CREATE INDEX bank_job_run_idx ON bank_job (run_id);

CREATE TABLE bank_audit_event (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    actor text NOT NULL,
    action text NOT NULL,
    subject text NOT NULL
);

CREATE INDEX bank_audit_expiry_idx ON bank_audit_event (created_at);
