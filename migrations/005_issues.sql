CREATE TABLE bank_issue (
    id text PRIMARY KEY,
    project_id text NOT NULL REFERENCES bank_project(id),
    lineage text NOT NULL,
    rule_id text NOT NULL,
    file_path text NOT NULL,
    fingerprint text NOT NULL,
    level text NOT NULL,
    title text NOT NULL,
    line integer,
    occurrences integer NOT NULL,
    first_seen timestamptz NOT NULL,
    last_seen timestamptz NOT NULL,
    last_run text NOT NULL,
    state text NOT NULL CHECK (state IN ('open', 'fixed')),
    state_at timestamptz NOT NULL,
    state_run text NOT NULL,
    is_new boolean NOT NULL,
    assignee text REFERENCES bank_account(username),
    triage text NOT NULL DEFAULT 'open' CHECK (triage IN ('open', 'accepted', 'false_positive')),
    decision jsonb,
    UNIQUE (project_id, lineage, rule_id, file_path, fingerprint)
);
CREATE INDEX bank_issue_queue ON bank_issue (project_id, state, last_seen DESC, id);
CREATE INDEX bank_issue_assigned ON bank_issue (assignee, project_id) WHERE state = 'open';

CREATE TABLE bank_issue_event (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    issue_id text NOT NULL REFERENCES bank_issue(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL,
    action text NOT NULL,
    run_id text,
    actor text,
    details jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX bank_issue_history ON bank_issue_event (issue_id, created_at DESC, id DESC);

-- Last complete check of each rule/file. A slow older scan cannot reopen issues
-- that a more recent completed scan already proved absent.
CREATE TABLE bank_issue_coverage (
    project_id text NOT NULL REFERENCES bank_project(id),
    lineage text NOT NULL,
    rule_id text NOT NULL,
    file_path text NOT NULL,
    scanned_at timestamptz NOT NULL,
    run_id text NOT NULL,
    PRIMARY KEY (project_id, lineage, rule_id, file_path)
);
