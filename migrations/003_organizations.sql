CREATE TABLE bank_organization (
    id text PRIMARY KEY,
    name text NOT NULL
);

CREATE TABLE bank_project (
    id text PRIMARY KEY,
    organization_id text NOT NULL REFERENCES bank_organization(id),
    name text NOT NULL,
    UNIQUE (organization_id, id)
);

CREATE TABLE bank_account (
    username text PRIMARY KEY,
    display_name text NOT NULL,
    password_hash text,
    legacy_membership_seeded boolean NOT NULL DEFAULT false
);

CREATE TABLE bank_organization_member (
    organization_id text NOT NULL REFERENCES bank_organization(id),
    username text NOT NULL REFERENCES bank_account(username),
    role text NOT NULL CHECK (role IN ('owner', 'moderator', 'member')),
    PRIMARY KEY (organization_id, username)
);

CREATE INDEX bank_organization_member_user_idx ON bank_organization_member (username, organization_id);

CREATE TABLE bank_project_member (
    project_id text NOT NULL,
    username text NOT NULL,
    organization_id text NOT NULL,
    role text NOT NULL CHECK (role IN ('manager', 'editor', 'reader')),
    PRIMARY KEY (project_id, username),
    FOREIGN KEY (organization_id, project_id) REFERENCES bank_project(organization_id, id),
    FOREIGN KEY (organization_id, username) REFERENCES bank_organization_member(organization_id, username)
        ON DELETE CASCADE
);

CREATE INDEX bank_project_member_org_user_idx ON bank_project_member (organization_id, username);

CREATE TABLE bank_invite (
    id text PRIMARY KEY,
    organization_id text NOT NULL REFERENCES bank_organization(id),
    project_id text,
    organization_role text NOT NULL CHECK (organization_role IN ('owner', 'moderator', 'member')),
    project_role text CHECK (project_role IN ('manager', 'editor', 'reader')),
    token_digest text UNIQUE NOT NULL,
    created_by text NOT NULL REFERENCES bank_account(username),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    accepted_by text REFERENCES bank_account(username),
    accepted_at timestamptz,
    revoked_at timestamptz,
    FOREIGN KEY (organization_id, project_id) REFERENCES bank_project(organization_id, id),
    CHECK ((project_id IS NULL) = (project_role IS NULL)),
    CHECK (project_id IS NULL OR organization_role = 'member'),
    CHECK ((accepted_by IS NULL) = (accepted_at IS NULL)),
    CHECK (accepted_at IS NULL OR revoked_at IS NULL)
);

CREATE INDEX bank_invite_pending_idx ON bank_invite (organization_id, project_id, expires_at)
    WHERE accepted_at IS NULL AND revoked_at IS NULL;
CREATE INDEX bank_invite_expiry_idx ON bank_invite (expires_at);

INSERT INTO bank_organization (id, name) VALUES ('default', 'Рабочее пространство');
INSERT INTO bank_project (id, organization_id, name) VALUES ('default', 'default', 'Основной проект');

ALTER TABLE bank_workflow DROP CONSTRAINT bank_workflow_version_fkey;
ALTER TABLE bank_run DROP CONSTRAINT bank_run_workflow_version_fkey;

ALTER TABLE bank_workflow_version ADD COLUMN project_id text NOT NULL DEFAULT 'default' REFERENCES bank_project(id);
ALTER TABLE bank_workflow_version DROP CONSTRAINT bank_workflow_version_pkey;
ALTER TABLE bank_workflow_version ADD PRIMARY KEY (project_id, number);
ALTER TABLE bank_workflow_version ALTER COLUMN project_id DROP DEFAULT;

ALTER TABLE bank_workflow ADD COLUMN project_id text NOT NULL DEFAULT 'default';
ALTER TABLE bank_workflow DROP COLUMN singleton;
ALTER TABLE bank_workflow ADD PRIMARY KEY (project_id);
ALTER TABLE bank_workflow ADD FOREIGN KEY (project_id, version) REFERENCES bank_workflow_version(project_id, number);
ALTER TABLE bank_workflow ALTER COLUMN project_id DROP DEFAULT;

ALTER TABLE bank_run ADD COLUMN project_id text NOT NULL DEFAULT 'default';
ALTER TABLE bank_run ADD COLUMN created_by text;
ALTER TABLE bank_run ADD FOREIGN KEY (project_id, workflow_version) REFERENCES bank_workflow_version(project_id, number);
ALTER TABLE bank_run DROP CONSTRAINT bank_run_dedupe_key_key;
ALTER TABLE bank_run ADD UNIQUE (project_id, dedupe_key);
ALTER TABLE bank_run ALTER COLUMN project_id DROP DEFAULT;

UPDATE bank_run AS run
SET created_by = event.actor
FROM (
    SELECT DISTINCT ON (subject) subject, actor FROM bank_audit_event
    WHERE action = 'enqueue' ORDER BY subject, id
) AS event
WHERE run.id = event.subject;

UPDATE bank_run SET report = report || jsonb_build_object('projectId', project_id, 'createdBy', created_by);

CREATE INDEX bank_run_project_history_idx ON bank_run (project_id, created_at DESC, id DESC);
DROP INDEX bank_run_lineage_idx;
CREATE INDEX bank_run_project_lineage_idx ON bank_run (project_id, (report->>'lineage'), created_at DESC, id DESC);
CREATE INDEX bank_run_creator_history_idx ON bank_run (created_by, created_at DESC, id DESC) WHERE created_by IS NOT NULL;

ALTER TABLE bank_audit_event ADD COLUMN organization_id text NOT NULL DEFAULT 'default' REFERENCES bank_organization(id);
ALTER TABLE bank_audit_event ADD COLUMN project_id text DEFAULT 'default';
ALTER TABLE bank_audit_event ADD FOREIGN KEY (organization_id, project_id) REFERENCES bank_project(organization_id, id);
ALTER TABLE bank_audit_event ALTER COLUMN organization_id DROP DEFAULT;
ALTER TABLE bank_audit_event ALTER COLUMN project_id DROP DEFAULT;

CREATE INDEX bank_audit_project_history_idx ON bank_audit_event (project_id, id DESC);
