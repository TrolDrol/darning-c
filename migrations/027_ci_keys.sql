CREATE TABLE bank_ci_key (
    id text PRIMARY KEY,
    owner text NOT NULL REFERENCES bank_account(username) ON DELETE CASCADE,
    home_project text NOT NULL REFERENCES bank_project(id) ON DELETE CASCADE,
    organization_id text NOT NULL REFERENCES bank_organization(id) ON DELETE CASCADE,
    label text NOT NULL,
    digest text NOT NULL UNIQUE,
    scopes text[] NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE bank_ci_key_project (
    key_id text NOT NULL REFERENCES bank_ci_key(id) ON DELETE CASCADE,
    project_id text NOT NULL REFERENCES bank_project(id) ON DELETE CASCADE,
    PRIMARY KEY (key_id, project_id)
);
