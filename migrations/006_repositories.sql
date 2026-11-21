CREATE TABLE bank_github_binding (
    project_id text PRIMARY KEY REFERENCES bank_project(id) ON DELETE CASCADE,
    binding_id text NOT NULL UNIQUE,
    app_id bigint NOT NULL,
    installation_id bigint NOT NULL,
    repository_id bigint NOT NULL,
    repository text NOT NULL,
    python_path text NOT NULL,
    config_path text NOT NULL,
    verified_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (app_id, repository_id)
);

CREATE TABLE bank_github_challenge (
    project_id text PRIMARY KEY REFERENCES bank_project(id) ON DELETE CASCADE,
    digest text NOT NULL UNIQUE,
    app_id bigint NOT NULL,
    repository text NOT NULL,
    python_path text NOT NULL,
    config_path text NOT NULL,
    actor text NOT NULL REFERENCES bank_account(username),
    expires_at timestamptz NOT NULL DEFAULT clock_timestamp() + interval '1 hour'
);

CREATE TABLE bank_github_legacy_override (
    project_id text PRIMARY KEY REFERENCES bank_project(id) ON DELETE CASCADE
);
