CREATE TABLE bank_project_smtp_recipient (
    project_id text PRIMARY KEY REFERENCES bank_project(id) ON DELETE CASCADE,
    username text NOT NULL REFERENCES bank_account(username) ON DELETE CASCADE
);
