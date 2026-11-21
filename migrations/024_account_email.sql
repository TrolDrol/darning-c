CREATE TABLE bank_account_email (
    username text PRIMARY KEY REFERENCES bank_account(username) ON DELETE CASCADE,
    verified_email text,
    pending_email text,
    requested_at timestamptz,
    expires_at timestamptz,
    state text CHECK (state IN ('queued','sent','failed')),
    digest text,
    attempts integer NOT NULL DEFAULT 0
);
CREATE INDEX bank_account_email_queue ON bank_account_email(requested_at) WHERE state='queued';
