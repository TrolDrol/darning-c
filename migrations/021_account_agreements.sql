CREATE TABLE bank_account_agreement (
    username TEXT NOT NULL REFERENCES bank_account(username) ON DELETE CASCADE,
    document TEXT NOT NULL,
    version TEXT NOT NULL,
    accepted_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (username, document, version)
);
