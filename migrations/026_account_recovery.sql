ALTER TABLE bank_account
    ADD COLUMN session_generation bigint NOT NULL DEFAULT 0,
    ADD COLUMN deleted_at timestamptz,
    ADD COLUMN recovery_digest text,
    ADD COLUMN recovery_expires timestamptz,
    ADD COLUMN recovery_recipient text,
    ADD COLUMN recovery_requested timestamptz,
    ADD COLUMN recovery_queued boolean NOT NULL DEFAULT false;
CREATE UNIQUE INDEX bank_recovery_token ON bank_account(recovery_digest) WHERE recovery_digest IS NOT NULL;
CREATE INDEX bank_recovery_queue ON bank_account(recovery_requested) WHERE recovery_queued;
CREATE TABLE bank_account_admin_event (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    created_at timestamptz NOT NULL DEFAULT now(),
    actor text NOT NULL,
    action text NOT NULL,
    subject text NOT NULL
);
