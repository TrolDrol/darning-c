-- Jobs from older releases carry only a binding ID. Keep their original filters
-- when a manager changes the scope while preserving the repository's identity.
ALTER TABLE bank_github_binding ADD COLUMN legacy_paths jsonb;
