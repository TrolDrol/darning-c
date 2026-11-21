ALTER TABLE bank_github_binding DROP CONSTRAINT bank_github_binding_pkey;
ALTER TABLE bank_github_binding DROP CONSTRAINT bank_github_binding_binding_id_key;
ALTER TABLE bank_github_binding ADD PRIMARY KEY (binding_id);
CREATE UNIQUE INDEX bank_github_binding_project_name
    ON bank_github_binding(project_id, app_id, lower(repository));

ALTER TABLE bank_github_challenge DROP CONSTRAINT bank_github_challenge_pkey;
ALTER TABLE bank_github_challenge DROP CONSTRAINT bank_github_challenge_digest_key;
ALTER TABLE bank_github_challenge ADD PRIMARY KEY (digest);
CREATE UNIQUE INDEX bank_github_challenge_project_name
    ON bank_github_challenge(project_id, app_id, lower(repository));

-- Existing @bound graphs must not change repositories after the first binding is removed.
ALTER TABLE bank_project ADD COLUMN github_default_binding text;
UPDATE bank_project p SET github_default_binding = b.binding_id
FROM bank_github_binding b WHERE b.project_id = p.id;

-- A database binding previously superseded the environment-backed default.
INSERT INTO bank_github_legacy_override(project_id)
SELECT project_id FROM bank_github_binding WHERE project_id = 'default' AND binding_id <> 'legacy'
ON CONFLICT DO NOTHING;
