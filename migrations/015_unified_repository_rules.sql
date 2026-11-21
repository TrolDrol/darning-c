-- Give the unchanged release preset a new published version. Saved run snapshots
-- and manually selected policies keep the checks that were configured for them.
WITH original AS (
    SELECT w.project_id, w.version, v.spec
    FROM bank_workflow w
    JOIN bank_workflow_version v ON v.project_id = w.project_id AND v.number = w.version
    WHERE w.version IN (1, 2) AND w.draft = v.spec AND v.spec = '{
        "name":"Проверка сервиса перед релизом","rules":["PY-001","PY-002","PY-003","CFG-001","CFG-002"],
        "trigger":"manual","explain":true,"delivery":true,"minimum":"high",
        "recipient":"Команда сервиса","deliveryChannel":"local"
    }'::jsonb
    FOR UPDATE OF w
), published AS (
    INSERT INTO bank_workflow_version (project_id, number, spec)
    SELECT project_id, version + 1, jsonb_set(spec, '{rules}', (spec->'rules') || '["SEC-001","KT-001","DEP-001"]'::jsonb)
    FROM original RETURNING project_id, number, spec
), activated AS (
    UPDATE bank_workflow w SET version = p.number, draft = p.spec
    FROM published p WHERE w.project_id = p.project_id RETURNING w.project_id, w.version
)
INSERT INTO bank_audit_event (actor, action, subject, organization_id, project_id)
SELECT 'Штопка', 'publish', a.version::text, p.organization_id, p.id
FROM activated a JOIN bank_project p ON p.id = a.project_id;
