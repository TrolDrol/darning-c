-- Keep the source of historical issues after individual reports expire or a binding is removed.
CREATE TABLE bank_repository_source (
    project_id text NOT NULL REFERENCES bank_project(id) ON DELETE CASCADE,
    lineage text NOT NULL,
    repository text NOT NULL,
    PRIMARY KEY (project_id, lineage)
);
CREATE INDEX bank_repository_source_name ON bank_repository_source (project_id, lower(repository));

CREATE FUNCTION bank_report_repository(doc jsonb) RETURNS text
LANGUAGE sql IMMUTABLE AS $$
    SELECT coalesce(nullif(doc->'event'->>'repository',''), nullif(doc->'githubTrial'->>'repository',''),
        CASE WHEN doc->>'lineage' LIKE 'github-read:%' THEN substr(doc->>'lineage',13)
             WHEN doc->>'lineage' LIKE 'github:%' THEN split_part(doc->>'source', ' · ', 1) END)
$$;

INSERT INTO bank_repository_source(project_id,lineage,repository)
SELECT DISTINCT ON (project_id, report->>'lineage') project_id, report->>'lineage', bank_report_repository(report)
FROM bank_run WHERE report->>'lineage' IS NOT NULL AND bank_report_repository(report) IS NOT NULL
ORDER BY project_id, report->>'lineage', created_at DESC, id DESC;

INSERT INTO bank_repository_source(project_id,lineage,repository)
SELECT DISTINCT i.project_id, i.lineage, coalesce(b.repository, substr(i.lineage,13))
FROM bank_issue i LEFT JOIN bank_github_binding b
  ON b.project_id=i.project_id AND i.lineage LIKE 'github:' || b.repository_id || ':%'
WHERE b.repository IS NOT NULL OR i.lineage LIKE 'github-read:%'
ON CONFLICT DO NOTHING;

CREATE FUNCTION bank_remember_repository() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE repo text := bank_report_repository(NEW.report);
BEGIN
    IF repo IS NOT NULL AND NEW.report->>'lineage' IS NOT NULL THEN
        INSERT INTO bank_repository_source(project_id,lineage,repository)
        VALUES (NEW.project_id, NEW.report->>'lineage',repo)
        ON CONFLICT (project_id,lineage) DO UPDATE SET repository=EXCLUDED.repository
        WHERE bank_repository_source.repository IS DISTINCT FROM EXCLUDED.repository;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER bank_run_remember_repository AFTER INSERT ON bank_run
FOR EACH ROW EXECUTE FUNCTION bank_remember_repository();
