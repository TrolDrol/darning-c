"""PostgreSQL workflow history, reports and persistent job leases."""

from contextlib import contextmanager
from datetime import datetime, time, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from issue_store import backfill_issues, record_scan, sync_triage
from run_diagnostics import analysis_diagnostics


MIGRATIONS = Path(__file__).with_name("migrations")
MIGRATION_LOCK = 655703806018258746
DEFAULT_PROJECT = "default"

RUN_SUMMARY = """
    SELECT jsonb_build_object(
        'id', id, 'createdAt', report->'createdAt', 'completedAt', report->'completedAt',
        'updatedAt', updated_at, 'projectId', project_id, 'createdBy', created_by,
        'workflow', report->'workflow', 'source', report->'source', 'revision', report->'revision',
        'status', report->'status', 'skipReason', report->'skipReason', 'origin', report->'origin', 'baselineId', report->'baselineId',
        'lineage', report->'lineage', 'sourceBinding', report->'sourceBinding', 'delivery', report->'delivery',
        'githubCheck', report->'githubCheck', 'event', report->'event', 'gate', report->'gate',
        'findingCount', jsonb_array_length(coalesce(report->'findings', '[]'::jsonb)),
        'highCount', (
            SELECT count(*) FROM jsonb_array_elements(coalesce(report->'findings', '[]'::jsonb)) AS finding
            WHERE finding->>'level' = 'high'
        )
    ) AS summary,
    jsonb_path_query_array(report, '$.coverage[*] ? (@.status == "error")') AS coverage,
    jsonb_path_query_array(report, '$.stages[*] ? (@.status == "error")') AS stages,
    report->>'error' AS error
    FROM bank_run
"""


class JobAlreadyActive(RuntimeError):
    pass


def _summary(row):
    summary = row["summary"]
    count = len(analysis_diagnostics(row | {"status": summary["status"]}))
    return summary | {"diagnosticCount": count}


def _version(row):
    return {
        "number": row["number"],
        "publishedAt": row["published_at"].astimezone(timezone.utc).isoformat(),
        "spec": row["spec"],
    }


def _audit(db, actor, action, subject, project_id):
    if actor is not None:
        db.execute(
            """
            INSERT INTO bank_audit_event (actor, action, subject, organization_id, project_id)
            SELECT %s, %s, %s, organization_id, id FROM bank_project WHERE id = %s
            """,
            (actor, action, subject, project_id),
        )


def initialize_workflow(db, project_id, spec, timestamp):
    db.execute(
        """
        INSERT INTO bank_workflow_version (project_id, number, published_at, spec) VALUES (%s, 1, %s, %s)
        ON CONFLICT (project_id, number) DO NOTHING
        """,
        (project_id, timestamp, Jsonb(spec)),
    )
    db.execute(
        """
        INSERT INTO bank_workflow (project_id, draft, version) VALUES (%s, %s, 1)
        ON CONFLICT (project_id) DO NOTHING
        """,
        (project_id, Jsonb(spec)),
    )


def _insert_job(db, run_id, kind, payload):
    row = db.execute(
        """
        INSERT INTO bank_job (run_id, kind, payload)
        VALUES (%s, %s, %s)
        ON CONFLICT (run_id, kind) WHERE finished_at IS NULL DO NOTHING
        RETURNING id
        """,
        (run_id, kind, Jsonb(payload)),
    ).fetchone()
    if row is None:
        raise JobAlreadyActive(f"Active job already exists for {kind}.")


def _lock_report(db, run_id, project_id=None):
    row = db.execute(
        "SELECT report FROM bank_run WHERE id = %s AND project_id = coalesce(%s, project_id) FOR UPDATE",
        (run_id, project_id),
    ).fetchone()
    return row["report"] if row else None


def _save_report(db, run_id, report):
    db.execute("UPDATE bank_run SET report = %s, updated_at = clock_timestamp() WHERE id = %s", (Jsonb(report), run_id))
    return report


class PostgresStore:
    def __init__(self, dsn, password=None):
        self.dsn = dsn
        self.connection_options = {"password": password} if password is not None else {}

    @contextmanager
    def connect(self):
        with psycopg.connect(self.dsn, row_factory=dict_row, connect_timeout=5, **self.connection_options) as db:
            db.execute("SET LOCAL statement_timeout = '15s'")
            db.execute("SET LOCAL lock_timeout = '5s'")
            yield db

    def ping(self):
        with self.connect() as db:
            return db.execute("SELECT 1 AS ok").fetchone()["ok"] == 1

    def migrate(self):
        migrations = sorted(MIGRATIONS.glob("[0-9][0-9][0-9]_*.sql"))
        if not migrations:
            raise RuntimeError("PostgreSQL migrations are missing.")
        with self.connect() as db:
            db.execute("SELECT pg_advisory_xact_lock(%s)", (MIGRATION_LOCK,))
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS bank_schema_migration (
                    name text PRIMARY KEY,
                    checksum text NOT NULL,
                    applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
                )
                """
            )
            applied = {
                row["name"]: row["checksum"]
                for row in db.execute("SELECT name, checksum FROM bank_schema_migration")
            }
            if applied.keys() - {migration.name for migration in migrations}:
                raise RuntimeError("The PostgreSQL schema is newer than this application.")
            for migration in migrations:
                contents = migration.read_bytes()
                checksum = sha256(contents.replace(b"\r\n", b"\n")).hexdigest()
                if migration.name in applied:
                    if applied[migration.name] != checksum:
                        raise RuntimeError(f"Applied migration has changed: {migration.name}")
                    continue
                db.execute(contents.decode("utf-8"), prepare=False)
                if migration.name == "005_issues.sql":
                    backfill_issues(db)
                if migration.name == "017_graph_run_registry.sql":
                    from case_run_projection import backfill_graph_runs
                    backfill_graph_runs(db)
                db.execute(
                    "INSERT INTO bank_schema_migration (name, checksum) VALUES (%s, %s)",
                    (migration.name, checksum),
                )

    def initialize(self, spec, timestamp, project_id=DEFAULT_PROJECT):
        with self.connect() as db:
            initialize_workflow(db, project_id, spec, timestamp)

    def get_workflow(self, project_id=DEFAULT_PROJECT):
        with self.connect() as db:
            row = db.execute(
                """
                SELECT workflow.draft, v.number, v.published_at, v.spec
                FROM bank_workflow AS workflow
                JOIN bank_workflow_version AS v ON v.project_id = workflow.project_id AND v.number = workflow.version
                WHERE workflow.project_id = %s
                """,
                (project_id,),
            ).fetchone()
            return {"draft": row["draft"], "version": _version(row)} if row else None

    def save_draft(self, spec, actor, project_id=DEFAULT_PROJECT):
        with self.connect() as db:
            updated = db.execute("UPDATE bank_workflow SET draft = %s WHERE project_id = %s", (Jsonb(spec), project_id))
            if not updated.rowcount:
                return None
            _audit(db, actor, "save_draft", "workflow", project_id)
            return spec

    def publish(self, spec, actor, project_id=DEFAULT_PROJECT):
        return self._publish(actor, project_id, spec=spec)

    def set_pull_request_checks(self, enabled, actor, project_id):
        return self._publish(actor, project_id, pull_requests=enabled)

    def _publish(self, actor, project_id, *, spec=None, pull_requests=None):
        with self.connect() as db:
            workflow = db.execute(
                "SELECT version, draft FROM bank_workflow WHERE project_id = %s FOR UPDATE",
                (project_id,),
            ).fetchone()
            if workflow is None:
                return None
            number = workflow["version"]
            version = db.execute(
                "SELECT number, published_at, spec FROM bank_workflow_version WHERE project_id = %s AND number = %s",
                (project_id, number),
            ).fetchone()
            draft = spec
            if pull_requests is not None:
                trigger = "pull_request" if pull_requests else "manual"
                spec = version["spec"] | {"trigger": trigger}
                draft = workflow["draft"] | {"trigger": trigger}
            if spec != version["spec"]:
                version = db.execute(
                    """
                    INSERT INTO bank_workflow_version (project_id, number, spec) VALUES (%s, %s, %s)
                    RETURNING number, published_at, spec
                    """,
                    (project_id, number + 1, Jsonb(spec)),
                ).fetchone()
                _audit(db, actor, "publish", str(version["number"]), project_id)
            db.execute(
                "UPDATE bank_workflow SET draft = %s, version = %s WHERE project_id = %s",
                (Jsonb(draft), version["number"], project_id),
            )
            return _version(version)

    def get_run(self, run_id, project_id=None):
        with self.connect() as db:
            row = db.execute(
                "SELECT report FROM bank_run WHERE id = %s AND project_id = coalesce(%s, project_id)",
                (run_id, project_id),
            ).fetchone()
            return row["report"] if row else None

    def list_runs(self, limit=50, project_id=DEFAULT_PROJECT):
        with self.connect() as db:
            rows = db.execute(
                "SELECT report FROM bank_run WHERE project_id = %s ORDER BY created_at DESC, id DESC LIMIT %s",
                (project_id, limit),
            )
            return [row["report"] for row in rows]

    def list_summaries(self, limit=50, project_id=DEFAULT_PROJECT, created_by=None):
        with self.connect() as db:
            rows = db.execute(
                RUN_SUMMARY + """
                WHERE project_id = %s AND (%s::text IS NULL OR created_by = %s)
                ORDER BY created_at DESC, id DESC LIMIT %s
                """,
                (project_id, created_by, created_by, limit),
            )
            return [_summary(row) for row in rows]

    def list_personal_summaries(self, username, project_ids, limit=100):
        if not project_ids:
            return []
        with self.connect() as db:
            rows = db.execute(
                RUN_SUMMARY + """
                WHERE created_by = %s AND project_id = ANY(%s)
                ORDER BY created_at DESC, id DESC LIMIT %s
                """,
                (username, list(project_ids), limit),
            )
            return [_summary(row) for row in rows]

    def project_analytics(self, project_id=DEFAULT_PROJECT, days=30):
        if not 1 <= days <= 366:
            raise ValueError("Choose an analytics period from 1 to 366 days.")
        today = datetime.now(timezone.utc).date()
        first_day = today - timedelta(days=days - 1)
        since = datetime.combine(first_day, time.min, timezone.utc)
        until = datetime.combine(today + timedelta(days=1), time.min, timezone.utc)
        with self.connect() as db:
            rows = db.execute(
                """
                WITH period AS (
                    SELECT (created_at AT TIME ZONE 'UTC')::date AS day,
                        coalesce(report->>'status', 'unknown') AS status,
                        coalesce(report->'findings', '[]'::jsonb) AS findings
                    FROM bank_run
                    WHERE project_id = %s AND created_at >= %s AND created_at < %s
                )
                SELECT day, status, count(*) AS runs, sum(jsonb_array_length(findings)) AS findings,
                    sum(jsonb_array_length(
                        jsonb_path_query_array(findings, '$[*] ? (@.level == "high")')
                    )) AS high
                FROM period GROUP BY day, status
                """,
                (project_id, since, until),
            ).fetchall()
        sums = {"runs": 0, "findings": 0, "high": 0}
        timeline = {
            first_day + timedelta(days=offset): sums.copy()
            for offset in range(days)
        }
        statuses = {}
        for row in rows:
            statuses[row["status"]] = statuses.get(row["status"], 0) + row["runs"]
            for metric in sums:
                sums[metric] += row[metric]
                timeline[row["day"]][metric] += row[metric]
        return {
            "periodDays": days, "totals": sums, "statuses": statuses,
            "timeline": [{"date": day.isoformat(), **values} for day, values in timeline.items()],
        }

    def list_audit(self, project_id=DEFAULT_PROJECT, limit=100):
        with self.connect() as db:
            rows = db.execute(
                """
                SELECT id, created_at AS "createdAt", actor, action, subject, project_id AS "projectId"
                FROM bank_audit_event WHERE project_id = %s ORDER BY id DESC LIMIT %s
                """,
                (project_id, limit),
            ).fetchall()
        return [row | {"createdAt": row["createdAt"].astimezone(timezone.utc).isoformat()} for row in rows]

    def get_latest_run(self, lineage, statuses=("passed", "review", "partial", "skipped"), exclude_id=None,
                       project_id=DEFAULT_PROJECT):
        with self.connect() as db:
            row = db.execute(
                """
                SELECT report FROM bank_run
                WHERE project_id = %s AND report->>'lineage' = %s AND report->>'status' = ANY(%s)
                    AND id IS DISTINCT FROM %s
                ORDER BY created_at DESC, id DESC LIMIT 1
                """,
                (project_id, lineage, list(statuses), exclude_id),
            ).fetchone()
            return row["report"] if row else None

    def enqueue(self, run, kind, payload, dedupe_key=None, actor=None, project_id=DEFAULT_PROJECT):
        run = run | {"projectId": project_id, "createdBy": actor}
        with self.connect() as db:
            # Conflict and lookup are separate statements for concurrent visibility in READ COMMITTED.
            for _ in range(2):
                inserted = db.execute(
                    """
                    INSERT INTO bank_run (id, project_id, workflow_version, dedupe_key, report, created_by)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT (project_id, dedupe_key) DO NOTHING RETURNING id
                    """,
                    (run["id"], project_id, run["workflow"]["number"], dedupe_key, Jsonb(run), actor),
                ).fetchone()
                if inserted:
                    _insert_job(db, run["id"], kind, payload)
                    _audit(db, actor, "enqueue", run["id"], project_id)
                    return run
                prior = db.execute(
                    "SELECT report FROM bank_run WHERE project_id = %s AND dedupe_key = %s",
                    (project_id, dedupe_key),
                ).fetchone()
                if prior:
                    return prior["report"]
            raise RuntimeError("Concurrent retention prevented enqueuing the run.")

    def claim(self, kinds, lease_seconds):
        with self.connect() as db:
            return db.execute(
                """
                WITH candidate AS (
                    SELECT id FROM bank_job WHERE kind = ANY(%s) AND finished_at IS NULL
                        AND available_at <= clock_timestamp()
                        AND (lease_until IS NULL OR lease_until <= clock_timestamp())
                    ORDER BY available_at, id LIMIT 1 FOR UPDATE SKIP LOCKED
                )
                UPDATE bank_job AS job
                SET lease_token = %s, lease_until = clock_timestamp() + %s, attempt = job.attempt + 1
                FROM candidate WHERE job.id = candidate.id
                RETURNING job.id, job.run_id, job.kind, job.payload, job.attempt, job.lease_token AS token
                """,
                (list(kinds), uuid4(), timedelta(seconds=lease_seconds)),
            ).fetchone()

    def defer(self, job, delay_seconds, report_patch=None):
        with self.connect() as db:
            run_id = job["run_id"]
            report = _lock_report(db, run_id)
            if report is None:
                return False
            result = db.execute(
                """
                UPDATE bank_job SET available_at = clock_timestamp() + %s, lease_token = NULL, lease_until = NULL
                WHERE id = %s AND run_id = %s AND lease_token = %s AND lease_until > clock_timestamp()
                """,
                (timedelta(seconds=delay_seconds), job["id"], run_id, job["token"]),
            )
            if result.rowcount != 1:
                return False
            if report_patch:
                _save_report(db, run_id, report | report_patch)
            return True

    def patch_active(self, job, report_patch):
        with self.connect() as db:
            run_id = job["run_id"]
            report = _lock_report(db, run_id)
            if report is None:
                return None
            active = db.execute(
                """
                SELECT id FROM bank_job WHERE id = %s AND run_id = %s AND lease_token = %s
                    AND lease_until > clock_timestamp()
                FOR UPDATE
                """,
                (job["id"], run_id, job["token"]),
            ).fetchone()
            return _save_report(db, run_id, report | report_patch) if active else None

    def complete(self, job, report_patch, followups=()):
        with self.connect() as db:
            run_id = job["run_id"]
            report = _lock_report(db, run_id)
            if report is None:
                return None
            active = db.execute(
                """
                UPDATE bank_job SET finished_at = clock_timestamp(), payload = NULL,
                    lease_token = NULL, lease_until = NULL
                WHERE id = %s AND run_id = %s AND lease_token = %s AND lease_until > clock_timestamp()
                RETURNING id
                """,
                (job["id"], run_id, job["token"]),
            ).fetchone()
            if active is None:
                return None
            for kind, payload in followups:
                _insert_job(db, run_id, kind, payload)
            amended = report | report_patch
            if job["kind"] == "scan":
                record_scan(db, amended)
            return _save_report(db, run_id, amended)

    def update_run(self, run_id, callback, actor, action, project_id=DEFAULT_PROJECT, *, finding_id=None):
        with self.connect() as db:
            report = _lock_report(db, run_id, project_id)
            if report is None:
                return None
            before = {item["id"]: (item.get("triage"), item.get("triageDecision"))
                      for item in report.get("findings", [])} if action == "finding.triage" else {}
            amended = _save_report(db, run_id, callback(report))
            if before:
                sync_triage(db, before, amended, actor, finding_id)
            _audit(db, actor, action, run_id, project_id)
            return amended

    def requeue(self, run_id, kind, payload, callback, actor, action, project_id=DEFAULT_PROJECT):
        with self.connect() as db:
            report = _lock_report(db, run_id, project_id)
            if report is None:
                return None
            amended = callback(report)
            _insert_job(db, run_id, kind, payload)
            _audit(db, actor, action, run_id, project_id)
            return _save_report(db, run_id, amended)

    def prune(self, report_days=30, job_hours=24):
        job_age = timedelta(hours=job_hours)
        report_age = timedelta(days=report_days)
        with self.connect() as db:
            expired_runs = db.execute(
                """
                SELECT run.id, run.report FROM bank_run AS run
                WHERE EXISTS (
                    SELECT 1 FROM bank_job AS job WHERE job.run_id = run.id AND job.finished_at IS NULL
                        AND job.created_at < clock_timestamp() - %s
                        AND (job.lease_until IS NULL OR job.lease_until <= clock_timestamp())
                )
                ORDER BY run.created_at LIMIT 100 FOR UPDATE OF run SKIP LOCKED
                """,
                (job_age,),
            ).fetchall()
            jobs = 0
            for run in expired_runs:
                expired = db.execute(
                    """
                    UPDATE bank_job SET finished_at = clock_timestamp(), payload = NULL,
                        lease_token = NULL, lease_until = NULL
                    WHERE run_id = %s AND finished_at IS NULL AND created_at < clock_timestamp() - %s
                        AND (lease_until IS NULL OR lease_until <= clock_timestamp())
                    RETURNING kind
                    """,
                    (run["id"], job_age),
                ).fetchall()
                if expired:
                    jobs += len(expired)
                    report = run["report"]
                    for item in expired:
                        _expire_report(report, item["kind"])
                    _save_report(db, run["id"], report)

            old_runs = db.execute(
                """
                SELECT id FROM bank_run AS run
                WHERE run.created_at < clock_timestamp() - %s AND NOT EXISTS (
                    SELECT 1 FROM bank_job AS job WHERE job.run_id = run.id AND job.finished_at IS NULL
                )
                ORDER BY run.created_at LIMIT 500 FOR UPDATE OF run SKIP LOCKED
                """,
                (report_age,),
            ).fetchall()
            reports = db.execute(
                """
                DELETE FROM bank_run AS run WHERE id = ANY(%s) AND NOT EXISTS (
                    SELECT 1 FROM bank_job AS job WHERE job.run_id = run.id AND job.finished_at IS NULL
                )
                """,
                ([row["id"] for row in old_runs],),
            ).rowcount
            events = db.execute(
                """
                DELETE FROM bank_audit_event WHERE id IN (
                    SELECT id FROM bank_audit_event
                    WHERE created_at < clock_timestamp() - %s ORDER BY created_at LIMIT 1000
                    FOR UPDATE SKIP LOCKED
                )
                """,
                (report_age,),
            ).rowcount
            return {"jobs": jobs, "reports": reports, "auditEvents": events}


def _expire_report(report, kind):
    message = "Истёк срок хранения задания."
    if kind == "scan" and report["status"] in ("queued", "running"):
        report.update(status="failed", error=message, completedAt=datetime.now(timezone.utc).isoformat())
    channel = {"smtp": "delivery", "github": "githubCheck"}.get(kind)
    if channel and (delivery := report.get(channel)):
        unknown = delivery["status"] in ("sending", "running")
        delivery.update(
            status="unknown" if unknown else "failed",
            message="Истёк срок задания. Результат отправки неизвестен." if unknown else message,
        )
