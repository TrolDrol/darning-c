"""Project-scoped issue identities, observations and team decisions."""

from collections import defaultdict
from datetime import date, timedelta
from hashlib import sha256
import json

from psycopg.types.json import Jsonb

from analyzers import REPOSITORY_RULE_ID, REPORT_RULES as RULES, repository_paths_checked
from workspace import WorkspaceError, now


TERMINAL = {"review", "passed", "partial", "skipped"}
FIELDS = """id, project_id AS "projectId", lineage, rule_id AS "ruleId", file_path AS file,
    fingerprint, level, title, line, occurrences, state, triage, decision AS "triageDecision", assignee,
    first_seen AS "firstSeenAt", last_seen AS "lastSeenAt", last_run AS "lastRunId",
    state_run AS "stateRunId", is_new AS "isNew" """
SEVERITY_ORDER = "CASE level WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC"
FILTERS = {"open": "state='open'", "all": "true", "fixed": "state='fixed'",
           "priority": "state='open' AND level IN ('high','critical') AND is_new AND (triage='open' OR (decision->>'expiresAt')::date<CURRENT_DATE)",
           "new": "state='open' AND is_new", "high": "state='open' AND level IN ('high','critical')",
           "review": "state='open' AND (decision->>'expiresAt')::date <= CURRENT_DATE",
           "mine": "state='open' AND assignee=%s"}
CANDIDATES = """
    SELECT a.username, a.display_name AS "displayName" FROM bank_project p
    JOIN bank_organization_member o ON o.organization_id=p.organization_id
    JOIN bank_account a ON a.username=o.username
    LEFT JOIN bank_project_member m ON m.project_id=p.id AND m.username=o.username
    WHERE p.id=%s AND (o.role='owner' OR m.role IS NOT NULL)
"""


def issue_key(project_id, lineage, finding):
    parts = [project_id, lineage, finding.get("ruleId"), finding.get("file"), finding.get("fingerprint")]
    if all(isinstance(part, str) and part for part in parts):
        return sha256(json.dumps(parts, ensure_ascii=False).encode()).hexdigest()[:32]
    return None


def _event(db, issue_id, action, when, run=None, actor=None, **details):
    db.execute(
        """INSERT INTO bank_issue_event(issue_id,action,created_at,run_id,actor,details)
           VALUES (%s,%s,%s,%s,%s,%s)""", (issue_id, action, when, run, actor, Jsonb(details)))


def _lock_scope(db, project):
    db.execute("SELECT id FROM bank_project WHERE id=%s FOR UPDATE", (project,))


def _capture_decision(db, project, issue_id, status, decision, actor, run=None):
    changed = db.execute(
        """UPDATE bank_issue SET triage=%s, decision=%s WHERE id=%s AND project_id=%s
           AND (triage IS DISTINCT FROM %s OR decision IS DISTINCT FROM %s)""",
        (status, Jsonb(decision) if decision else None, issue_id, project, status, Jsonb(decision) if decision else None))
    if changed.rowcount:
        _event(db, issue_id, "triage", (decision or {}).get("at") or now(), run, actor, status=status, decision=decision)


def record_scan(db, report, backfill=False):
    project, lineage, run = report.get("projectId"), report.get("lineage"), report["id"]
    if not project or not lineage or report.get("workflow", {}).get("preview") or report.get("status") not in TERMINAL:
        return
    _lock_scope(db, project)
    when = db.execute("SELECT created_at FROM bank_run WHERE id=%s", (run,)).fetchone()["created_at"]
    order = (when, run)
    by_id = defaultdict(list)
    for finding in report.get("findings", []):
        key = issue_key(project, lineage, finding)
        if key:
            finding["issueId"] = key
            by_id[key].append(finding)
    rules = report["workflow"].get("spec", {}).get("rules", [])
    covered = {(rule, item["file"]) for item in report.get("coverage", []) if item.get("status") == "done"
               for rule in rules if RULES.get(rule, {}).get("engine") == item.get("engine")}
    if report["status"] == "partial":
        covered.clear()
    # This scope covers names across one identified Git repository. Separate
    # uploads can share the "custom" lineage, so the same inference is unsafe there.
    all_paths = (REPOSITORY_RULE_ID, "")
    if lineage.startswith(("github:", "github-read:")) and repository_paths_checked(report):
        covered.add(all_paths)
    rows = db.execute("SELECT * FROM bank_issue WHERE project_id=%s AND lineage=%s", (project, lineage))
    prior = {row["id"]: row for row in rows}
    watermarks = {(row["rule_id"], row["file_path"]): (row["scanned_at"], row["run_id"]) for row in db.execute(
        "SELECT * FROM bank_issue_coverage WHERE project_id=%s AND lineage=%s", (project, lineage))}
    for key, group in by_id.items():
        f = group[0]
        row = prior.get(key)
        scope = (f["ruleId"], f["file"])
        if row is None:
            newer = watermarks.get(all_paths if scope[0] == REPOSITORY_RULE_ID else scope)
            fixed = bool(newer and newer > order)
            state_when, state_run = newer if fixed else order
            db.execute(
                """INSERT INTO bank_issue(id,project_id,lineage,rule_id,file_path,fingerprint,level,title,line,
                       occurrences,first_seen,last_seen,last_run,state,state_at,state_run,is_new)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (key, project, lineage, *scope, f["fingerprint"], f.get("level", ""), f.get("title", scope[0]),
                 f.get("line"), len(group), when, when, run, "fixed" if fixed else "open", state_when,
                 state_run, not fixed and f.get("novelty") not in ("known", "unknown")))
            if fixed:
                _event(db, key, "fixed", state_when, state_run)
        else:
            db.execute("UPDATE bank_issue SET first_seen=least(first_seen,%s) WHERE id=%s", (when, key))
            if order >= (row["last_seen"], row["last_run"]):
                db.execute("""UPDATE bank_issue SET last_seen=%s,last_run=%s,line=%s,title=%s,level=%s,occurrences=%s
                              WHERE id=%s""",
                           (when, run, f.get("line"), f.get("title", scope[0]), f.get("level", ""), len(group), key))
            if order > (row["state_at"], row["state_run"]):
                reopened = row["state"] == "fixed"
                db.execute("UPDATE bank_issue SET state='open',state_at=%s,state_run=%s,is_new=%s WHERE id=%s",
                           (when, run, reopened or f.get("novelty") == "new", key))
                if reopened:
                    _event(db, key, "reopened", when, run)
        _event(db, key, "seen", when, run, line=f.get("line"), occurrences=len(group), revision=report.get("revision"))
        if backfill and f.get("triageDecision"):
            decision = f["triageDecision"]
            if decision.get("at", "") >= ((row or {}).get("decision") or {}).get("at", ""):
                _capture_decision(db, project, key, f["triage"], decision, decision.get("actor"), run)

    for key, row in prior.items():
        scope = all_paths if row["rule_id"] == REPOSITORY_RULE_ID else (row["rule_id"], row["file_path"])
        if key in by_id or scope not in covered or order <= (row["state_at"], row["state_run"]):
            continue
        db.execute("UPDATE bank_issue SET state='fixed',state_at=%s,state_run=%s,is_new=false WHERE id=%s",
                   (when, run, key))
        if row["state"] != "fixed":
            _event(db, key, "fixed", when, run, revision=report.get("revision"))

    for rule, path in covered:
        if (rule, path) not in watermarks or order > watermarks[(rule, path)]:
            db.execute(
                """INSERT INTO bank_issue_coverage(project_id,lineage,rule_id,file_path,scanned_at,run_id)
                   VALUES (%s,%s,%s,%s,%s,%s) ON CONFLICT (project_id,lineage,rule_id,file_path)
                   DO UPDATE SET scanned_at=excluded.scanned_at,run_id=excluded.run_id""",
                (project, lineage, rule, path, when, run))


def backfill_issues(db):
    with db.cursor(name="historical_issue_reports") as cursor:
        cursor.execute("""SELECT report FROM bank_run WHERE report->>'status' IN ('review','passed','partial','skipped')
                          ORDER BY created_at,id""")
        for row in cursor:
            report = row["report"]
            record_scan(db, report, backfill=True)
            if any("issueId" in f for f in report.get("findings", [])):
                db.execute("UPDATE bank_run SET report=%s WHERE id=%s", (Jsonb(report), report["id"]))


def sync_triage(db, before, report, actor, finding_id):
    for f in report.get("findings", []):
        changed = before.get(f["id"]) != (f.get("triage"), f.get("triageDecision"))
        if f.get("issueId") and (f["id"] == finding_id or changed):
            _capture_decision(db, report["projectId"], f["issueId"], f["triage"], f.get("triageDecision"), actor, report["id"])


def _public(row):
    result = dict(row)
    for key in ("firstSeenAt", "lastSeenAt"):
        result[key] = result[key].isoformat()
    return result


class IssueStore:
    def __init__(self, store):
        self.store = store

    def apply_decisions(self, report, findings):
        mapping = defaultdict(list)
        for f in findings:
            key = issue_key(report.get("projectId"), report.get("lineage"), f)
            if key:
                mapping[key].append(f)
        if not mapping:
            return
        with self.store.connect() as db:
            rows = db.execute("SELECT id,triage,decision FROM bank_issue WHERE project_id=%s AND id=ANY(%s)",
                              (report["projectId"], list(mapping)))
            for row in rows:
                decision = row["decision"]
                active = decision and decision["expiresAt"] >= date.today().isoformat()
                for f in mapping[row["id"]]:
                    f["triage"] = row["triage"] if active else "open"
                    f["triageDecision"] = decision if active else None

    def list_issues(self, project_id, username, filter="open", offset=0, limit=50, *, repository=None):
        if filter not in FILTERS or type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 100:
            raise WorkspaceError("Проверьте фильтр или параметры страницы.")
        projects = [project_id] if isinstance(project_id, str) else project_id
        params = [projects]
        where = " WHERE project_id=ANY(%s) AND " + FILTERS[filter]
        if filter == "mine":
            params.append(username)
        if repository:
            where += " AND lower(repository)=lower(%s)"
            params.append(repository)
        source = """ FROM (SELECT i.*, s.repository FROM bank_issue i
                           LEFT JOIN bank_repository_source s USING(project_id, lineage)) AS sourced"""
        with self.store.connect() as db:
            total = db.execute("SELECT count(*) AS n" + source + where, params).fetchone()["n"]
            rows = db.execute("SELECT " + FIELDS + ", repository" + source + where +
                              f" ORDER BY {SEVERITY_ORDER},last_seen DESC,id LIMIT %s OFFSET %s", (*params, limit, offset))
            return {"issues": [_public(row) for row in rows], "total": total, "offset": offset, "limit": limit}

    def assigned(self, username, accessible_project_ids):
        with self.store.connect() as db:
            rows = db.execute("SELECT " + FIELDS + " FROM bank_issue WHERE project_id=ANY(%s) AND assignee=%s "
                              f"AND state='open' ORDER BY {SEVERITY_ORDER},last_seen DESC,id LIMIT 100",
                              (list(accessible_project_ids), username))
            return [_public(row) for row in rows]

    def counts(self, project_id):
        with self.store.connect() as db:
            return db.execute(
                """SELECT count(*) FILTER(WHERE state='open') AS open,
                          count(*) FILTER(WHERE state='open' AND level IN ('high','critical')) AS high,
                          count(*) FILTER(WHERE state='open' AND is_new) AS new,
                          count(*) FILTER(WHERE state='open' AND (decision->>'expiresAt')::date<=CURRENT_DATE) AS review,
                          count(*) FILTER(WHERE state='fixed') AS fixed
                   FROM bank_issue WHERE project_id=%s""", (project_id,)).fetchone()

    def candidates(self, project_id):
        with self.store.connect() as db:
            return db.execute(CANDIDATES + " ORDER BY a.display_name,a.username", (project_id,)).fetchall()

    def get_issue(self, project_id, issue_id):
        with self.store.connect() as db:
            return self._detail(db, project_id, issue_id)

    def _detail(self, db, project_id, issue_id):
        row = db.execute("SELECT " + FIELDS + " FROM bank_issue WHERE project_id=%s AND id=%s",
                         (project_id, issue_id)).fetchone()
        if not row:
            return None
        result = _public(row)
        last = db.execute("SELECT report->'findings' AS findings FROM bank_run WHERE project_id=%s AND id=%s",
                          (project_id, result["lastRunId"])).fetchone()
        result["finding"] = next((f for f in (last or {}).get("findings", []) if f.get("issueId") == issue_id), None)
        history = db.execute("""SELECT e.action,e.created_at AS "createdAt",r.id AS "runId",e.actor,e.details
                                FROM bank_issue_event e LEFT JOIN bank_run r ON r.id=e.run_id AND r.project_id=%s
                                WHERE e.issue_id=%s ORDER BY e.created_at DESC,e.id DESC LIMIT 200""", (project_id, issue_id))
        result["history"] = [event | {"createdAt": event["createdAt"].isoformat()} for event in history]
        return result

    def update_issue(self, project_id, issue_id, actor_username, payload):
        if "status" not in payload and "assignee" not in payload:
            raise WorkspaceError("Укажите назначение или решение по замечанию.")
        with self.store.connect() as db:
            _lock_scope(db, project_id)
            issue = db.execute("SELECT assignee FROM bank_issue WHERE project_id=%s AND id=%s FOR UPDATE",
                               (project_id, issue_id)).fetchone()
            if not issue:
                raise WorkspaceError("Замечание не найдено.", 404)
            if "assignee" in payload:
                assignee = payload["assignee"]
                if assignee is not None and (not isinstance(assignee, str) or not db.execute(
                    CANDIDATES + " AND a.username=%s", (project_id, assignee)).fetchone()):
                    raise WorkspaceError("Выберите участника этого проекта.")
                if assignee != issue["assignee"]:
                    db.execute("UPDATE bank_issue SET assignee=%s WHERE id=%s", (assignee, issue_id))
                    _event(db, issue_id, "assigned", now(), actor=actor_username, assignee=assignee)
            if "status" in payload:
                status = payload["status"]
                if status not in ("open", "accepted", "false_positive"):
                    raise WorkspaceError("Выберите допустимое решение.")
                decision = None
                if status != "open":
                    reason = payload.get("reason")
                    if not isinstance(reason, str) or not 3 <= len(reason.strip()) <= 300:
                        raise WorkspaceError("Укажите причину длиной от 3 до 300 символов.")
                    try:
                        expires = date.fromisoformat(payload.get("expiresAt"))
                    except (ValueError, TypeError):
                        raise WorkspaceError("Укажите дату пересмотра решения.") from None
                    if not date.today() <= expires <= date.today() + timedelta(days=365):
                        raise WorkspaceError("Дата пересмотра должна быть в пределах года.")
                    decision = {"reason": reason.strip(), "expiresAt": expires.isoformat(), "actor": actor_username, "at": now()}
                _capture_decision(db, project_id, issue_id, status, decision, actor_username)
            db.execute("""INSERT INTO bank_audit_event(actor,action,subject,organization_id,project_id)
                          SELECT %s,'issue.update',%s,organization_id,id FROM bank_project WHERE id=%s""",
                       (actor_username, issue_id, project_id))
            return self._detail(db, project_id, issue_id)
