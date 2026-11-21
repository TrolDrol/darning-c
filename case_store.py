"""Durable workflow queue and team template library (PostgreSQL or local SQLite)."""
import json
from hashlib import sha256
import os
import re
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from uuid import NAMESPACE_URL, uuid4, uuid5
from zoneinfo import ZoneInfo

from workspace import DATA, WorkspaceError

BASE = Path(__file__).parent
DEFAULT_AUTOMATION = "default"
DEFAULT_NAME = "Основной сценарий"
PROJECT_QUEUE_LIMIT = 12


def automation_id(value):
    if value != DEFAULT_AUTOMATION and (not isinstance(value, str) or not re.fullmatch("[a-f0-9]{32}", value)):
        raise WorkspaceError("Сценарий не найден.", 404)
    return value


def automation_name(value):
    if not isinstance(value, str) or not 1 <= len(value.strip()) <= 100 or not value.strip().isprintable():
        raise WorkspaceError("Введите название сценария от 1 до 100 печатных символов.")
    return value.strip()


def automation_revision(document):
    fields = [document["automationName"], document["graph"]]
    return sha256(json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

class StudioStore:
    def __init__(self, postgres=None, folder=None):
        self.postgres = postgres
        if postgres is None:
            folder = Path(folder or DATA)
            folder.mkdir(parents=True, exist_ok=True)
            self.path = folder / "studio.sqlite3"
            with self.connection() as query:
                query("BEGIN IMMEDIATE")
                migrations = ["007_case_studio.sql", "008_studio_model.sql", "025_node_models.sql", "028_studio_triggers.sql"]
                if "automation_id" not in {r["name"] for r in query("PRAGMA table_info(studio_run)")}:
                    migrations.append("018_project_automations.sql")
                if "schedule_hold" not in {r["name"] for r in query("PRAGMA table_info(studio_automation)")}:
                    migrations.append("020_shared_workflows.sql")
                schema = "\n".join((BASE / "migrations" / name).read_text(encoding="utf8") for name in migrations)
                # Local workspaces predate the organization model.
                for statement in schema.replace(" REFERENCES bank_project(id) ON DELETE CASCADE", "").split(";"):
                    if statement.strip():
                        query(statement)
                if "fingerprint" not in {row["name"] for row in query("PRAGMA table_info(studio_model)")}:
                    query("ALTER TABLE studio_model ADD COLUMN fingerprint TEXT NOT NULL DEFAULT ''")

    @contextmanager
    def connection(self):
        if self.postgres:
            with self.postgres.connect() as db:
                yield lambda q, args=(): db.execute(q.replace("?", "%s"), args)
        else:
            db = sqlite3.connect(self.path, timeout=10)
            db.row_factory = sqlite3.Row
            try:
                with db:
                    yield db.execute
            finally:
                db.close()

    def selected(self, q, project, selected):
        from case_graph import default_graph
        if automation_id(selected) == DEFAULT_AUTOMATION:
            row = q("SELECT graph,schedule_time FROM studio_graph WHERE project_id=?", (project,)).fetchone()
            return {"graph": json.loads(row["graph"]) if row else default_graph(), "automationId": selected,
                    "automationName": DEFAULT_NAME, "scheduleTime": row["schedule_time"] if row else None}
        row = q("SELECT name,graph,schedule_time,schedule_hold FROM studio_automation WHERE project_id=? AND id=?",
                (project, selected)).fetchone()
        if not row:
            raise WorkspaceError("Сценарий не найден.", 404)
        return {"graph": json.loads(row["graph"]), "automationId": selected, "automationName": row["name"],
                "scheduleTime": row["schedule_time"], "scheduleHeld": bool(row["schedule_hold"])}

    def automation(self, project, selected):
        with self.connection() as q:
            return self.selected(q, project, selected)

    def overview(self, project, organization, selected=DEFAULT_AUTOMATION, *, include_templates=True):
        from case_graph import NODE_TYPES
        with self.connection() as q:
            active = self.selected(q, project, selected)
            subscription = q("SELECT kind FROM studio_event_subscription WHERE project_id=? AND automation_id=?",
                             (project, selected)).fetchone()
            active["activeEvent"] = subscription["kind"] if subscription else None
            automations = [{"id": DEFAULT_AUTOMATION, "name": DEFAULT_NAME}]
            automations.extend(dict(row) for row in q("SELECT id,name FROM studio_automation WHERE project_id=? ORDER BY name,id", (project,)))
            templates = ([dict(t) for t in q("SELECT id,name,description,graph FROM studio_template WHERE organization_id=? ORDER BY created_at DESC,id LIMIT 200",(organization,))]
                         if include_templates else [])
            runs = [dict(r) for r in q("SELECT id,status,created_at FROM studio_run WHERE project_id=? AND automation_id=? ORDER BY created_at DESC,id DESC LIMIT 100", (project,selected))]
        for t in templates:
            t["graph"] = json.loads(t["graph"])
        return active | {"automations": automations, "types": list(NODE_TYPES), "templates": templates, "runs": runs}

    def create(self, project, name, *, graph=None):
        name = automation_name(name)
        selected = uuid4().hex
        if graph is None:
            graph = {"nodes": [], "edges": []}
        hold = any(node["type"] == "schedule" for node in graph["nodes"])
        with self.connection() as q:
            q("INSERT INTO studio_automation(project_id,id,name,graph,schedule_hold) VALUES(?,?,?,?,?)",
              (project, selected, name, json.dumps(graph), int(hold)))
        return {"graph": graph, "automationId": selected, "automationName": name, "scheduleTime": None,
                "scheduleHeld": hold}

    def save(self, project, graph, selected=DEFAULT_AUTOMATION, *, name=None, complete=True, enable_schedule=False,
             expected_revision=None):
        at = int(time.time())
        schedule = next((n["params"]["time"] for n in graph["nodes"] if n["type"]=="schedule"), None)
        with self.connection() as q:
            # Serialize conditional CI writes with ordinary saves, including the virtual default graph.
            if self.postgres:
                q("SELECT id FROM bank_project WHERE id=? FOR UPDATE", (project,))
            else:
                q("BEGIN IMMEDIATE")
            if expected_revision is not None and automation_revision(self.selected(q, project, selected)) != expected_revision:
                raise WorkspaceError("Сценарий изменился. Получите его актуальную версию.", 409)
            if automation_id(selected) != DEFAULT_AUTOMATION:
                if name is not None:
                    name = automation_name(name)
                fields, values = "graph=?,name=coalesce(?,name)", [json.dumps(graph), name]
                if complete:
                    fields += (",scheduled_graph=CASE WHEN schedule_hold=0 OR ?=1 THEN ? END"
                               ",schedule_time=CASE WHEN schedule_hold=0 OR ?=1 THEN ? END"
                               ",scheduled_at=CASE WHEN schedule_hold=0 OR ?=1 THEN CAST(? AS BIGINT) END"
                               ",schedule_hold=CASE WHEN ?=1 THEN 0 ELSE schedule_hold END")
                    enable = int(enable_schedule is True)
                    values.extend([enable, json.dumps(graph) if schedule else None, enable, schedule,
                                   enable, at if schedule else None, int(enable or not schedule)])
                row = q(f"UPDATE studio_automation SET {fields} WHERE project_id=? AND id=? RETURNING name,schedule_time,schedule_hold",
                        (*values, project, selected)).fetchone()
                if not row:
                    raise WorkspaceError("Сценарий не найден.", 404)
                self.sync_event_trigger(q, project, selected, graph, complete)
                return {"automationId": selected, "automationName": row["name"], "graph": graph,
                        "draft": not complete, "scheduleTime": row["schedule_time"], "scheduleHeld": bool(row["schedule_hold"])}
            q("""INSERT INTO studio_graph(project_id,graph,saved_at,schedule_time) VALUES(?,?,?,?)
                 ON CONFLICT(project_id) DO UPDATE SET graph=excluded.graph,saved_at=excluded.saved_at,schedule_time=excluded.schedule_time""",
              (project, json.dumps(graph), at, schedule))
            self.sync_event_trigger(q, project, selected, graph, complete)
        return {"graph": graph, "automationId": selected, "automationName": DEFAULT_NAME, "scheduleTime": schedule}

    def sync_event_trigger(self, q, project, selected, graph, complete):
        from case_graph import EVENT_TRIGGERS
        if not complete:
            return
        trigger = next((n["type"] for n in graph["nodes"] if n["type"] in EVENT_TRIGGERS), None)
        if trigger is None:
            q("DELETE FROM studio_event_subscription WHERE project_id=? AND automation_id=?", (project, selected))
            return
        source = next(n for n in graph["nodes"] if n["type"] == "source")
        repository = source.get("params", {}).get("repository", "")
        if trigger in ("github_pr", "github_push"):
            existing = q("""SELECT count(*) AS n FROM studio_event_subscription
                            WHERE project_id=? AND kind=? AND repository=? AND automation_id<>?""",
                         (project, trigger, repository, selected)).fetchone()["n"]
            if existing >= PROJECT_QUEUE_LIMIT:
                raise WorkspaceError(f"Для одного события GitHub в репозитории можно включить до {PROJECT_QUEUE_LIMIT} сценариев.", 409)
        q("""INSERT INTO studio_event_subscription(project_id,automation_id,kind,repository,graph)
             VALUES(?,?,?,?,?) ON CONFLICT(project_id,automation_id) DO UPDATE SET
             kind=excluded.kind,repository=excluded.repository,graph=excluded.graph""",
          (project, selected, trigger, repository, json.dumps(graph)))

    def template(self, organization, graph, name, description):
        if not isinstance(name,str) or not 1<=len(name.strip())<=100 or not isinstance(description,str) or not 1<=len(description.strip())<=500:
            raise WorkspaceError("Укажите название и описание шаблона.")
        key = uuid4().hex
        with self.connection() as q:
            q("INSERT INTO studio_template VALUES(?,?,?,?,?,?)",(key,organization,name.strip(),description.strip(),json.dumps(graph),int(time.time())))
        return {"id":key,"graph":graph}

    def copy_template(self, project, organization, key):
        with self.connection() as q:
            row = q("SELECT graph FROM studio_template WHERE organization_id=? AND id=?",(organization,key)).fetchone()
        if not row:
            raise WorkspaceError("Шаблон не найден.",404)
        return {"graph": json.loads(row["graph"])}

    def insert(self, q, key, project, graph, payload, selected=DEFAULT_AUTOMATION, name=DEFAULT_NAME):
        now = int(time.time())
        report = {"id":key,"status":"queued","stages":[],"findings":[],"summary":{},"createdAt":now,"graph":graph,
                  "automationId": selected, "automationName": name}
        if payload.get("createdBy"):
            report["createdBy"] = payload["createdBy"]
        if payload.get("event"):
            report["event"] = payload["event"]
            report["revision"] = payload["revision"]
        q("""INSERT INTO studio_run(id,project_id,status,graph,payload,report,created_at,updated_at,automation_id)
             VALUES(?,?,'queued',?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING""",
          (key,project,json.dumps(graph),json.dumps(payload),json.dumps(report),now,now,selected))
        return report

    def has_queue_capacity(self, q, project, requested=1):
        if self.postgres:
            q("SELECT id FROM bank_project WHERE id=? FOR UPDATE", (project,)).fetchone()
        pending = q("SELECT count(*) AS n FROM studio_run WHERE project_id=? AND status IN ('queued','running')",
                    (project,)).fetchone()
        return pending["n"] + requested <= PROJECT_QUEUE_LIMIT

    def enqueue(self, project, graph, payload, selected=DEFAULT_AUTOMATION):
        with self.connection() as q:
            if not self.postgres:
                q("BEGIN IMMEDIATE")
            if not self.has_queue_capacity(q, project):
                raise WorkspaceError("Очередь проекта заполнена. Дождитесь завершения текущих запусков.", 429)
            name = DEFAULT_NAME if selected == DEFAULT_AUTOMATION else self.selected(q, project, selected)["automationName"]
            return self.insert(q, uuid4().hex, project, graph, payload, selected, name)

    def report(self, project, key):
        with self.connection() as q:
            row = q("SELECT report FROM studio_run WHERE project_id=? AND id=?",(project,key)).fetchone()
        if not row:
            raise WorkspaceError("Запуск не найден.",404)
        report = json.loads(row["report"])
        report.setdefault("automationId", DEFAULT_AUTOMATION)
        report.setdefault("automationName", DEFAULT_NAME)
        return report

    def update(self, report, finished=False):
        if finished and self.postgres:
            from case_run_projection import save_graph_run
            with self.postgres.connect() as db:
                at = int(time.time())
                row = db.execute("""UPDATE studio_run SET status=%s,report=%s,updated_at=%s,payload=NULL
                    WHERE id=%s AND status='running' RETURNING project_id,created_at""",
                    (report["status"], json.dumps(report), at, report["id"])).fetchone()
                if row:
                    save_graph_run(db, row["project_id"], report, row["created_at"], at)
                return int(row is not None)
        with self.connection() as q:
            return q("""UPDATE studio_run SET status=?, report=?, updated_at=?,payload=CASE WHEN ?=1 THEN NULL ELSE payload END
                         WHERE id=? AND status='running'""",
                     (report["status"],json.dumps(report),int(time.time()),int(finished),report["id"])).rowcount

    def tick(self, now=None):
        now = now or datetime.now(timezone.utc)
        with self.connection() as q:
            if not self.postgres:
                q("BEGIN IMMEDIATE")
            schedules = q("""SELECT project_id,? AS id,? AS name,graph,saved_at,schedule_time
                FROM studio_graph WHERE schedule_time IS NOT NULL
                UNION ALL SELECT project_id,id,name,scheduled_graph,scheduled_at,schedule_time
                FROM studio_automation WHERE schedule_time IS NOT NULL ORDER BY project_id,id""",
                (DEFAULT_AUTOMATION, DEFAULT_NAME)).fetchall()
            for row in schedules:
                hour, minute = map(int,row["schedule_time"].split(":"))
                graph = json.loads(row["graph"])
                params = next(n["params"] for n in graph["nodes"] if n["type"] == "schedule")
                zone = params.get("timezone", "UTC")
                local = now.astimezone(timezone.utc if zone == "UTC" else ZoneInfo(zone))
                if ("weekdays" in params and local.isoweekday() not in params["weekdays"]
                        or "monthDay" in params and local.day != params["monthDay"]):
                    continue
                due = local.replace(hour=hour, minute=minute, second=0, microsecond=0, fold=0)
                if row["saved_at"] <= due.timestamp() <= now.timestamp():
                    scope = row["project_id"] if row["id"] == DEFAULT_AUTOMATION else f"{row['project_id']}:{row['id']}"
                    key = uuid5(NAMESPACE_URL, f"darning:{scope}:{due.date()}").hex
                    if not q("SELECT 1 FROM studio_run WHERE id=?", (key,)).fetchone() and self.has_queue_capacity(q, row["project_id"]):
                        src=next(n for n in graph["nodes"] if n["type"]=="source")
                        repo=src.get("params",{}).get("repository")
                        if repo:
                            self.insert(q,key,row["project_id"],graph,{"repository":repo,"trigger":"schedule"},row["id"],row["name"])
            # No automatic replay of side effects after a worker dies.
            for row in q("SELECT id,report FROM studio_run WHERE status='running' AND updated_at<?",(int(now.timestamp())-1800,)).fetchall():
                report = json.loads(row["report"])
                report.update(status="failed",error="Исполнитель прервал работу. Проверьте доставку перед повтором.")
                q("UPDATE studio_run SET status='failed',report=?,payload=NULL WHERE id=? AND status='running' AND updated_at<?",
                  (json.dumps(report),row["id"],int(now.timestamp())-1800))
            days = max(1,int(os.getenv("BANK_REPORT_RETENTION_DAYS","30")))
            q("DELETE FROM studio_event_receipt WHERE created_at<?", (int(now.timestamp())-86400*days,))
            q("DELETE FROM studio_run WHERE status IN ('passed','review','failed','skipped','partial') AND updated_at<?",(int(now.timestamp())-86400*days,))

    def claim(self):
        with self.connection() as q:
            if not self.postgres:
                q("BEGIN IMMEDIATE")
            lock = " FOR UPDATE SKIP LOCKED" if self.postgres else ""
            row = q("SELECT * FROM studio_run WHERE status='queued' ORDER BY created_at,id LIMIT 1"+lock).fetchone()
            if not row:
                return None
            report = json.loads(row["report"])
            report["status"] = "running"
            q("UPDATE studio_run SET status='running',report=?,updated_at=? WHERE id=?",(json.dumps(report),int(time.time()),row["id"]))
            return row["project_id"],json.loads(row["payload"]),report
