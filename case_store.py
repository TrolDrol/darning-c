"""Durable workflow queue and team template library (PostgreSQL or local SQLite)."""
import json
from hashlib import sha256
import os
import re
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import NAMESPACE_URL, uuid4, uuid5
import case_schedule
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
    fields = [document["automationName"], document["graph"], document.get("activeEvent"), document.get("scheduleTime")]
    return sha256(json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def schedule_view(graph):
    return case_schedule.describe(graph, datetime.fromtimestamp(time.time(), timezone.utc))


def _legacy_schedule_exists(q, project, selected, scope, due):
    """Recognize a prior-format job only when its graph matched this due minute."""
    utc = due.astimezone(timezone.utc)
    days = {utc.date() + timedelta(days=offset) for offset in (-1, 0, 1)}
    legacy = {uuid5(NAMESPACE_URL, f"darning:{scope}:{day}").hex: day.isoformat() for day in days}
    local_minute = due.strftime("%Y-%m-%dT%H:%M")
    legacy[uuid5(NAMESPACE_URL, f"darning:{scope}:{local_minute}").hex] = local_minute
    slots = ",".join("?" for _ in legacy)
    started = int(utc.timestamp())
    # Cron stored its wall minute in the old time zone. Jobs created at or after
    # this instant cover previous time zones without scanning historical days.
    rows = q(f"""SELECT id,graph FROM studio_run WHERE id IN ({slots})
                 OR (project_id=? AND automation_id=? AND created_at BETWEEN ? AND ?)""",
             (*legacy, project, selected, started, started + 86400)).fetchall()
    for row in rows:
        params = case_schedule.clock_params(json.loads(row["graph"]))
        if not params:
            continue
        local = due.astimezone(case_schedule.clock_zone(params))
        if local.fold:
            continue
        slot = local.strftime("%Y-%m-%dT%H:%M")
        if "cron" in params and row["id"] == uuid5(NAMESPACE_URL, f"darning:{scope}:{slot}").hex:
            return True
        if (legacy.get(row["id"]) == local.date().isoformat() and params.get("time") == local.strftime("%H:%M")
                and case_schedule.fixed_day(params, local.date())):
            return True
    return False


class StudioStore:
    def __init__(self, postgres=None, folder=None):
        self.postgres = postgres
        if postgres is None:
            folder = Path(folder or DATA)
            folder.mkdir(parents=True, exist_ok=True)
            self.path = folder / "studio.sqlite3"
            with self.connection() as query:
                query("BEGIN IMMEDIATE")
                migrations = ["007_case_studio.sql", "008_studio_model.sql", "025_node_models.sql", "028_studio_triggers.sql",
                              "029_studio_trigger_pause.sql"]
                if "automation_id" not in {r["name"] for r in query("PRAGMA table_info(studio_run)")}:
                    migrations.append("018_project_automations.sql")
                if "schedule_hold" not in {r["name"] for r in query("PRAGMA table_info(studio_automation)")}:
                    migrations.append("020_shared_workflows.sql")
                if "replay_options" not in {r["name"] for r in query("PRAGMA table_info(studio_run)")}:
                    migrations.append("031_studio_repair.sql")
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
            row = q("""SELECT g.graph,g.schedule_time,s.kind FROM studio_graph g
                       LEFT JOIN studio_event_subscription s ON s.project_id=g.project_id AND s.automation_id=?
                       WHERE g.project_id=?""", (selected, project)).fetchone()
            graph = json.loads(row["graph"]) if row else default_graph()
            return {"graph": graph, "automationId": selected, "automationName": DEFAULT_NAME, "activeEvent": row["kind"] if row else None,
                    "scheduleTime": row["schedule_time"] if row else None,
                    "activeSchedule": schedule_view(graph) if row and row["schedule_time"] else None,
                    "scheduleHeld": bool(row and not row["schedule_time"] and any(n["type"] == "schedule" for n in graph["nodes"]))}
        row = q("""SELECT a.name,a.graph,a.schedule_time,a.schedule_hold,a.scheduled_graph,s.kind FROM studio_automation a
                   LEFT JOIN studio_event_subscription s ON s.project_id=a.project_id AND s.automation_id=a.id
                   WHERE a.project_id=? AND a.id=?""",
                (project, selected)).fetchone()
        if not row:
            raise WorkspaceError("Сценарий не найден.", 404)
        graph = json.loads(row["graph"])
        active_graph = json.loads(row["scheduled_graph"]) if row["schedule_time"] else None
        return {"graph": graph, "automationId": selected, "automationName": row["name"],
                "scheduleTime": row["schedule_time"], "scheduleHeld": bool(row["schedule_hold"]), "activeEvent": row["kind"],
                "draft": active_graph is not None and graph != active_graph,
                "activeSchedule": schedule_view(active_graph) if active_graph is not None else None}

    def automation(self, project, selected):
        with self.connection() as q:
            return self.selected(q, project, selected)

    def overview(self, project, organization, selected=DEFAULT_AUTOMATION, *, include_templates=True):
        from case_graph import NODE_TYPES
        with self.connection() as q:
            active = self.selected(q, project, selected)
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
                "activeSchedule": None, "scheduleHeld": hold, "activeEvent": None}

    def lock_project(self, q, project):
        if self.postgres:
            q("SELECT id FROM bank_project WHERE id=? FOR UPDATE", (project,)).fetchone()
        else:
            q("BEGIN IMMEDIATE")

    def set_trigger_pause(self, q, project, selected, paused):
        if paused:
            q("INSERT INTO studio_trigger_pause(project_id,automation_id) VALUES(?,?) ON CONFLICT DO NOTHING",
              (project, selected))
        else:
            q("DELETE FROM studio_trigger_pause WHERE project_id=? AND automation_id=?", (project, selected))

    def stop_waiting(self, q, project, selected, schedule):
        self.set_trigger_pause(q, project, selected, True)
        q("DELETE FROM studio_event_subscription WHERE project_id=? AND automation_id=?", (project, selected))
        if selected == DEFAULT_AUTOMATION:
            q("UPDATE studio_graph SET schedule_time=NULL WHERE project_id=?", (project,))
        else:
            q("""UPDATE studio_automation SET scheduled_graph=NULL,scheduled_at=NULL,schedule_time=NULL,schedule_hold=?
                 WHERE project_id=? AND id=?""", (int(schedule), project, selected))

    def pause(self, project, selected):
        with self.connection() as q:
            self.lock_project(q, project)
            current = self.selected(q, project, selected)
            schedule = any(n["type"] == "schedule" for n in current["graph"]["nodes"])
            self.stop_waiting(q, project, selected, schedule)
        return current | {"activeEvent": None, "scheduleTime": None, "activeSchedule": None, "scheduleHeld": schedule}

    def save(self, project, graph, selected=DEFAULT_AUTOMATION, *, name=None, complete=True, trigger_enabled=None,
             expected_revision=None):
        from case_graph import EVENT_TRIGGERS
        at = int(time.time())
        schedule = next((n["params"].get("cron") or n["params"].get("time") for n in graph["nodes"] if n["type"] == "schedule"), None)
        event = next((n["type"] for n in graph["nodes"] if n["type"] in EVENT_TRIGGERS), None)
        with self.connection() as q:
            self.lock_project(q, project)
            current = self.selected(q, project, selected)
            if expected_revision is not None and automation_revision(current) != expected_revision:
                raise WorkspaceError("Сценарий изменился. Получите его актуальную версию.", 409)
            if not complete and trigger_enabled is False:
                self.stop_waiting(q, project, selected, bool(schedule))
            if complete:
                if not (schedule or event) or trigger_enabled is not None:
                    self.set_trigger_pause(q, project, selected, bool(schedule or event) and trigger_enabled is False)
                paused = q("SELECT 1 FROM studio_trigger_pause WHERE project_id=? AND automation_id=?",
                           (project, selected)).fetchone() is not None
                hold = bool(schedule and (paused or trigger_enabled is None and current.get("scheduleHeld")))
                schedule_time = None if hold else schedule
                self.sync_event_trigger(q, project, selected, graph, None if paused else event)
            if automation_id(selected) != DEFAULT_AUTOMATION:
                if name is not None:
                    name = automation_name(name)
                fields, values = "graph=?,name=coalesce(?,name)", [json.dumps(graph), name]
                if complete:
                    fields += ",scheduled_graph=?,schedule_time=?,scheduled_at=?,schedule_hold=?"
                    values.extend([json.dumps(graph) if schedule_time else None, schedule_time,
                                   at if schedule_time else None, int(hold)])
                row = q(f"UPDATE studio_automation SET {fields} WHERE project_id=? AND id=? RETURNING name,schedule_time,schedule_hold",
                        (*values, project, selected)).fetchone()
                if not row:
                    raise WorkspaceError("Сценарий не найден.", 404)
                result = {"automationId": selected, "automationName": row["name"], "graph": graph,
                          "draft": not complete, "scheduleTime": row["schedule_time"], "scheduleHeld": bool(row["schedule_hold"])}
            else:
                q("""INSERT INTO studio_graph(project_id,graph,saved_at,schedule_time) VALUES(?,?,?,?)
                 ON CONFLICT(project_id) DO UPDATE SET graph=excluded.graph,saved_at=excluded.saved_at,schedule_time=excluded.schedule_time""",
                  (project, json.dumps(graph), at, schedule_time))
                result = {"graph": graph, "automationId": selected, "automationName": DEFAULT_NAME,
                          "scheduleTime": schedule_time, "scheduleHeld": hold}
            subscription = q("SELECT kind FROM studio_event_subscription WHERE project_id=? AND automation_id=?",
                             (project, selected)).fetchone()
            active_schedule = None
            if result["scheduleTime"]:
                active_schedule = schedule_view(graph) if complete else current["activeSchedule"]
            return result | {"activeEvent": subscription["kind"] if subscription else None, "activeSchedule": active_schedule}

    def sync_event_trigger(self, q, project, selected, graph, trigger):
        if trigger is None:
            q("DELETE FROM studio_event_subscription WHERE project_id=? AND automation_id=?", (project, selected))
            return
        source = next(n for n in graph["nodes"] if n["type"] == "source")
        repository = source.get("params", {}).get("repository", "")
        if trigger in ("github_pr", "github_push"):
            if not repository:
                raise WorkspaceError("В блоке «Репозиторий» выберите подключённый репозиторий для событий GitHub.")
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
                  "automationId": selected, "automationName": name, "trigger": payload.get("trigger", "manual")}
        if payload.get("createdBy"):
            report["createdBy"] = payload["createdBy"]
        if "scheduledAt" in payload:
            report["scheduledAt"] = payload["scheduledAt"]
        if "repair" in payload:
            report["repair"] = payload["repair"]
        if payload.get("event"):
            report["event"] = payload["event"]
            report["revision"] = payload["revision"]
        replay_options = {option: payload[option] for option in ("advisories", "dependencyMetrics") if option in payload}
        q("""INSERT INTO studio_run(id,project_id,status,graph,payload,report,created_at,updated_at,automation_id,replay_options)
             VALUES(?,?,'queued',?,?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING""",
          (key,project,json.dumps(graph),json.dumps(payload),json.dumps(report),now,now,selected,
           json.dumps(replay_options) if replay_options else None))
        return report

    def has_queue_capacity(self, q, project, requested=1):
        if self.postgres:
            q("SELECT id FROM bank_project WHERE id=? FOR UPDATE", (project,)).fetchone()
        pending = q("SELECT count(*) AS n FROM studio_run WHERE project_id=? AND status IN ('queued','running')",
                    (project,)).fetchone()
        return pending["n"] + requested <= PROJECT_QUEUE_LIMIT

    def enqueue(self, project, graph, payload, selected=DEFAULT_AUTOMATION, *, manual=False):
        with self.connection() as q:
            if not self.postgres:
                q("BEGIN IMMEDIATE")
            if not self.has_queue_capacity(q, project):
                raise WorkspaceError("Очередь проекта заполнена. Дождитесь завершения текущих запусков.", 429)
            current = self.selected(q, project, selected)
            if manual:
                from case_graph import AUTOMATIC_TRIGGERS
                if current["activeEvent"] or current["scheduleTime"] or any(n["type"] in AUTOMATIC_TRIGGERS for n in current["graph"]["nodes"]):
                    raise WorkspaceError("Сначала сохраните сценарий с ручным триггером.", 409)
            return self.insert(q, uuid4().hex, project, graph, payload, selected, current["automationName"])

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
                if row and not report.get("repair"):
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
                graph = json.loads(row["graph"])
                due = case_schedule.last_slot(case_schedule.clock_params(graph), now, row["saved_at"])
                if due is None:
                    continue
                project, selected = row["project_id"], row["id"]
                scope = project if selected == DEFAULT_AUTOMATION else f"{project}:{selected}"
                timestamp = int(due.timestamp())
                key = uuid5(NAMESPACE_URL, f"darning:{scope}:schedule:{timestamp}").hex
                if q("SELECT 1 FROM studio_run WHERE id=?", (key,)).fetchone() or not self.has_queue_capacity(q, project):
                    continue
                # The schedule may have been changed after tick's first read.
                if self.postgres:
                    if selected == DEFAULT_AUTOMATION:
                        fresh = q("SELECT graph,saved_at,schedule_time FROM studio_graph WHERE project_id=?",
                                  (project,)).fetchone()
                    else:
                        fresh = q("""SELECT scheduled_graph AS graph,scheduled_at AS saved_at,schedule_time
                                     FROM studio_automation WHERE project_id=? AND id=?""", (project, selected)).fetchone()
                    if not fresh or any(row[field] != fresh[field] for field in ("saved_at", "schedule_time", "graph")):
                        continue
                if _legacy_schedule_exists(q, project, selected, scope, due):
                    continue
                source = next(n for n in graph["nodes"] if n["type"] == "source")
                repo = source.get("params", {}).get("repository")
                if not repo:
                    continue
                self.insert(q, key, project, graph, {"repository": repo, "trigger": "schedule", "scheduledAt": timestamp},
                            selected, row["name"])
            # No automatic replay of side effects after a worker dies.
            for row in q("SELECT id,report FROM studio_run WHERE status='running' AND updated_at<?",(int(now.timestamp())-1800,)).fetchall():
                report = json.loads(row["report"])
                report.update(status="failed",error="Исполнитель прервал работу. Проверьте доставку перед повтором.")
                q("UPDATE studio_run SET status='failed',report=?,payload=NULL WHERE id=? AND status='running' AND updated_at<?",
                  (json.dumps(report),row["id"],int(now.timestamp())-1800))
            days = max(1,int(os.getenv("BANK_REPORT_RETENTION_DAYS","30")))
            q("DELETE FROM studio_event_receipt WHERE created_at<?", (int(now.timestamp())-86400*days,))
            retained = """AND id NOT IN (
                SELECT origin_run FROM studio_repair WHERE state NOT IN ('accepted','stopped')
                UNION SELECT round->>'runId' FROM studio_repair,
                    LATERAL jsonb_array_elements(document::jsonb->'rounds') AS round
                    WHERE state NOT IN ('accepted','stopped') AND round->>'runId' IS NOT NULL
            )""" if self.postgres else ""
            q("DELETE FROM studio_run WHERE status IN ('passed','review','failed','skipped','partial') AND updated_at<? " + retained,
              (int(now.timestamp())-86400*days,))

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
            report["startedAt"] = int(time.time())
            q("UPDATE studio_run SET status='running',report=?,updated_at=? WHERE id=?",(json.dumps(report),report["startedAt"],row["id"]))
            return row["project_id"],json.loads(row["payload"]),report
