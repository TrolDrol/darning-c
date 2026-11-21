"""Dispatch authenticated repository events against saved workflow snapshots."""
from hashlib import sha256
import json
import time
from uuid import uuid4

from case_graph import is_bound_source
from case_repository import selected_revision, source_marker
from case_store import automation_id
from workspace import WorkspaceError


def enqueue_webhook(store, project, automation_id_value, delivery_id, repository, revision, *, actor, request_hash=None):
    selected = automation_id(automation_id_value)
    if not is_bound_source(repository) or ":" not in repository:
        raise WorkspaceError("Передайте идентификатор подключённого репозитория.")
    if not isinstance(delivery_id, str) or not 1 <= len(delivery_id) <= 200:
        raise WorkspaceError("Передайте ключ повторной доставки.")
    binding = source_marker(store, project, repository)
    if not binding or repository != "@bound:" + binding["bindingId"]:
        raise WorkspaceError("Репозиторий не подключён к этому проекту.", 404)
    event = {"type": "webhook", "deliveryId": delivery_id, "revision": selected_revision(revision)}
    runs = _dispatch(store, project, binding, event, selected=selected, actor=actor, request_hash=request_hash)
    return runs[0]


def enqueue_github(store, project, binding, event):
    return _dispatch(store, project, binding, event, actor="github")


def _dispatch(store, project, binding, event, *, actor, selected=None, request_hash=None):
    kind = event["type"]
    reference = "@bound:" + binding["bindingId"]
    source = "webhook:" + selected if selected else "github:" + binding["bindingId"]
    delivery = event["deliveryId"]
    fingerprint = sha256(json.dumps([event, reference, request_hash], sort_keys=True).encode()).hexdigest()
    with store.connection() as q:
        if store.postgres:
            q("SELECT id FROM bank_project WHERE id=? FOR UPDATE", (project,)).fetchone()
        else:
            q("BEGIN IMMEDIATE")
        prior = q("""SELECT fingerprint,result FROM studio_event_receipt
                     WHERE project_id=? AND source=? AND delivery=?""", (project, source, delivery)).fetchone()
        if prior:
            if prior["fingerprint"] != fingerprint:
                raise WorkspaceError("Этот идентификатор доставки уже использован с другими параметрами.", 409)
            return [item | {"duplicate": True} for item in json.loads(prior["result"])]
        if selected:
            row = q("""SELECT automation_id,graph,repository FROM studio_event_subscription
                       WHERE project_id=? AND automation_id=? AND kind='webhook'""", (project, selected)).fetchone()
            if not row:
                raise WorkspaceError("Сохраните готовый сценарий с начальным блоком «HTTP-вебхук».", 409)
            if row["repository"] and row["repository"] != reference:
                raise WorkspaceError("Репозиторий запроса отличается от источника сохранённого сценария.", 409)
            rows = [row]
        else:
            rows = q("""SELECT automation_id,graph FROM studio_event_subscription
                        WHERE project_id=? AND kind=? AND repository=? ORDER BY automation_id""",
                     (project, kind, reference)).fetchall()
        if rows and not store.has_queue_capacity(q, project, len(rows)):
            raise WorkspaceError("Очередь проекта заполнена. Повторите доставку позже.", 429)
        result = []
        payload = {"repository": reference, "binding": binding, "revision": event["revision"],
                   "trigger": kind, "createdBy": actor, "event": event}
        for row in rows:
            automation = row["automation_id"]
            name = store.selected(q, project, automation)["automationName"]
            run_id = uuid4().hex
            store.insert(q, run_id, project, json.loads(row["graph"]), payload, automation, name)
            result.append({"id": run_id, "automationId": automation, "duplicate": False})
        q("INSERT INTO studio_event_receipt(project_id,source,delivery,fingerprint,result,created_at) VALUES(?,?,?,?,?,?)",
          (project, source, delivery, fingerprint, json.dumps(result), int(time.time())))
        return result
