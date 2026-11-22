"""Read-only view of a project's armed triggers and unfinished executions."""
import json
import re

from case_store import DEFAULT_AUTOMATION, DEFAULT_NAME, PROJECT_QUEUE_LIMIT, schedule_view
from workspace import WorkspaceError


PAGE_SIZE = 100


def activity(store, project, offset="0"):
    if not isinstance(offset, str) or not re.fullmatch("[0-9]{1,8}", offset):
        raise WorkspaceError("Некорректная страница активных сценариев.")
    offset = int(offset)
    with store.connection() as q:
        # Select and page the light index first. Only the returned timers need the
        # schedule parameters from their last activated graph (drafts can differ).
        waiting = q("""
            WITH armed(id, name, trigger) AS (
                SELECT s.automation_id, COALESCE(a.name, ?), s.kind
                FROM studio_event_subscription s
                LEFT JOIN studio_automation a ON a.project_id=s.project_id AND a.id=s.automation_id
                WHERE s.project_id=?
                UNION ALL SELECT ?, ?, 'schedule' FROM studio_graph
                    WHERE project_id=? AND schedule_time IS NOT NULL
                UNION ALL SELECT id, name, 'schedule' FROM studio_automation
                    WHERE project_id=? AND schedule_time IS NOT NULL
            ), page AS (
                SELECT * FROM armed ORDER BY name,id LIMIT ? OFFSET ?
            )
            SELECT totals.n, p.id, p.name, p.trigger, coalesce(g.graph,a.scheduled_graph) AS clock_graph
            FROM (SELECT count(*) AS n FROM armed) totals
            LEFT JOIN page p ON 1=1
            LEFT JOIN studio_graph g ON p.trigger='schedule' AND p.id=? AND g.project_id=?
            LEFT JOIN studio_automation a ON p.trigger='schedule' AND a.id=p.id AND a.project_id=?
            ORDER BY p.name,p.id
        """, (DEFAULT_NAME, project, DEFAULT_AUTOMATION, DEFAULT_NAME, project, project, PAGE_SIZE, offset,
              DEFAULT_AUTOMATION, project, project)).fetchall()

        if store.postgres:
            trigger = "COALESCE(report::json->>'trigger', report::json#>>'{event,type}', payload::json->>'trigger', 'manual')"
            name = "report::json->>'automationName'"
            start = "report::json->>'startedAt'"
        else:
            trigger = ("COALESCE(json_extract(report,'$.trigger'), json_extract(report,'$.event.type'), "
                       "json_extract(payload,'$.trigger'), 'manual')")
            name = "json_extract(report,'$.automationName')"
            start = "json_extract(report,'$.startedAt')"
        runs = q(f"""SELECT id,automation_id,status,created_at,updated_at,{trigger} AS trigger,
                           {start} AS started_at,coalesce({name}, ?) AS name
                    FROM studio_run WHERE project_id=? AND status IN ('running','queued')
                    ORDER BY CASE WHEN status='running' THEN 0 ELSE 1 END,created_at,id LIMIT ?""",
                 (DEFAULT_NAME, project, PROJECT_QUEUE_LIMIT)).fetchall()
    listeners = []
    for row in waiting:
        if row["id"] is None:  # Count row for an empty page.
            continue
        schedule = schedule_view(json.loads(row["clock_graph"])) if row["clock_graph"] else None
        listeners.append({"automationId": row["id"], "automationName": row["name"], "status": "waiting",
                          "trigger": row["trigger"], "schedule": schedule})
    active_runs = [{"runId": row["id"], "automationId": row["automation_id"], "automationName": row["name"],
                    "status": row["status"], "trigger": row["trigger"], "createdAt": row["created_at"],
                    "startedAt": int(row["started_at"]) if row["started_at"] is not None else None,
                    "updatedAt": row["updated_at"]} for row in runs]
    total = waiting[0]["n"]
    return {"waiting": listeners, "waitingTotal": total,
            "nextOffset": offset + PAGE_SIZE if offset + PAGE_SIZE < total else None,
            "runs": active_runs, "runsTotal": len(active_runs)}
