"""Register completed automation scans in project issues and release comparisons."""
import json
from datetime import datetime, timezone
from hashlib import sha256

from psycopg.types.json import Jsonb

from analyzers import REPORT_RULES as RULES
from case_unified import standard_finding
from issue_store import record_scan


def _utc(seconds):
    return datetime.fromtimestamp(seconds, timezone.utc).isoformat()


def as_project_run(project, report, started, completed):
    source = report.get("source") or {}
    repository = source.get("repository")
    graph = report.get("graph") or {}
    version = report.get("graphVersion") or sha256(json.dumps(graph, sort_keys=True).encode()).hexdigest()[:12]
    stages = report.get("stages", [])
    coverage = report.get("coverage", [])
    checked = {entry["engine"] for entry in coverage}
    findings = []
    incomplete = 0
    for i, raw in enumerate(report.get("findings", []), 1):
        try:
            finding = standard_finding(raw, i)
        except (AttributeError, KeyError, TypeError, ValueError):
            # Original reports remain available even for historical finding formats.
            incomplete += 1
            continue
        findings.append(finding | {"triage":"open", "novelty":"unknown"})
    rules = sorted({key for key, rule in RULES.items() if rule["engine"] in checked}
                   | {finding["ruleId"] for finding in findings if finding["ruleId"] in RULES})
    status = report["status"]
    if (status == "failed" and findings) or incomplete:
        status = "partial"
    spec = {"name": report.get("automationName") or "Автоматизация проекта", "rules": rules, "gateMinimum":"off"}
    result = {
        "id": report["id"], "graphRunId": report["id"], "automationId": report.get("automationId", "default"),
        "createdBy": report.get("createdBy"),
        "projectId": project, "createdAt": _utc(started), "completedAt": _utc(completed),
        "origin": "automation", "status": status, "source": repository or "Загруженный проект",
        "revision": source.get("revision") or "", "sourceRepositoryId":source.get("repositoryId"),
        "lineage": "github-read:" + repository.lower() if repository else "graph-upload:" + report["id"],
        "workflow": {"number":version, "spec":spec}, "findings": findings, "fixed": [],
        "coverage":coverage, "stages":[{"id": s["id"], "status":s["status"], "message":s.get("message", "")}
                                      for s in stages if s.get("status") in ("done","error","skipped")],
        "error":report.get("error"), "delivery":None, "githubCheck":None,
    }
    if report.get("skipReason"):
        result["skipReason"] = report["skipReason"]
    if source.get("bindingId"):
        result["sourceBinding"] = "@bound:" + source["bindingId"]
    if incomplete:
        result["error"] = f"В исходном отчёте есть замечания прежнего формата ({incomplete}). Откройте схему запуска."
    if "coverage" not in report:
        result["coverageNote"] = "Этот запуск сохранён до учёта охвата по файлам. Его находки доступны, охват для сравнения неизвестен."
    scoped_scanners = {node["id"] for node in graph.get("nodes", []) if node.get("params", {}).get("directory")}
    if source.get("inventory") and any(s.get("type") == "secrets" and s.get("status") == "done"
                                      and s["id"] not in scoped_scanners for s in stages):
        result["inventory"] = source["inventory"]
    return result


def save_graph_run(db, project, report, started, completed):
    run = as_project_run(project, report, started, completed)
    created = db.execute("""INSERT INTO bank_run(id,project_id,workflow_version,report,created_at,created_by)
        VALUES (%s,%s,NULL,%s,%s,%s) ON CONFLICT (id) DO NOTHING RETURNING id""",
        (run["id"], project, Jsonb(run), run["createdAt"], run["createdBy"])).fetchone()
    if created:
        record_scan(db, run)
        db.execute("UPDATE bank_run SET report=%s WHERE id=%s AND project_id=%s",
                   (Jsonb(run), run["id"], project))


def backfill_graph_runs(db):
    with db.cursor(name="graph_history") as rows:
        rows.execute("""SELECT project_id, report, created_at, updated_at FROM studio_run
            WHERE status IN ('passed','review','partial','failed','skipped') ORDER BY created_at,id""")
        for row in rows:
            save_graph_run(db, row["project_id"], json.loads(row["report"]), row["created_at"], row["updated_at"])
