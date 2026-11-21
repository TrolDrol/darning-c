"""PostgreSQL-backed scan and notification workers."""

import json
import logging
import os
import signal
import subprocess
import sys
import time
from collections import Counter
from datetime import date
from pathlib import Path
from threading import Event

from analyzers import CONTENT_ENGINES, RULES, repository_paths_checked
from delivery import send_summary
from case_account_email import deliver_one
from account_recovery import deliver_reset
from delivery import account_smtp
from github_integration import GitHubError, github_config, is_current_head, load_snapshots, publish_check, trial_snapshot
from repository_service import job_binding
from issue_store import IssueStore
from release_review import evaluate_gate
from production import Signals, database
from settings import public_url
from workspace import PRESETS, SMTP, make_run, now


logger = logging.getLogger(__name__)
BUSY_LEASE = 180
HEARTBEAT = Path("/tmp/bank-worker-heartbeat")
KINDS = {"scan": ("scan",), "delivery": ("smtp", "github")}
EVIDENCE = {
    "PY-001": "verify=False", "PY-002": "debug=True", "PY-003": "eval(…)",
    "CFG-001": '"secure": false', "CFG-002": '"include_request_body": true',
}


def static_analysis(head, rules, base=None):
    snapshots = {"head": head}
    if base is not None:
        snapshots["base"] = base
    root = Path(__file__).resolve().parent
    env = {"SYSTEMROOT": os.environ["SYSTEMROOT"]} if os.name == "nt" else {}
    invocation = (
        "import sys; sys.path.insert(0, sys.argv[1]); from scan_process import main; main()"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", invocation, str(root)], env=env, cwd=root,
        input=json.dumps({"snapshots": snapshots, "rules": rules}).encode(),
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=32, check=True,
    )
    return json.loads(result.stdout)


def compare_base(findings, base, head_stages, head_sources=None, base_sources=None):
    base_findings, base_stages = base or ([], [])
    comparable = {step["id"] for step in base_stages if step["id"] in CONTENT_ENGINES and (step["status"] == "done"
                  or (step["status"] == "skipped" and step.get("coverage") == []))}
    analyzed = {step["id"] for step in head_stages if step["id"] in CONTENT_ENGINES and step["status"] == "done"}
    paths_comparable = repository_paths_checked(head_sources or {}) and repository_paths_checked(base_sources or {})
    before = Counter((f["file"], f["fingerprint"]) for f in base_findings)
    after = Counter((f["file"], f["fingerprint"]) for f in findings)
    for finding in findings:
        key = (finding["file"], finding["fingerprint"])
        checked = paths_comparable if finding["engine"] == "repository" else finding["engine"] in comparable
        if not checked:
            novelty = "unknown"
        elif before[key] == 0:
            novelty = "new"
        elif before[key] >= after[key]:
            novelty = "known"
        else:
            novelty = "unknown"
        finding["novelty"] = novelty
    complete = (analyzed and analyzed <= comparable and not any(step["status"] == "error" for step in head_stages)
                and all(f["novelty"] != "unknown" for f in findings))
    return {"status": "available" if complete else "unavailable"}


def carry_triage(findings, prior):
    if not prior:
        return
    previous = prior.get("findings", [])
    previous_counts = Counter((item["file"], item.get("fingerprint")) for item in previous)
    current_counts = Counter((item["file"], item["fingerprint"]) for item in findings)
    decisions = {
        (item.get("fingerprint"), item["file"]): item for item in previous
        if item.get("triageDecision") and item["triageDecision"]["expiresAt"] >= date.today().isoformat()
        and previous_counts[item["file"],item["fingerprint"]] == current_counts[item["file"],item["fingerprint"]] == 1
    }
    for finding in findings:
        match = decisions.get((finding["fingerprint"], finding["file"]))
        if match:
            finding.update(triage=match["triage"], triageDecision=match["triageDecision"])


def fail_scan(store, signals, job, report, message):
    patch = {"status": "failed", "completedAt": now(), "error": message}
    patch["gate"] = evaluate_gate(report | patch)
    followups = []
    if report.get("event") and patch["gate"]["status"] != "disabled":
        patch["githubCheck"] = {"status": "queued", "message": "Ожидает публикации в GitHub."}
        followups.append(("github", {}))
    if store.complete(job, patch, followups) and followups:
        signals.notify("delivery")


def scan(store, signals, github, job, report):
    if job["attempt"] > 3:
        return fail_scan(store, signals, job, report, "Лимит попыток сканирования исчерпан.")
    if store.patch_active(job, {"status": "running", "startedAt": now()}) is None:
        return
    start = time.monotonic()
    version = report["workflow"]
    rules = version["spec"]["rules"]
    active = sorted({RULES[rule]["engine"] for rule in rules})
    event = report.get("event")
    trial = report.get("githubTrial")
    base = None
    if event:
        if not github:
            raise GitHubError("Интеграция GitHub отключена.")
        head, base = load_snapshots(github, event, engines=tuple(active))
    elif trial:
        revision, head = trial_snapshot(github, tuple(active))
    else:
        head = job["payload"]["sources"]

    def named_snapshot(snapshot):
        if snapshot is None or "files" in snapshot:
            return snapshot
        # Older fixed-path readers returned content under the engine name.
        # All detectors, including shared secret checks, need the actual Git path.
        return {"files": {path: snapshot.get(engine) for engine, path in github.paths.items() if path},
                "githubBinding": True}

    if event or trial:
        head, base = named_snapshot(head), named_snapshot(base)

    results = static_analysis(head, rules, base)
    project = report.get("projectId", "default")
    prior = store.get_run(report["baselineId"], project_id=project) if report["baselineId"] else None
    findings, stages = results["head"]
    if event:
        comparison = compare_base(findings, results.get("base"), stages, head, base)
    for finding in findings:
        finding["evidence"] = EVIDENCE.get(finding["ruleId"], finding["evidence"])
    scan_version = version | {"spec": version["spec"] | {"delivery": False}} if trial else version
    result = make_run(scan_version, head, report["source"], prior, report["origin"],
                      use_model=project == "default" and not trial, analysis=(findings, stages))
    carry_triage(findings, prior)
    IssueStore(store).apply_decisions(report, findings)

    delivery = result["delivery"]
    followups = []
    if event:
        if delivery:
            eligible = {f["id"] for f in findings if f["novelty"] == "new" and f["triage"] == "open"}
            delivery["findingIds"] = [item for item in delivery["findingIds"] if item in eligible]
            if not delivery["findingIds"]:
                delivery = None
                result["stages"][-1].update(status="skipped", message="Новых замечаний по условиям доставки нет.")
        followups.append(("github", {}))
    if delivery and delivery["status"] == "queued":
        followups.append(("smtp", {}))
    patch = {key: result[key] for key in ("status", "stages", "findings", "fixed")}
    patch.update({key: result[key] for key in ("inventory", "skipReason") if key in result})
    patch.update(
        delivery=delivery, coverage=result["coverage"], completedAt=now(),
        durationMs=round(1000 * (time.monotonic() - start)),
    )
    if event:
        patch.update(comparison=comparison, githubCheck={"status": "queued", "message": "Ожидает публикации в GitHub."})
    if trial:
        patch["revision"] = revision
        result["stages"][-1]["message"] = "Пробная проверка без внешней доставки."
    patch["gate"] = evaluate_gate(report | patch, baseline=prior)
    saved = store.complete(job, patch, followups)
    if saved and followups:
        signals.notify("delivery")


def report_url(url, report):
    project = report.get("projectId", "default")
    scope = f"?project={project}" if project != "default" else ""
    return f"{url}/{scope}#runs/{report['id']}"


def smtp(store, github, url, job, report):
    delivery = report["delivery"].copy()
    if delivery["status"] == "sending":
        delivery.update(status="unknown", message="Процесс завершился после начала отправки. Приём письма не подтверждён.")
    elif not SMTP or SMTP.recipient != delivery["address"]:
        delivery.update(status="failed", message="Проверьте настройки SMTP и исходный адрес доставки.")
    elif report.get("event") and (not github or not is_current_head(github, report["event"])):
        delivery.update(status="superseded", message="Pull request закрыт или появился новый коммит.")
    else:
        delivery.update(status="sending", attempts=delivery["attempts"] + 1, message="Отправка начата.")
        if store.patch_active(job, {"delivery": delivery}) is None:
            return
        status, message = send_summary(SMTP, report, report_url=report_url(url, report))
        delivery.update(status=status, message=message)
    store.complete(job, {"delivery": delivery})


def github_check(store, github, url, job, report):
    if not github:
        result = {"status": "failed", "message": "Интеграция GitHub отключена."}
    else:
        reconcile = report["githubCheck"]["status"] == "sending"
        if store.patch_active(job, {"githubCheck": {"status": "sending", "message": "Публикация в GitHub."}}) is None:
            return
        result = publish_check(github, report["event"], report, report_url(url, report), reconcile_only=reconcile)
    store.complete(job, {"githubCheck": result})


def handle_job(store, signals, github, url, job):
    report = store.get_run(job["run_id"])
    kind = job["kind"]
    try:
        if report.get("event") or report.get("githubTrial"):
            github = job_binding(store, github, report)
        if kind == "scan":
            scan(store, signals, github, job, report)
        elif kind == "smtp":
            smtp(store, github, url, job, report)
        else:
            github_check(store, github, url, job, report)
    except (GitHubError, subprocess.SubprocessError) as error:
        if kind == "scan":
            if isinstance(error, GitHubError) and error.retryable and job["attempt"] < 3:
                store.defer(job, 2**job["attempt"], {"status": "queued"})
                return
            message = str(error) if isinstance(error, GitHubError) else "Анализатор превысил лимит или завершился с ошибкой."
            fail_scan(store, signals, job, report, message)
        else:
            field = "delivery" if kind == "smtp" else "githubCheck"
            status = "unknown" if error.uncertain else "temporary" if error.retryable else "failed"
            store.complete(job, {field: report[field] | {"status": status, "message": str(error)}})


def loop(store, role, stop):
    signals = Signals()
    url = public_url()
    github = github_config(require_webhook=False)
    account_transport = account_smtp(SMTP) if role == "delivery" else None
    next_prune = 0
    report_days = int(os.getenv("BANK_REPORT_RETENTION_DAYS", "30"))
    job_hours = int(os.getenv("BANK_JOB_RETENTION_HOURS", "24"))
    if report_days < 1 or job_hours < 1:
        raise ValueError("Параметры хранения должны быть положительными.")
    while not stop.is_set():
        if os.name != "nt":
            HEARTBEAT.touch()
        try:
            if role == "scan" and time.monotonic() >= next_prune:
                store.prune(report_days, job_hours)
                next_prune = time.monotonic() + 300
            if role == "delivery":
                deliver_one(store, account_transport)
                deliver_reset(store, account_transport, url)
            job = store.claim(KINDS[role], BUSY_LEASE)
            if job is None:
                signals.wait(role)
            else:
                handle_job(store, signals, github, url, job)
        except Exception as error:
            logger.error("Worker %s operation failed (%s)", role, type(error).__name__)
            stop.wait(2)


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    if len(sys.argv) != 2 or sys.argv[1] not in (*KINDS, "migrate"):
        raise SystemExit("Использование: production_worker.py scan|delivery|migrate")
    role = sys.argv[1]
    store = database()
    if role == "migrate":
        store.migrate()
        store.initialize(PRESETS["full"], now())
        return
    stop = Event()
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda _signal, _frame: stop.set())
    loop(store, role, stop)


if __name__ == "__main__":
    main()
