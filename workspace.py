"""Versioned local workflows, execution reports, and recommendation deliveries."""

from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from urllib.request import HTTPRedirectHandler, Request, build_opener
from uuid import uuid4
import json
import os
import sqlite3
from contextlib import contextmanager

from analyzers import REPOSITORY_RULE_ID, RULES, repository_paths_checked, run_analysis
from delivery import send_summary, smtp_config
from settings import secret
from run_diagnostics import analysis_diagnostics
from case_severity import reaches


DATA = Path(os.getenv("BANK_DATA_DIR", Path(__file__).parent / ".data"))
SMTP = smtp_config()
PRESETS = {
    "full": {
        "name": "Проверка сервиса перед релизом", "rules": list(RULES),
        "trigger": "manual", "explain": True, "delivery": True,
        "minimum": "high", "recipient": "Команда сервиса", "deliveryChannel": "local"
    },
    "config": {
        "name": "Проверка настроек сервиса", "rules": ["CFG-001", "CFG-002"],
        "trigger": "push", "explain": True, "delivery": True,
        "minimum": "medium", "recipient": "Команда платформы", "deliveryChannel": "local"
    }
}
STEPS = [
    {"id": "source", "label": "Исходный код", "detail": "Ручной запуск", "number": "01"},
    {"id": "python", "label": "Анализ кода", "detail": "Секреты, Python и Kotlin", "number": "02"},
    {"id": "config", "label": "Настройки и зависимости", "detail": "JSON, Gradle и Maven", "number": "03"},
    {"id": "explain", "label": "Рекомендации", "detail": "Пояснение и исправление", "number": "04"},
    {"id": "gate", "label": "Условия приёмки", "detail": "Новые замечания", "number": "05"},
    {"id": "deliver", "label": "Доставка", "detail": "Сводка рекомендаций", "number": "06"}
]


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


AI_HTTP = build_opener(NoRedirect())


class WorkspaceError(ValueError):
    def __init__(self, message, status=400, *, code=None):
        self.status = status
        self.code = code
        super().__init__(message)


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def snapshot_revision(sources):
    return sha256(json.dumps(sources, ensure_ascii=False, sort_keys=True).encode()).hexdigest()[:12]


def public_settings():
    return {
        "llmConfigured": bool(os.getenv("BANK_AI_URL") and os.getenv("BANK_AI_MODEL")),
        "smtpConfigured": SMTP is not None
    }


def explain(finding):
    endpoint = os.getenv("BANK_AI_URL")
    model = os.getenv("BANK_AI_MODEL")
    reference = {key: finding[key] for key in ("ruleId", "title", "risk", "fix", "verify")}
    if endpoint and model:
        instruction = (
            "Кратко поясни безопасное исправление статической проверки по каталогу. "
            "Переформулируй только данные каталога на русском. "
            "Верни один JSON объект с двумя непустыми строками summary и action. "
            "Не добавляй команд, фрагментов кода, новых находок или оценок."
        )
        payload = {
            "model": model, "messages": [
                {"role": "system", "content": instruction},
                {"role": "user", "content": json.dumps(reference, ensure_ascii=False)}
            ],
            "max_tokens": 180, "temperature": 0.1
        }
        headers = {"Content-Type": "application/json"}
        if token := secret("BANK_AI_KEY"):
            headers["Authorization"] = f"Bearer {token}"
        try:
            request = Request(endpoint, data=json.dumps(payload).encode(), headers=headers)
            with AI_HTTP.open(request, timeout=4) as response:
                raw = json.loads(response.read(100_000))
            result = json.loads(raw["choices"][0]["message"]["content"])
            explanation = {key: result[key].strip() for key in ("summary", "action")}
            if all(1 <= len(text) <= 320 and b"\x00" not in text.encode() for text in explanation.values()):
                return explanation | {"origin": "llm"}
        except (ValueError, KeyError, IndexError, TypeError, AttributeError, OSError, RecursionError):
            pass
    return {"summary": finding["risk"], "action": finding["fix"], "origin": "catalog"}


def make_run(workflow, sources, source_label, previous=None, origin="manual", use_model=True, analysis=None):
    spec = workflow["spec"]
    findings, stages = analysis if analysis is not None else run_analysis(sources, spec["rules"])
    coverage = [dict(item, engine=step["id"]) for step in stages for item in step.pop("coverage", [])]
    inventory = sources.get("inventory")
    skip_reason = None
    if "files" in sources and not coverage:
        if inventory and inventory.get("emptyRepository"):
            skip_reason = "В репозитории ещё нет коммитов."
        elif inventory and inventory.get("totalFiles") == 0:
            skip_reason = "В выбранной области нет файлов для проверки."
        else:
            skip_reason = "Для включённых правил в снимке нет подходящих текстовых файлов."
    stages.insert(0, {"id": "source", "status": "done", "message": source_label})
    failed = {stage["id"] for stage in stages if stage["status"] == "error"}
    with_explanation = spec["explain"]
    recommendations = {}
    for finding in findings:
        finding["triage"] = "open"
        if with_explanation:
            rule = (finding["ruleId"], finding["risk"], finding["fix"])
            if rule not in recommendations:
                recommendations[rule] = explain(finding) if use_model else {
                    "summary": finding["risk"], "action": finding["fix"], "origin": "catalog"
                }
            finding["recommendation"] = recommendations[rule]
    stages.append({
        "id": "explain", "status": "done" if with_explanation else "skipped",
        "message": f"Карточек: {len(findings)}" if with_explanation else "Шаг отключён"
    })

    qualifying = [finding for finding in findings if reaches(finding.get("level"), spec["minimum"])]
    delivery = None
    stage = {"id": "deliver", "status": "skipped", "message": "Шаг отключён"}
    if spec["delivery"] and qualifying:
        channel = spec.get("deliveryChannel", "local")
        delivery = {
            "channel": channel, "recipient": spec["recipient"],
            "findingIds": [finding["id"] for finding in qualifying]
        }
        if channel == "local":
            delivery["status"] = "simulated"
            stage.update(status="done", message="Сохранено в локальную очередь")
        elif SMTP:
            delivery.update(status="queued", address=SMTP.recipient, attempts=0)
            stage.update(status="pending", message="Ожидает отправки по SMTP")
        else:
            delivery.update(status="failed", attempts=0, message="SMTP не настроен.")
            stage.update(status="error", message=delivery["message"])
    elif spec["delivery"]:
        stage["message"] = "Нет замечаний по условиям доставки"
    stages.append(stage)
    if failed:
        status = "partial"
    elif findings:
        status = "review"
    elif skip_reason:
        status = "skipped"
    else:
        status = "passed"
    run = {
        "id": uuid4().hex[:12], "createdAt": now(), "workflow": workflow, "source": source_label,
        "revision": snapshot_revision(sources), "origin": origin, "baselineId": previous["id"] if previous else None,
        "status": status,
        "stages": stages, "findings": findings, "fixed": [], "delivery": delivery, "coverage": coverage,
    }
    if inventory is not None:
        run["inventory"] = inventory
    if skip_reason:
        run["skipReason"] = skip_reason
    if previous and not failed:
        observed = {(item["file"], item["ruleId"], item.get("fingerprint")) for item in findings}
        # Historical findings without fingerprints can only be compared at file and rule level.
        observed.update({(item["file"], item["ruleId"], None) for item in findings})
        checked_files = {(item["file"], item["engine"]) for item in coverage if item["status"] == "done"}
        paths_comparable = repository_paths_checked(previous) and repository_paths_checked(run)
        for item in previous["findings"]:
            path, rule = item["file"], item["ruleId"]
            checked = (paths_comparable if rule == REPOSITORY_RULE_ID
                       else rule in spec["rules"] and (path, RULES.get(rule, {}).get("engine")) in checked_files)
            if checked and (path, rule, item.get("fingerprint")) not in observed:
                run["fixed"].append(item)
    if analysis is None and spec.get("gateMinimum", "off") != "off":
        from release_review import evaluate_gate
        run["gate"] = evaluate_gate(run, previous)
    return run


def seed():
    draft = deepcopy(PRESETS["full"])
    version = {"number": 1, "publishedAt": now(), "spec": deepcopy(draft)}
    return {"draft": draft, "version": version, "runs": []}


def decode_state(raw):
    state = json.loads(raw)
    for spec in (state["draft"], state["version"]["spec"]):
        spec.setdefault("deliveryChannel", "local")
    return state


def uses_original_full_preset(state):
    version = state["version"]
    original = ["PY-001", "PY-002", "CFG-001", "CFG-002"]
    previous = ["PY-001", "PY-002", "PY-003", "CFG-001", "CFG-002"]
    return (version["spec"] == state["draft"] and
            (version["number"] == 1 and version["spec"] == PRESETS["full"] | {"rules": original} or
             version["number"] in (1, 2) and version["spec"] == PRESETS["full"] | {"rules": previous}))


@contextmanager
def connect():
    DATA.mkdir(exist_ok=True, parents=True)
    db = sqlite3.connect(DATA / "workspace.sqlite3", timeout=5)
    try:
        db.execute("CREATE TABLE IF NOT EXISTS workspace (id INTEGER PRIMARY KEY, data TEXT NOT NULL)")
        yield db
    finally:
        db.close()


def get_or_seed(db):
    row = db.execute("SELECT data FROM workspace WHERE id = 1").fetchone()
    if row:
        state = decode_state(row[0])
        if uses_original_full_preset(state):
            state["draft"] = deepcopy(PRESETS["full"])
            state["version"] = {"number": state["version"]["number"] + 1, "publishedAt": now(), "spec": deepcopy(state["draft"])}
        return state
    state = seed()
    db.execute("INSERT INTO workspace (id, data) VALUES (1, ?)", (json.dumps(state, ensure_ascii=False),))
    return state


def change(action):
    with connect() as db:
        with db:
            db.execute("BEGIN IMMEDIATE")
            state = get_or_seed(db)
            result = action(state)
            db.execute("UPDATE workspace SET data = ? WHERE id = 1", (json.dumps(state, ensure_ascii=False),))
    return result


def read_state():
    with connect() as db:
        row = db.execute("SELECT data FROM workspace WHERE id = 1").fetchone()
        if row:
            state = decode_state(row[0])
            if not uses_original_full_preset(state):
                return state
    return change(lambda state: state)


def get_workspace():
    from case_archive import SOURCE_POLICY
    state = read_state()
    state.pop("audit", None)
    return state | {
        "runs": [run | {"diagnostics": analysis_diagnostics(run)} for run in state["runs"]],
        "rules": RULES, "presets": PRESETS, "steps": STEPS, "settings": public_settings(), "sourcePolicy": SOURCE_POLICY,
    }


def validate_spec(spec):
    if not isinstance(spec, dict):
        raise WorkspaceError("Укажите параметры сценария.")
    name, recipient = spec.get("name"), spec.get("recipient")
    rules = spec.get("rules")
    if not isinstance(name, str) or not 2 <= len(name.strip()) <= 70:
        raise WorkspaceError("Название сценария должно содержать от 2 до 70 символов.")
    if not isinstance(rules, list) or len(rules) > len(RULES) or any(not isinstance(rule, str) or rule not in RULES for rule in rules):
        raise WorkspaceError("Выберите правила из каталога.")
    if not rules:
        raise WorkspaceError("Включите хотя бы одно правило.")
    if spec.get("trigger") not in ("manual", "push", "pull_request") or spec.get("minimum") not in ("high", "medium"):
        raise WorkspaceError("Проверьте тип запуска и порог доставки.")
    if any(not isinstance(spec.get(key), bool) for key in ("explain", "delivery")):
        raise WorkspaceError("Проверьте параметры шагов.")
    if not isinstance(recipient, str) or len(recipient.strip()) > 80 or (spec["delivery"] and not recipient.strip()):
        raise WorkspaceError("Укажите команду получателя длиной до 80 символов.")
    channel = spec.get("deliveryChannel", "local")
    if channel not in ("local", "smtp"):
        raise WorkspaceError("Выберите канал доставки.")
    gate = spec.get("gateMinimum", "off")
    if gate not in ("off", "high", "medium"):
        raise WorkspaceError("Выберите допустимое условие приёмки.")
    return {
        "name": name.strip(), "recipient": recipient.strip(), "rules": list(dict.fromkeys(rules)),
        "deliveryChannel": channel,
        **({"gateMinimum": gate} if gate != "off" else {}),
        **{key: spec[key] for key in ("trigger", "minimum", "explain", "delivery")}
    }


def record_local_action(state, action, subject):
    events = state.setdefault("audit", [])
    event_id = events[-1]["id"] + 1 if events else 1
    events.append({"id": event_id, "createdAt": now(), "action": action, "subject": subject})
    del events[:-1000]


def save_draft(spec):
    draft = validate_spec(spec)

    def apply(state):
        state["draft"] = draft
        record_local_action(state, "save_draft", "workflow")
        return draft
    return change(apply)


def publish(spec):
    draft = validate_spec(spec)
    if draft["delivery"] and draft["deliveryChannel"] == "smtp" and not SMTP:
        raise WorkspaceError("Настройте SMTP на сервере перед публикацией сценария.")

    def apply(state):
        state["draft"] = draft
        if draft != state["version"]["spec"]:
            state["version"] = {"number": state["version"]["number"] + 1, "publishedAt": now(), "spec": draft}
            record_local_action(state, "publish", str(state["version"]["number"]))
        return state["version"]
    return change(apply)


def find_run(state, run_id):
    for run in state["runs"]:
        if run["id"] == run_id:
            return run
    raise WorkspaceError("Запуск не найден.", 404)


def set_delivery_status(run, status, message):
    delivery = run["delivery"]
    delivery.update(status=status, message=message, at=now())
    stage = next(stage for stage in run["stages"] if stage["id"] == "deliver")
    stage.update(status={"sent": "done", "sending": "pending"}.get(status, "error"), message=message)


def retry_delivery(payload):
    run_id = payload.get("runId")

    def claim(state):
        run = find_run(state, run_id)
        delivery = run["delivery"]
        if not delivery or delivery["status"] not in ("queued", "temporary"):
            raise WorkspaceError("Для этой записи повторная отправка недоступна.", 409)
        if not SMTP or SMTP.recipient != delivery["address"]:
            raise WorkspaceError("Настройте SMTP с адресом, указанным в записи доставки.", 409)
        delivery["attempts"] += 1
        set_delivery_status(run, "sending", "Отправка начата. Приём письма пока не подтверждён.")
        return run

    claimed = change(claim)
    status, message = send_summary(SMTP, claimed, int(os.getenv("PORT", "8103")))

    def finish(state):
        run = next((item for item in state["runs"] if item["id"] == run_id), claimed)
        set_delivery_status(run, status, message)
        return run

    return change(finish)


def folder_inventory(paths, files, unreadable=()):
    from case_archive import accepts, repository_inventory
    if not isinstance(paths, list):
        raise WorkspaceError("Передайте до 12 000 относительных путей внутри папки проекта.")
    inventory = repository_inventory(paths)
    if not isinstance(unreadable, (tuple, list)) or len(unreadable) > len(paths) or any(not isinstance(p, str) for p in unreadable):
        raise WorkspaceError("Проверьте список непрочитанных файлов папки.")
    unavailable = set(unreadable)
    names = set(paths)
    if not (set(files) | unavailable) <= names or unavailable.intersection(files):
        raise WorkspaceError("Переданные файлы должны входить в перечень путей выбранной папки.")
    if any(accepts(p, "python") and p not in files and p not in unavailable for p in names):
        raise WorkspaceError("Передайте текст и перечень непрочитанных файлов выбранной папки.")
    return inventory


def repository_files(files, inventory=None):
    from case_archive import accepts, valid_path
    if not isinstance(files, dict) or len(files) > 250:
        raise WorkspaceError("Выберите модуль, содержащий до 250 текстовых файлов.")
    total = 0
    for path, content in files.items():
        if not valid_path(path) or len(path) > 350 or not accepts(path, "repository"):
            raise WorkspaceError("Выберите текстовые файлы исходного проекта с относительными путями.")
        if content is None and inventory and inventory.get("scope") == "paths":
            # A missing explicit path is reported alongside files successfully read at this revision.
            continue
        if not isinstance(content, str) or "\x00" in content:
            raise WorkspaceError(f"Файл {path} должен содержать текст UTF-8.")
        try:
            size = len(content.encode("utf-8"))
        except UnicodeEncodeError:
            raise WorkspaceError(f"Файл {path} должен содержать текст UTF-8.") from None
        if size > 300_000:
            raise WorkspaceError(f"Файл {path} превышает 300 КБ.")
        total += size
    if total > 3_000_000:
        raise WorkspaceError("Выберите модуль до 3 МБ текстовых файлов.")
    return {"files": files, **({"inventory": inventory} if inventory is not None else {})}


def select_sources(payload, *, store=None, project="default"):
    if payload.get("preset", "custom") != "custom":
        raise WorkspaceError("Выберите свой репозиторий, архив или исходные файлы.")
    if "repository" in payload:
        from case_repository import source_files
        snapshot = source_files(store, project, payload["repository"], payload.get("revision"), mode="repository")
        repo = snapshot["repository"]
        sources = repository_files(snapshot["files"], snapshot.get("inventory"))
        return sources, repo, "github-read:" + repo.lower(), snapshot["revision"]
    if "archive" in payload:
        from case_archive import archive_snapshot, decode_archive
        snapshot = archive_snapshot(decode_archive(payload["archive"]), "repository")
        sources = repository_files(snapshot["files"], snapshot["inventory"])
    elif "files" in payload:
        sources = repository_files(payload["files"])
        if "filePaths" in payload:
            sources["inventory"] = folder_inventory(payload["filePaths"], sources["files"], payload.get("unreadablePaths", ()))
    else:
        sources = payload.get("sources")
        if not isinstance(sources, dict) or any(
            not isinstance(sources.get(key), str) or len(sources[key]) > 30_000 for key in ("python", "config")
        ):
            raise WorkspaceError("Укажите исходники длиной до 30 000 символов на файл.")
        sources = {key: sources[key] for key in ("python", "config")}
    return sources, "Пользовательский снимок", "custom", snapshot_revision(sources)


def execute(payload):
    state = read_state()
    snapshot = state["version"]
    origin = payload.get("origin", "manual")
    if origin not in ("manual", "push") or (origin == "push" and snapshot["spec"]["trigger"] != "push"):
        raise WorkspaceError("Событие push должно быть выбрано в опубликованном сценарии.")
    sources, label, lineage, revision = select_sources(payload)

    previous = find_run(state, payload["baselineId"]) if payload.get("baselineId") else None
    if previous and (previous.get("lineage") or ("custom" if previous["source"] == "Пользовательский снимок" else previous.get("source"))) != lineage:
        raise WorkspaceError("Для сравнения выберите файлы из того же проекта.")
    run = make_run(snapshot, sources, label, previous, origin)
    run.update(lineage=lineage, revision=revision)

    def apply(current):
        prior = next((
            item for item in current["runs"]
            if origin == "push" and item["origin"] == "push"
            and item["revision"] == run["revision"] and item["workflow"]["number"] == snapshot["number"]
        ), None)
        if prior:
            return prior, False
        current["runs"] = [run, *current["runs"]][:50]
        return run, True

    result, created = change(apply)
    if created and result["delivery"] and result["delivery"]["status"] == "queued":
        try:
            return retry_delivery({"runId": result["id"]})
        except WorkspaceError as error:
            if error.status not in (404, 409):
                raise
            current = read_state()
            return next((item for item in current["runs"] if item["id"] == result["id"]), result)
    return result


def triage(payload):
    status = payload.get("status")
    if status not in ("open", "accepted", "false_positive"):
        raise WorkspaceError("Выберите статус из списка.")

    def apply(state):
        run = find_run(state, payload.get("runId"))
        finding = next((item for item in run["findings"] if item["id"] == payload.get("findingId")), None)
        if finding is None:
            raise WorkspaceError("Замечание не найдено.", 404)
        finding["triage"] = status
        record_local_action(state, "finding.triage", run["id"])
        return run
    return change(apply)
