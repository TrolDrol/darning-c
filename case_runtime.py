"""Workflow application service. Input source is read only inside the worker."""
from contextlib import nullcontext
from email.message import EmailMessage
from hashlib import sha256
from functools import cache
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from threading import Event, Lock, Thread
from urllib.parse import urlencode

from case_source import advisory_database
from case_archive import archive_snapshot, decode_archive, repository_inventory
from delivery import account_smtp, send_message, send_summary, smtp_config
from workspace import WorkspaceError, folder_inventory, repository_files
import case_model
from case_graph import AUTOMATIC_TRIGGERS, SCANNERS, TRIGGERS, finding_identity, is_bound_source, merge_finding
from case_repository import dependency_baseline, github_error, markers, public_snapshot, resolve_repository, selected_revision, snapshot, source_files, source_marker
from case_dependency_review import ENGINE as PR_DEPENDENCIES, LIMITS as PR_DEPENDENCY_LIMITS, manifest_inputs
from github_integration import GitHubError
from case_scan_cache import ScanCache

SCHEDULE_SOURCE_REQUIRED = "Для расписания подключите репозиторий проекта и выберите его в блоке источника."
SCHEDULE_POLL_SECONDS = 5


def scan_file(kind, path, params):
    from case_unified import applicable
    from case_web_review import applies as web_source
    directory = params.get("directory")
    if directory and not path.startswith(directory + "/"):
        return False
    if kind in ("github_actions", "dockerfile"):
        from case_pipeline_checks import applies
        return applies(kind, path)
    if kind == "java_review":
        return path.lower().endswith(".java")
    if kind == "spring_review":
        from case_spring_review import applies
        return applies(path) or path.lower().endswith((".kt", ".java"))
    if kind == "spring_routes":
        from case_spring_routes import applies
        return applies(path)
    if kind == "package_review":
        from case_package_review import applies
        return applies(path)
    if kind == "literal_review":
        from case_literal_review import applies
        return applies(path, params)
    if kind == "json_keys":
        return path.lower().endswith(".json")
    if kind == "sast":
        language = ("kotlin" if applicable(path, "sast") else "python" if path.lower().endswith(".py")
                    else "json" if path.lower().endswith(".json") else "javascript" if web_source(path) else None)
        return language is not None and params.get("language", language) == language
    if kind in ("sca", "dependency_review"):
        manifest = {"build.gradle.kts":"gradle", "pom.xml":"maven"}.get(path.rsplit("/", 1)[-1])
        return manifest is not None and params.get("manifest", manifest) == manifest
    return True

def analyze(kind, files, advisories, with_coverage=False, memo=None):
    request = json.dumps([kind, files, advisories if kind in ("sca", "dependency_review", "package_review", "literal_review") else None]).encode()

    def invoke():
        proc = subprocess.run([sys.executable, "-I", "-B", str(Path(__file__).with_name("case_scan_process.py"))],
                              input=request, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30,
                              env={k:v for k,v in os.environ.items() if k.upper() in ("SYSTEMROOT","WINDIR","LANG","LC_ALL")})
        if proc.returncode or len(proc.stdout) > 6_000_000:
            raise ValueError("Анализатор не смог завершить проверку.")
        return proc.stdout

    result = json.loads(memo.run(request, invoke) if memo is not None else invoke())
    if isinstance(result,dict) and "inputError" in result:
        raise WorkspaceError(result["inputError"])
    if isinstance(result,dict) and "coverage" in result and not with_coverage:
        if any(row["status"] == "error" for row in result["coverage"]):
            raise WorkspaceError("Не удалось перепроверить весь исходный снимок.")
        return result["findings"]
    return result

def send_notice(project, run_id, findings, summary, revision, graph_version, *, partial=False, store=None,
                initiator=None, automatic=False):
    from case_account_email import automatic_project_recipient, operator_project_recipient, project_recipient

    url = os.getenv("BANK_PUBLIC_URL","http://127.0.0.1:8103").rstrip("/") + "/?" + urlencode({"project":project}) + "#studio/" + run_id
    if os.getenv("BANK_PRODUCTION") == "1" and not operator_project_recipient(project):
        recipient = None
        if store and store.postgres:
            if automatic:
                recipient = automatic_project_recipient(store.postgres,project)
            elif initiator:
                recipient = project_recipient(store.postgres,project,initiator)
        if not recipient:
            if automatic:
                return "failed","Назначьте подтверждённый адрес в разделе «Проекты → Участники → Получатель SMTP»."
            return "failed","Подтвердите почту в своём профиле и повторите запуск с доступом редактора к проекту."
        try:
            config = account_smtp(None,recipient=recipient) or smtp_config(recipient=recipient)
        except ValueError:
            return "failed","Администратору нужно проверить параметры отправителя и авторизацию SMTP."
        if not config:
            return "failed","Администратору нужно настроить SMTP для отправки отчётов."
        notice = EmailMessage()
        notice["From"], notice["To"] = config.sender, config.recipient
        notice["Subject"] = "Штопка · результат проверки"
        status = "Проверка выполнена частично." if partial else "Проверка завершена."
        notice.set_content(f"{status}\nЗамечаний: {len(findings)}.\n\nОткрыть отчёт после входа в «Штопку»:\n{url}")
        return send_message(config,notice)
    config = smtp_config()
    if not config:
        return "failed","Укажите SMTP для ноды уведомления."
    items = []
    actions = {}
    for group in (summary or {}).get("groups",[]):
        for loc in group.get("evidence",[]):
            actions[(loc.get("path"),loc.get("line"),loc.get("advisoryId"))] = group.get("action","")
    for index, item in enumerate(findings[:100]):
        action = actions.get((item["path"],item.get("line"),item.get("advisoryId"))) or item.get("fix","")
        items.append({"id":str(index),"ruleId":item.get("class") or item.get("advisoryId",""),
                      "title":item.get("title") or item["category"],"fix":action})
    payload = {"workflow":{"number":graph_version},"subject":"Штопка · отчёт графа " + graph_version,
               "status":"partial" if partial else "passed","revision":revision,"id":run_id,
               "delivery":{"findingIds":[i["id"] for i in items]},"findings":items}
    return send_summary(config,payload,report_url=url)

class Studio:
    def __init__(self, store):
        from case_repair import RepairSessions
        from case_telegram import TelegramIntegration
        self.store = store
        self.telegram = TelegramIntegration(store)
        self.repair = RepairSessions(self)
        self.worker_lock = Lock()
        self.stop = Event()
        self.wake = Event()
        self.thread = None

    def start(self):
        with self.worker_lock:
            if self.thread is None or not self.thread.is_alive():
                self.thread = Thread(target=self.loop,daemon=True,name="case-studio")
                self.thread.start()

    def poll_schedule(self):
        import logging
        while not self.stop.is_set():
            try:
                self.store.tick()
                self.wake.set()
            except Exception as exc:
                logging.getLogger(__name__).error("Studio scheduler: %s", type(exc).__name__)
            self.stop.wait(SCHEDULE_POLL_SECONDS)

    def loop(self):
        import logging
        Thread(target=self.poll_schedule, daemon=True, name="case-scheduler").start()
        if self.store.postgres:
            Thread(target=self.repair.loop, daemon=True, name="case-repair").start()
        while not self.stop.is_set():
            try:
                if self.store.postgres:
                    self.telegram.process_one()
                claimed = self.store.claim()
                if claimed:
                    self.process(*claimed)
                    continue
            except Exception as exc:
                logging.getLogger(__name__).error("Studio worker: %s",type(exc).__name__)
            self.wake.wait(2)
            self.wake.clear()

    def action(self, project, organization, payload, *, actor=None):
        from case_graph import GraphError, validate_graph
        from case_store import DEFAULT_AUTOMATION, automation_id
        action = payload.get("action")
        selected = automation_id(payload.get("automationId", DEFAULT_AUTOMATION))
        if action == "pause":
            return self.store.pause(project, selected)
        if action == "create":
            return self.store.create(project, payload.get("name"))
        if action == "library_import":
            from case_library import import_template
            return import_template(self.store, project, organization, payload)
        if action=="copy":
            return self.store.copy_template(project,organization,str(payload.get("id","")))
        if action=="generate":
            from case_intelligence import generate_graph
            prompt = payload.get("prompt")
            if not isinstance(prompt,str) or not 1<=len(prompt.strip())<=2000:
                raise WorkspaceError("Введите описание сценария (до 2000 знаков).")
            try:
                with case_model.using(self.store,project):
                    graph = generate_graph(prompt, payload.get("timezone") or "Europe/Moscow")
                bindings=markers(self.store,project)
                if bindings:
                    named=[b for b in bindings if re.search(
                        r"(?<![\w.-])"+re.escape(b["repository"])+r"(?:\.git)?(?![\w-]|\.[\w-])",prompt,re.I)]
                    if len(named)>1:
                        raise WorkspaceError("Для одного сценария выберите один подключённый репозиторий.")
                    target=(named or bindings)[0]
                    source=next(n for n in graph["nodes"] if n["type"]=="source")
                    source["params"]["repository"]="@bound:"+target["bindingId"]
                return {"graph": validate_graph(graph)}
            except ValueError as exc:
                raise WorkspaceError(str(exc),422) from None
        complete = True
        try:
            candidate = payload.get("graph")
            if action=="run" and "graph" not in payload:
                candidate = self.store.automation(project, selected)["graph"]
            try:
                graph = validate_graph(candidate)
            except GraphError:
                if action != "save" or selected == DEFAULT_AUTOMATION:
                    raise
                graph = validate_graph(candidate, draft=True)
                complete = False
        except GraphError as exc:
            raise WorkspaceError(str(exc)) from None
        if action=="save":
            enabled = payload.get("triggerEnabled")
            if "triggerEnabled" in payload and type(enabled) is not bool:
                raise WorkspaceError("Укажите, включён ли автоматический запуск.")
            if enabled is None and payload.get("enableSchedule") is True:
                enabled = True
            if enabled is True and (not complete or not any(n["type"] in AUTOMATIC_TRIGGERS for n in graph["nodes"])):
                raise WorkspaceError("Для включения выберите автоматический триггер и завершите граф.")
            node=next((n for n in graph["nodes"] if n["type"]=="source"), None)
            reference=node["params"].get("repository") if node else None
            if is_bound_source(reference):
                bound=source_marker(self.store,project,reference)
                if not bound:
                    if any(n["type"]=="schedule" for n in graph["nodes"]):
                        raise WorkspaceError(SCHEDULE_SOURCE_REQUIRED,409)
                    raise WorkspaceError("Выберите доступный репозиторий в блоке источника.",409)
                node["params"]["repository"]="@bound:"+bound["bindingId"]
            elif complete and enabled is not False and any(n["type"] == "schedule" for n in graph["nodes"]):
                raise WorkspaceError(SCHEDULE_SOURCE_REQUIRED,409)
            return self.store.save(project, graph, selected, name=payload.get("name"), complete=complete,
                                   trigger_enabled=enabled,
                                   expected_revision=payload.get("expectedRevision"))
        if action=="template":
            if "scope" not in payload:
                return self.store.template(organization, graph, payload.get("name"), payload.get("description"))
            from case_library import publish
            return publish(self.store, organization, payload.get("scope","organization"), graph,
                           payload.get("name"), payload.get("description"))
        if action!="run":
            raise WorkspaceError("Неизвестное действие конструктора.")
        if any(n["type"] in AUTOMATIC_TRIGGERS for n in graph["nodes"]):
            raise WorkspaceError("Этот сценарий запускается автоматически. Включите ожидание его триггера.", 409)
        repo = payload.get("repository")
        inventory = None
        if "archive" in payload:
            if "files" in payload or repo is not None:
                raise WorkspaceError("Выберите один источник для запуска.")
            unpacked = archive_snapshot(decode_archive(payload["archive"]), "repository")
            payload = dict(payload, files=unpacked["files"])
            inventory = unpacked["inventory"]
        if repo is None and "files" not in payload:
            repo=next(n for n in graph["nodes"] if n["type"]=="source").get("params",{}).get("repository")
            if repo is None:
                raise WorkspaceError("Выберите репозиторий или загрузите свои файлы.")
        if repo is not None and "files" in payload:
            raise WorkspaceError("Выберите один источник: репозиторий, папку или ZIP.")
        revision=selected_revision(payload["revision"]) if "revision" in payload else None
        if repo is not None:
            name,bound=resolve_repository(self.store,project,repo)
            if bound:
                if not is_bound_source(repo) and not payload.get("emptyRepository"):
                    selected_revision(revision)
                source={"repository":"@bound:"+bound["bindingId"],"binding":bound}
                if revision:
                    source["revision"]=revision
            elif payload.get("emptyRepository") is True and revision is None:
                source={"repository":name, "emptyRepository":True}
            else:
                source={"repository":name,"revision":selected_revision(revision)}
        else:
            source = repository_files(payload.get("files"))
            if inventory is None and "filePaths" in payload:
                inventory = folder_inventory(payload["filePaths"], source["files"], payload.get("unreadablePaths", ()))
            source["inventory"] = inventory if inventory is not None else repository_inventory(source["files"])
        if "advisories" in payload and payload["advisories"] is not None:
            data = payload["advisories"]
            if not isinstance(data,dict) or not isinstance(data.get("vulnerabilities"),list) or len(data["vulnerabilities"])>1500 or len(json.dumps(data,ensure_ascii=False,separators=(",",":")).encode())>500000:
                raise WorkspaceError("Проверьте формат и размер справочника SCA.")
            from case_sca import advisory_index
            from case_package_review import package_advisory_index
            try:
                advisory_index(data)
                package_advisory_index(data)
            except ValueError as exc:
                raise WorkspaceError(str(exc)) from None
            source["advisories"] = data
        if "dependencyMetrics" in payload and type(payload["dependencyMetrics"]) is not bool:
            raise WorkspaceError("Проверьте параметр публичных метрик.")
        source["dependencyMetrics"]=payload.get("dependencyMetrics",False)
        if actor:
            source["createdBy"] = actor
        report = self.store.enqueue(project,graph,source,selected,manual=True)
        self.wake.set()
        return report

    def process(self, project, payload, report):
        from case_graph import execute_graph, GraphError, PacketTrace
        from case_intelligence import explain_findings, verify_explanation
        trace=PacketTrace(report)
        report["explanations"]={}
        active_id=None
        report["deliveries"] = {}
        advice_by_node = {}
        predecessors = {node["id"]: [] for node in report["graph"]["nodes"]}
        for edge in report["graph"]["edges"]:
            predecessors[edge["to"]].append(edge)
        graph_hash = sha256(json.dumps(report["graph"],sort_keys=True).encode()).hexdigest()[:12]
        report["graphVersion"] = graph_hash
        trigger = next((n["type"] for n in report["graph"]["nodes"] if n["type"] in TRIGGERS), None)
        if trigger in AUTOMATIC_TRIGGERS and trigger != payload.get("trigger"):
            # An older client could queue a timed or event graph with the manual button.
            report.update(status="skipped", coverage=[], skipReason="В очереди отсутствует событие выбранного триггера.")
            self.store.update(report, finished=True)
            return
        files = {}
        missing = []
        db = payload.get("advisories") or advisory_database()
        reported = {}
        coverage = {}
        input_counts = {}
        scanner_outputs = {}
        scan_cache = ScanCache()
        metric_files = {}
        report["coverage"] = []
        @cache
        def load_dependency_base():
            event = payload.get("event") or {}
            info = {"scope": PR_DEPENDENCY_LIMITS}
            base_sha, head_sha = event.get("baseSha"), event.get("revision")
            event_baseline = event.get("type") in ("github_pr", "webhook") and base_sha and head_sha
            if not event_baseline:
                base_sha = (payload.get("repair") or {}).get("baseRevision")
                head_sha = payload.get("revision") if base_sha else None
                if base_sha:
                    info["baselineKind"] = "repair"
            if not base_sha or not head_sha or not payload.get("binding"):
                return {}, info, "Запустите сценарий событием GitHub Pull request или передайте baseRevision через HTTP-вебхук."
            info.update(baseSha=base_sha, headSha=head_sha)
            if head_sha != report["source"]["revision"]:
                return {}, info, "Ревизия источника не совпадает с проверяемым коммитом."
            try:
                ancestor, baseline = dependency_baseline(self.store, project, payload["binding"], base_sha, head_sha)
            except (GitHubError, WorkspaceError, OSError) as exc:
                reason = str(github_error(exc)) if isinstance(exc, GitHubError) else str(exc) if isinstance(exc, WorkspaceError) else "Проверьте доступ к GitHub."
                return {}, info, "Не удалось получить базу для сравнения. " + reason
            return baseline, info | {"mergeBaseSha": ancestor}, ""

        def partial_result():
            return (any(item["status"] == "error" for item in coverage.values())
                    or any(item["rejected"] for item in report.get("aiReviews", {}).values()))

        def model_for(params):
            reference = params.get("modelReference")
            if reference is not None:
                return case_model.using_profile(reference.profile)
            return case_model.using(self.store, project, params.get("connection"), model=params.get("model"))

        def node(kind, params, incoming):
            nonlocal files, missing
            if kind=="source":
                reference=payload.get("repository")
                trace.data["inputs"][active_id]["source"] = {
                    "kind": "repository" if reference else "upload",
                    "revision": payload.get("revision"),
                }
                if is_bound_source(reference):
                    expected=payload.get("binding")
                    if not expected and payload.get("trigger")=="schedule":
                        expected=source_marker(self.store,project,reference)
                        if not expected:
                            raise WorkspaceError(SCHEDULE_SOURCE_REQUIRED,409)
                    if reference != "@bound" and (not expected or reference != "@bound:"+expected["bindingId"]):
                        raise WorkspaceError("Источник запуска не совпадает с выбранным репозиторием.",409)
                    files,report["source"]=snapshot(self.store,project,expected,payload.get("revision"),mode="repository",include_branch=True)
                    if payload.get("repair"):
                        report["source"].update(branch=payload["repair"]["branch"], historical=True)
                    missing = [path for path, text in files.items() if text is None]
                    files = {path: text for path, text in files.items() if text is not None}
                elif payload.get("repository") and (payload.get("revision") or payload.get("emptyRepository")):
                    loaded = (public_snapshot(payload["repository"], payload["revision"], "repository") if payload.get("revision")
                              else source_files(self.store, project, reference, None, "repository"))
                    files = loaded["files"]
                    report["source"]={"files":len(files), "repository":reference, "revision":payload.get("revision"),
                                      "inventory":loaded["inventory"]}
                else:
                    files = repository_files(payload.get("files"))["files"]
                    report["source"] = {"files":len(files),"repository":None,"revision":sha256(json.dumps(files,sort_keys=True,ensure_ascii=False).encode()).hexdigest()}
                    report["source"]["inventory"] = payload.get("inventory") or repository_inventory(files)
                trace.source(files,report["source"]["revision"])
                return sorted(files)
            elif kind in SCANNERS:
                checked = {path: body for path, body in files.items() if scan_file(kind, path, params)}
                manifest_source = files | dict.fromkeys(missing) if kind == "sca" and missing else files
                inputs = manifest_inputs(manifest_source, checked) if kind in ("sca", "dependency_review") else checked
                input_counts[active_id] = len(checked)
                trace.data["inputs"][active_id]["fileRefs"] = [
                    i for i, item in enumerate(trace.data["snapshot"]["files"]) if item["path"] in inputs]
                if kind == "dependency_review":
                    base, info, error = load_dependency_base()
                    trace.data["inputs"][active_id]["comparison"] = info
                    if error:
                        results = {"findings": [], "coverage": [{"file":"GitHub PR", "engine":PR_DEPENDENCIES,
                                                                 "status":"error", "message":error}]}
                    else:
                        base_inputs = manifest_inputs(base, [p for p in base if scan_file(kind, p, params)])
                        head_inputs = files | dict.fromkeys(missing)
                        head_inputs = manifest_inputs(head_inputs, [p for p in head_inputs if scan_file(kind, p, params)])
                        if (info.get("baselineKind") == "repair" and base_inputs == head_inputs
                                and all(isinstance(body, str) for body in head_inputs.values())):
                            results = {"findings": [], "coverage": [
                                {"file": path, "engine": PR_DEPENDENCIES, "status": "done",
                                 "message": "Файл зависимостей совпадает с исходным снимком."} for path in sorted(checked)
                            ]}
                        else:
                            results = analyze(kind, {"base":base_inputs, "head":head_inputs}, db, True, scan_cache)
                else:
                    results = analyze(kind, inputs, params if kind == "literal_review" else db, True, scan_cache) if checked else []
                if isinstance(results, dict):
                    if kind == "spring_routes":
                        report.setdefault("sourceRoutes", {})[active_id] = results["routes"]
                    entries, results = results["coverage"], results["findings"]
                else:
                    entries = [{"file": path, "engine": kind, "status": "done", "message": "Проверено"} for path in checked]
                for path in missing:
                    engine = next((engine for language, engine in (("python", "python"), ("json", "config"), ("javascript", "javascript"))
                                   if scan_file("sast", path, {"language": language})), None) if kind == "sast" else None
                    if kind != "dependency_review" and scan_file(kind, path, params):
                        entries.append({"file":path, "engine":(engine if kind=="sast" else None) or kind, "status":"error",
                                        "message":"Указанный файл не найден в этой версии."})
                for entry in entries:
                    scope = (entry["engine"], entry["file"])
                    if coverage.get(scope, {}).get("status") != "error":
                        coverage[scope] = entry
                report["coverage"] = list(coverage.values())
                scanner_outputs[active_id] = {
                    "checked": sum(entry["status"] == "done" for entry in entries),
                    "errors": [{k: entry[k] for k in ("file", "engine", "line", "column", "message") if k in entry}
                               for entry in entries if entry["status"] == "error"],
                }
                if kind == "secrets":
                    from analyzers import inspect_repository_paths
                    inventory = report["source"].get("inventory")
                    if inventory:
                        path_refs = [i for i, path in enumerate(inventory["sensitivePaths"]) if scan_file(kind, path, params)]
                        trace.data["inputs"][active_id]["sensitivePathRefs"] = path_refs
                        selected_paths = [inventory["sensitivePaths"][i] for i in path_refs]
                        for f in inspect_repository_paths(inventory | {"sensitivePaths": selected_paths})[0]:
                            results.append({"category": "SECRET", "class": "repository-sensitive-path", "path": f["file"],
                                            "severity": "MEDIUM", "title": f["title"], "description": f["risk"],
                                            "fix": f["fix"], "remediation": f["fix"]})
                for item in results:
                    identity = finding_identity(item)
                    reported[identity] = merge_finding(reported.get(identity), item)
                if kind == "sca" and payload.get("dependencyMetrics"):
                    metric_files.update(inputs)
                return results
            elif kind == "model_load":
                return case_model.load_reference(self.store, project, params.get("connection"), params.get("model"))
            elif kind == "ai_review":
                from case_ai_review import review
                with model_for(params):
                    info = review(*analyze("ai_review", files, None))
                report.setdefault("aiReviews", {})[active_id] = info
            elif kind=="explain":
                offline = params.get("mode") == "catalog"
                with nullcontext() if offline else model_for(params):
                    if not offline:
                        profile = case_model.active()
                        if profile.model and profile.endpoint:
                            trace.data["inputs"][active_id]["model"] = profile.model
                    facts = []
                    trace.data["inputs"][active_id]["modelInputs"] = facts
                    report["summary"] = explain_findings(incoming, catalog_only=offline, model_inputs=facts)
                report["explanations"][active_id]=report["summary"]
            elif kind=="verify":
                parent=next(e["from"] for e in report["graph"]["edges"] if e["to"]==active_id)
                path_facts = (report["source"].get("inventory") or {}).get("sensitivePaths", ())
                report["summary"]=verify_explanation(report["explanations"][parent],incoming,dict.fromkeys(path_facts,"") | files)
                report["explanations"][active_id]=report["summary"]
            elif kind=="notify":
                channel = params.get("channel", "smtp")
                if payload.get("repair"):
                    report["deliveries"][active_id] = {"status": "skipped", "channel": channel, "at": int(time.time()),
                                                        "message": "Уведомление будет отправлено по итогам раунда исправления."}
                    return None
                summaries = advice_by_node.get(active_id, set())
                summary = report["explanations"][next(iter(summaries))] if len(summaries) == 1 else {}
                if channel == "webhook":
                    from case_webhook_delivery import send_webhook
                    delivery = send_webhook(project, report["id"], incoming, status="running", node_id=active_id)
                elif channel == "telegram":
                    status, message = self.telegram.notify(project, report | {"summary":summary}, incoming)
                    delivery = {"status": status, "message": message}
                else:
                    status, message = send_notice(project, report["id"], incoming, summary, report["source"]["revision"],
                                                  graph_hash, partial=partial_result(), store=self.store,
                                                  initiator=payload.get("createdBy") if trigger == "manual" else None,
                                                  automatic=trigger in AUTOMATIC_TRIGGERS)
                    delivery = {"status": status, "message": message}
                report["delivery"] = delivery | {"channel": channel, "at": int(time.time())}
                report["deliveries"][active_id] = report["delivery"]
                if delivery["status"] != "sent":
                    raise ValueError(delivery["message"])
            return None
        def stage(event):
            nonlocal active_id
            if event["status"]=="running":
                active_id=event["id"]
                inherited = set()
                inputs = trace.data["inputs"][active_id]
                if event["type"] in TRIGGERS:
                    inputs["trigger"] = payload.get("trigger", "manual")
                    if "event" in payload:
                        inputs["event"] = payload["event"]
                    if "scheduledAt" in payload:
                        inputs["scheduledAt"] = payload["scheduledAt"]
                for edge in predecessors[active_id]:
                    output = trace.data["outputs"].get(edge["from"], {})
                    if output.get("port") == edge["port"]:
                        inherited.update(advice_by_node.get(edge["from"], set()))
                if inherited:
                    inputs["recommendationNodes"] = sorted(inherited)
                advice_by_node[active_id] = {active_id} if event["type"] in ("explain", "verify") else inherited
            if event["type"]=="source" and event["status"]=="done":
                event["output"]["files"]=len(files)
            if event["type"] in SCANNERS and event["status"]!="skipped":
                event["input"]["files"]=input_counts.get(event["id"], 0)
                if event["status"] == "done":
                    trace.data["outputs"][event["id"]]["coverage"] = scanner_outputs[event["id"]]
            items = report["stages"]
            for index,item in enumerate(items):
                if item["id"]==event["id"]:
                    items[index]=event
                    break
            else:
                items.append(event)
            self.store.update(report)
        try:
            report["findings"] = execute_graph(
                report["graph"], node, stage, on_packet=trace.capture,
                on_input=trace.capture_input, on_ports=trace.capture_ports, on_condition=trace.capture_condition,
            )
            inspected = any(item["status"] == "done" for item in report["coverage"])
            inspected |= any(item["type"] in ("regex", "custom") and item["status"] == "done" for item in report["stages"])
            reviews = report.get("aiReviews", {}).values()
            inspected |= any(item["filesExamined"] for item in reviews)
            partial = partial_result()
            needs_review = report["findings"] or any(item["suggestions"] for item in reviews)
            report["status"] = "partial" if partial else "review" if needs_review else "passed" if inspected else "skipped"
            if not inspected and not partial:
                report["skipReason"] = "В выбранной версии нет текстовых файлов для активных узлов проверки."
        except Exception as exc:
            report["status"] = "failed"
            report["findings"] = list(reported.values())
            source_error=str(github_error(exc)) if isinstance(exc,GitHubError) else str(exc) if isinstance(exc,(WorkspaceError, GraphError)) else ""
            receipt = report["deliveries"].get(active_id, {})
            delivery_error = receipt.get("message") if receipt.get("status") != "sent" else None
            report["error"] = report.get("error") or source_error or delivery_error or "Шаг завершился с ошибкой. Проверьте источник, параметры и журнал нод."
            failed_stage = next((item for item in report["stages"]
                                 if item["id"] == active_id and item["status"] == "error"), None)
            if failed_stage is not None:
                failed_stage["message"] = report["error"]
            import logging
            logging.getLogger(__name__).warning("Studio run %s failed (%s)", report["id"],type(exc).__name__)
        if payload.get("dependencyMetrics") and any(s["type"] == "sca" and s["status"] == "done" for s in report["stages"]):
            from case_metrics import collect
            try:
                report["dependencyMetrics"] = collect(analyze("coordinates", metric_files, None), project)
            except (ValueError, OSError, TypeError, KeyError, subprocess.TimeoutExpired):
                report["dependencyMetrics"] = {"rows": [], "total": None, "error": "Не удалось получить метрики зависимостей."}
        self.store.update(report,finished=True)

if __name__=="__main__":
    from production import database
    from case_store import StudioStore
    store=StudioStore(database())
    if os.environ.get("BANK_GITHUB_READER")=="serve":
        from case_git_reader import start_reader
        start_reader(store)
    Studio(store).loop()
