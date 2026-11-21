"""Compare observed findings and evaluate versioned release and notification policies."""

from collections import defaultdict
from datetime import date
from html import escape
import json

from analyzers import ENGINES, REPOSITORY_RULE_ID, RULES, repository_paths_checked
from workspace import WorkspaceError


COMPLETE = ("passed", "review", "partial", "skipped")
GATE_LABELS = {"disabled": "Отключено", "blocked": "Требует исправления", "passed": "Пройдено",
               "insufficient": "Недостаточно данных"}
TRIAGE_LABELS = {"open": "Открыто", "accepted": "Риск принят", "false_positive": "Ложное срабатывание"}


def repository_of(run):
    marker = run.get("event") or run.get("githubTrial") or {}
    lineage = run.get("lineage") or ""
    name = marker.get("repository") or (lineage.partition(":")[2] if lineage.startswith("github-read:") else "")
    if not name and lineage.startswith("github:"):
        name = (run.get("source") or "").partition(" · ")[0]
    identity = marker.get("repositoryId") or run.get("sourceRepositoryId") or (
        lineage.split(":")[1] if lineage.startswith("github:") else "")
    return str(identity), name.casefold()


def same_source(base, head):
    first_id, first_name = repository_of(base)
    second_id, second_name = repository_of(head)
    if first_id and second_id:
        return first_id == second_id
    if first_name or second_name:
        return first_name == second_name
    if first_id or second_id:
        return False

    def lineage(run):
        return run.get("lineage") or ("custom" if run.get("source") == "Пользовательский снимок" else run.get("source"))
    return lineage(base) == lineage(head)


def coverage(run):
    rules = run["workflow"]["spec"]["rules"]
    stages = {step["id"]: step for step in run.get("stages", [])}
    result = []
    for engine in sorted({RULES[rule]["engine"] for rule in rules if rule in RULES}):
        files = [row for row in run.get("coverage", []) if row["engine"] == engine]
        if not files and "coverage" not in run:
            files = [stages.get(engine, {})]
        for source in files:
            result.append({
                "engine": engine, "file": source.get("file") or (ENGINES[engine][0] if engine in ENGINES else ""),
                "status": source.get("status", "unknown"), "message": source.get("message", ""),
                "rules": [rule for rule in rules if RULES.get(rule, {}).get("engine") == engine],
            })
    return result


def checked(run):
    return {(item["file"], rule) for item in coverage(run) if item["status"] == "done" for rule in item["rules"]}


def partition(base, head):
    groups = {"new": [], "existing": [], "fixed": [], "unverified": []}
    indexes = []
    for run in (base, head):
        index = defaultdict(list)
        for item in run.get("findings", []):
            key = (item["file"], item["ruleId"], item.get("fingerprint"))
            index[key].append(item)
        indexes.append(index)
    comparable = checked(base) & checked(head)
    paths_comparable = repository_paths_checked(base) and repository_paths_checked(head)
    before, after = indexes
    for key in sorted(before.keys() | after.keys(), key=str):
        old, current = before[key], after[key]
        covered = paths_comparable if key[1] == REPOSITORY_RULE_ID else key[:2] in comparable
        if not covered or not key[2]:
            group = "unverified"
        elif not old:
            group = "new"
        elif not current:
            group = "fixed" if head["status"] != "partial" else "unverified"
        elif len(old) == len(current):
            group = "existing"
        else:
            # Duplicate fingerprints do not establish which individual occurrence changed.
            group = "unverified"
        groups[group].extend(current or old)
    return groups


def applies(finding, minimum):
    return minimum == "medium" or finding["level"] == "high"


def exempt(finding):
    decision = finding.get("triageDecision") or {}
    expires = decision.get("expiresAt", "")
    return finding.get("triage") in ("accepted", "false_positive") and expires >= date.today().isoformat()


def policy_result(minimum, newly_found, incomplete):
    blocking = sum(applies(item, minimum) and not exempt(item) for item in newly_found)
    if minimum == "off":
        status, reason = "disabled", "Условие приёмки отключено в этой версии сценария."
        blocking = 0
    elif incomplete:
        status, reason = "insufficient", incomplete
    elif blocking:
        status, reason = "blocked", f"Требуют исправления новых замечаний: {blocking}."
    else:
        status, reason = "passed", "Новых замечаний, требующих исправления по этому условию, нет."
    return {"status": status, "minimum": minimum, "blockingCount": blocking, "reason": reason}


def gate_without_content(minimum, new_findings, reason):
    # An independently verified new path can block a release even without language coverage.
    paths = [f for f in new_findings if f["ruleId"] == REPOSITORY_RULE_ID]
    decision = policy_result(minimum, paths, None)
    return decision if decision["status"] == "blocked" else policy_result(minimum, [], reason)


def pair_gate(base, head, groups, minimum):
    incomplete = None
    if base["status"] == "partial" or head["status"] == "partial":
        incomplete = "Одна из проверок выполнена частично. Повторите анализ полного снимка."
    elif base.get("skipReason") or head.get("skipReason") or "skipped" in (base["status"], head["status"]):
        return gate_without_content(minimum, groups["new"], "В одной из версий правила сценария не проверили содержимое файлов.")
    elif checked(base) != checked(head) or not checked(head):
        incomplete = "Охват файлов или правил различается. Проверьте обе версии с одинаковым набором правил."
    elif groups["unverified"]:
        incomplete = "Для части замечаний невозможно однозначно установить новизну."
    return policy_result(minimum, groups["new"], incomplete)


def evaluate_gate(run, baseline=None, spec=None):
    spec = spec or run["workflow"]["spec"]
    minimum = spec.get("gateMinimum", "off")
    if run.get("skipReason"):
        if run.get("origin") == "pull_request":
            new = [f for f in run.get("findings", []) if f.get("novelty") == "new"]
            return gate_without_content(minimum, new, run["skipReason"])
        if baseline and baseline.get("status") in COMPLETE and same_source(baseline, run):
            return pair_gate(baseline, run, partition(baseline, run), minimum)
        return policy_result(minimum, [], run["skipReason"])
    if run["status"] not in ("passed", "review"):
        return policy_result(minimum, [], "Ожидается полная проверка всех выбранных файлов.")
    if run.get("origin") == "pull_request":
        findings = run.get("findings", [])
        valid = run.get("comparison", {}).get("status") == "available"
        unknown = any(f.get("novelty") not in ("new", "known") for f in findings)
        reason = None if valid and not unknown else "Не удалось полностью сравнить изменения с базой pull request."
        return policy_result(minimum, [f for f in findings if f.get("novelty") == "new"], reason)
    if baseline and baseline.get("status") in COMPLETE and same_source(baseline, run):
        return pair_gate(baseline, run, partition(baseline, run), minimum)
    return policy_result(minimum, [], "Для определения новых замечаний нужна сопоставимая базовая проверка.")


def run_summary(run):
    return {"id": run["id"], "createdAt": run["createdAt"], "source": run.get("source"), "revision": run.get("revision"),
            "status": run["status"], "origin": run.get("origin"), "version": run["workflow"]["number"],
            "preview": bool(run["workflow"].get("preview"))}


def compare_release(base, head):
    if base.get("projectId") != head.get("projectId") or not same_source(base, head):
        raise WorkspaceError("Выберите две проверки одного проекта и источника.")
    if base["id"] == head["id"] or base["createdAt"] > head["createdAt"]:
        raise WorkspaceError("Базовой должна быть другая, более ранняя проверка.")
    if any(run["status"] not in COMPLETE for run in (base, head)):
        raise WorkspaceError("Дождитесь завершения обеих проверок.")
    groups = partition(base, head)
    gate = pair_gate(base, head, groups, head["workflow"]["spec"].get("gateMinimum", "off"))
    return {"projectId": head.get("projectId"), "base": run_summary(base), "head": run_summary(head),
            "coverage": {"base": coverage(base), "head": coverage(head)}, "groups": groups, "gate": gate,
            "recordedGate": head.get("gate"),
            "exceptions": [f for f in head.get("findings", []) if exempt(f)]}


def simulate_policy(run, spec, baseline=None, smtp_address=None):
    if run["status"] not in COMPLETE:
        raise WorkspaceError("Для моделирования выберите завершённую проверку.")
    added = sorted(set(spec["rules"]) - set(run["workflow"]["spec"]["rules"]))
    removed = sorted(set(run["workflow"]["spec"]["rules"]) - set(spec["rules"]))
    if added or removed:
        return {"needsScan": True, "addedRules": added, "removedRules": removed,
                "reason": "Набор правил изменился. Для результата запустите черновик на исходных файлах."}
    delivery = {"channel": spec["deliveryChannel"], "recipient": spec["recipient"], "count": 0}
    candidates = [f for f in run.get("findings", []) if applies(f, spec["minimum"])]
    if run.get("origin") == "pull_request":
        candidates = [f for f in candidates if f.get("novelty") == "new" and f.get("triage", "open") == "open"]
    delivery["partial"] = run["status"] == "partial"
    if run.get("origin") == "github_trial":
        delivery.update(status="disabled", reason="Внешняя доставка отключена для пробной проверки репозитория.")
    elif not spec["delivery"]:
        delivery.update(status="disabled", reason="Доставка отключена в черновике.")
    elif not candidates:
        delivery.update(status="skipped", reason="Среди полученных результатов нет замечаний по условиям доставки.")
    elif spec["deliveryChannel"] == "smtp" and not smtp_address:
        delivery.update(status="unavailable", count=len(candidates), reason="На проекте не настроен получатель SMTP.")
    else:
        delivery.update(status="planned", count=len(candidates), reason="Замечания соответствуют порогу важности и условиям запуска.")
        if spec["deliveryChannel"] == "smtp":
            delivery["address"] = smtp_address
    return {"needsScan": False, "run": run_summary(run), "gate": evaluate_gate(run, baseline, spec), "delivery": delivery}


def export_release(comparison, format="html"):
    filename = f"release-{comparison['base']['id']}-{comparison['head']['id']}"
    if format == "json":
        return filename + ".json", "application/json; charset=utf-8", json.dumps(comparison, ensure_ascii=False, indent=2).encode()
    if format != "html":
        raise WorkspaceError("Выберите HTML или JSON.")
    pieces = ['<!doctype html><html lang="ru"><meta charset="utf-8"><title>Сравнение версий</title>',
              '<style>body{font:16px/1.5 system-ui;max-width:70ch;margin:3rem auto;padding:0 1rem;color:#173b2b}'
              'li{overflow-wrap:anywhere}h2{break-after:avoid}li{break-inside:avoid}</style>',
              '<h1>Сравнение версий</h1>']
    for side, label in (("base", "Базовая версия"), ("head", "Проверяемая версия")):
        run = comparison[side]
        if run.get("origin") == "automation":
            version = "схема " + escape(str(run["version"]))
        else:
            version = "предпросмотр черновика" if run.get("preview") else f'сценарий v{int(run["version"])}'
        pieces.append(f'<h2>{label}</h2><p>{escape(run["source"] or "")} · {escape(run["createdAt"])}'
                      f' · {version} · ревизия {escape(run["revision"] or "—")}</p>'
                      f'<p>Запуск {escape(run["id"])}</p><ul>')
        for item in comparison["coverage"][side]:
            pieces.append(f'<li>{escape(item["file"])} · {escape(", ".join(item["rules"]))} · {escape(item["message"])}</li>')
        pieces.append("</ul>")
    for label, gate in (("Условия приёмки выбранной пары", comparison["gate"]),
                        ("Решение при завершении проверяемого запуска", comparison.get("recordedGate"))):
        if gate:
            pieces.append(f'<h2>{label}</h2><p><strong>{escape(GATE_LABELS[gate["status"]])}</strong>'
                          f' · блокирующих замечаний: {int(gate["blockingCount"])}</p><p>{escape(gate["reason"])}</p>')
    for key, label in (("new", "Новые"), ("existing", "Сохранились"), ("fixed", "Исправлены"),
                       ("unverified", "Требуют проверки"), ("exceptions", "Действующие исключения")):
        items = comparison["exceptions"] if key == "exceptions" else comparison["groups"][key]
        pieces.append(f"<h2>{label} · {len(items)}</h2><ul>")
        for item in items:
            text = f'{item["ruleId"]} · {item["title"]} · {item["file"]}'
            if item.get("line"):
                text += f', строка {item["line"]}'
            if key == "exceptions":
                decision = item["triageDecision"]
                text += f' · {decision.get("reason", "")} · пересмотр до {decision["expiresAt"]}'
            pieces.append("<li>" + escape(text))
            if "assignee" in item or "currentTriage" in item:
                live = TRIAGE_LABELS.get(item.get("currentTriage"), "—")
                extra = f'Сейчас в проекте · {live} · ответственный: {item.get("assignee") or "не назначен"}'
                current = item.get("currentDecision") or {}
                if current.get("expiresAt"):
                    extra += f' · пересмотр до {current["expiresAt"]} · {current.get("reason", "")}'
                pieces.append("<p>" + escape(extra) + "</p>")
            pieces.append("</li>")
        pieces.append("</ul>")
    pieces.append("</html>")
    return filename + ".html", "text/html; charset=utf-8", "".join(pieces).encode()
