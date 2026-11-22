"""Adapt the repository-level static checks to versioned standard-run reports."""
from collections import Counter
from hashlib import sha256
from pathlib import PurePosixPath

from case_detectors import scan_sast, scan_secrets, spring_properties
from case_sca import GRADLE_LOCK, scan_sca
from case_source import advisory_database
from case_pipeline_checks import RULES as PIPELINE_RULES
from case_java_review import RULES as JAVA_RULES
from case_web_review import RULES as WEB_RULES, inspect as inspect_web
from case_spring_review import RULES as SPRING_RULES
from case_jvm_crypto import RULES as JVM_RULES
from case_kotlin_jpa import RULES as JPA_RULES
from case_literal_review import RULES as LITERAL_RULES
from case_package_review import RULES as PACKAGE_RULES


REVIEW_RULES = PIPELINE_RULES | JAVA_RULES | WEB_RULES | SPRING_RULES | JVM_RULES | JPA_RULES | LITERAL_RULES | PACKAGE_RULES | {
    "PY-004": {
        "engine": "python", "level": "high", "title": "Вызов встроенной функции exec",
        "risk": "Функция exec исполняет переданный код Python.",
        "fix": "Замените исполнение строк явным выбором разрешённых операций.",
        "verify": "Повторите статическую проверку и проверьте обработку неизвестной операции.",
    },
    "PY-005": {
        "engine": "python", "level": "high", "title": "Команда выполняется через оболочку",
        "risk": "При shell=True оболочка интерпретирует строку команды и её управляющие символы.",
        "fix": "Передавайте имя программы и аргументы списком и оставьте shell выключенным.",
        "verify": "Повторите проверку и убедитесь, что аргументы процесса передаются без интерпретации оболочкой.",
    },
    "PY-006": {
        "engine": "python", "level": "high", "title": "Десериализация с помощью pickle",
        "risk": "Десериализация pickle допускает выполнение кода. Формат требует доверенного источника.",
        "fix": "Для внешних данных используйте формат без исполняемых объектов и проверяйте его структуру.",
        "verify": "Повторите проверку и проверьте отклонение данных вне ожидаемого формата.",
    },
    "DEP-PR-001": {
        "engine": "dependency_review", "level": "high", "title": "В PR добавлена уязвимая версия зависимости",
        "risk": "Новая для этого изменения версия входит в затронутый диапазон опубликованного уведомления.",
        "fix": "Сверьте версию с уведомлением и выберите исправленную совместимую версию.",
        "verify": "Повторите сравнение зависимостей и проверьте тесты проекта.",
    },
}


RULES = {
    "SEC-001": {"engine": "secrets", "title": "Секреты в исходниках и настройках", "level": "high",
                "risk": "Учётные данные могут попасть в историю репозитория.",
                "fix": "Используйте защищённое хранилище секретов.",
                "verify": "Проверьте источник значения и повторите проверку изменённого файла."},
    "KT-001": {"engine": "sast", "title": "Политики безопасности Kotlin / Spring", "level": "high",
               "risk": "Код приложения может нарушать политику доступа или обработки данных.",
               "fix": "Исправьте указанное место с учётом назначения обработчика.",
               "verify": "Повторите статическую проверку и тест соответствующего обработчика."},
    "DEP-001": {"engine": "sca", "title": "Зависимости Gradle и Maven", "level": "high",
                "risk": "Версия зависимости может входить в диапазон опубликованного уведомления.",
                "fix": "Обновите объявление зависимости и проверьте совместимость.",
                "verify": "Повторите проверку манифеста и тесты проекта."},
}


def applicable(path, engine):
    if engine == "secrets":
        return True
    if engine == "sast":
        return path.lower().endswith(".kt") or spring_properties(path)
    return PurePosixPath(path).name in ("pom.xml", "build.gradle.kts")


def standard_finding(raw, index=1):
    """One stable identity for a finding in a graph or a published rule set."""
    check = raw.get("checkId")
    if check in REVIEW_RULES:
        policy = REVIEW_RULES[check]
        return policy | {"id": f"{check}-{index}", "ruleId": check, "category": raw["category"],
                         "file": raw["path"], "line": raw.get("line"), "column": raw.get("column"),
                         "level": raw["severity"].lower(), "fingerprint": raw["fingerprint"],
                         "title": raw["title"], "risk": raw["description"], "fix": raw["fix"],
                         "evidence": raw["description"],
                         **{key: raw[key] for key in ("endLine", "advisoryId", "advisorySource", "ecosystem", "artifact", "version") if key in raw}}
    if raw.get("standardRule") or raw.get("class") == "repository-sensitive-path":
        from analyzers import RULES as catalog, inspect_repository_paths
        path = raw["path"]
        if raw.get("class") == "repository-sensitive-path":
            result = inspect_repository_paths({"sensitivePaths": [path], "totalFiles": 1})[0][0]
            return result | {"id": f"REPO-001-{index}"}
        rule = raw["standardRule"]
        return catalog[rule] | {"id": f"{rule}-{index}", "ruleId": rule, "file": path,
                                "line": raw["line"], "column": raw.get("column"), "fingerprint": raw["fingerprint"],
                                "evidence": raw["title"]}
    rule = {"SECRET": "SEC-001", "SAST": "KT-001", "SCA": "DEP-001"}[raw["category"]]
    if raw.get("class") == "json-duplicate-key":
        return {"id": f"JSON-KEYS-{index}", "ruleId": "JSON-KEYS", "engine":"json_keys", "level":"medium",
                "file": raw["path"], "line": raw["line"], "column": raw["column"], "fingerprint":raw["fingerprint"],
                "title": raw["title"], "evidence":raw["description"], "risk":raw["description"], "fix":raw["fix"],
                "verify":"Запустите проверку повторяющихся ключей на исправленном файле."}
    policy = RULES[rule]
    path = raw["path"]
    advisory = raw.get("advisoryId")
    detail = f"{raw['group']}:{raw['artifact']} · {advisory}" if advisory else raw["class"]
    # Neither evidence nor stable identities contain the value of a detected secret.
    return {"id": f"{rule}-{index}", "ruleId": rule, "file": path, "line": raw.get("line"),
            "column": None, "engine": policy["engine"], "level": raw["severity"].lower(),
            "fingerprint": sha256(f"{rule}:{path}:{detail}".encode()).hexdigest()[:32],
            "title": raw["title"], "evidence": detail, "risk": raw.get("description") or policy["risk"],
            **({"sourceContext": raw["sourceContext"]} if raw.get("sourceContext") else {}),
            "fix": raw.get("fix") or policy["fix"], "verify": policy["verify"]}


def graph_sast(files):
    from analyzers import REPORT_RULES as catalog, run_analysis
    rules = [rule for rule in catalog if catalog[rule]["engine"] in ("python", "config")]
    matches, stages = run_analysis({"files": files}, rules, include_review=True)
    coverage = [dict(row, engine=step["id"]) for step in stages if step["id"] in ("python", "config")
                for row in step.get("coverage", [])]
    coverage.extend({"file": path, "engine": "sast", "status": "done", "message": "Проверено"}
                    for path in sorted(files) if applicable(path, "sast"))
    items = scan_sast(files)
    for f in matches:
        items.append({"category": "SAST", "class": f["ruleId"], "standardRule": f["ruleId"], "path": f["file"],
                      "line": f["line"], "column": f["column"], "fingerprint": f["fingerprint"],
                      "severity": f["level"].upper(), "title": f["title"], "description": f["risk"],
                      "fix": f["fix"], "remediation": f["fix"]})
        if f["ruleId"] in REVIEW_RULES:
            items[-1]["checkId"] = f["ruleId"]
    web = inspect_web(files)
    items.extend(web["findings"])
    coverage.extend(web["coverage"])
    return {"findings": items, "coverage": coverage}


def manifest_findings(files, catalog):
    errors = {path: "Указанный файл не найден в этой версии." for path in sca_paths(files) if files[path] is None}
    manifests = any(isinstance(text, str) and applicable(path, "sca") for path, text in files.items())
    return (scan_sca(files, catalog, errors) if manifests else []), errors


def sca_paths(files):
    manifests = {path for path in files if applicable(path, "sca")}
    locks = {str(PurePosixPath(path).with_name(GRADLE_LOCK)) for path in manifests if PurePosixPath(path).name == "build.gradle.kts"}
    return sorted(manifests | (locks & files.keys()))


def file_coverage(paths, matches, errors):
    counts = Counter(item["path"] for item in matches)
    return [{"file": path, "status": "error" if path in errors else "done",
             "message": errors.get(path, f"Замечаний: {counts[path]}")} for path in paths]


def project_analysis(files, rules):
    findings, stages = [], []
    for rule, policy in RULES.items():
        engine = policy["engine"]
        if rule not in rules:
            stages.append({"id": engine, "status": "skipped", "message": "Правило отключено"})
            continue
        paths = sca_paths(files) if engine == "sca" else sorted(path for path in files if applicable(path, engine))
        usable = {path: files[path] for path in paths if files[path] is not None}
        errors = {path: "Указанный файл не найден в этой версии." for path in paths if path not in usable}
        if engine == "secrets":
            matches = scan_secrets(usable)
        elif engine == "sast":
            matches = scan_sast(usable)
        else:
            matches, malformed = manifest_findings(files, advisory_database() if usable else None)
            errors.update(malformed)
        for index, finding in enumerate(matches, 1):
            findings.append(standard_finding(finding, index))
        status, message = "done", f"Проверено файлов: {len(paths)}. Замечаний: {len(matches)}."
        if errors:
            status, message = "error", f"Файлов с ошибкой: {len(errors)}"
        elif not paths:
            status, message = "skipped", "В снимке нет подходящих файлов."
        stages.append({"id": engine, "status": status, "message": message, "coverage": file_coverage(paths, matches, errors)})
    return findings, stages
