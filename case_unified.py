"""Adapt the repository-level static checks to versioned standard-run reports."""
from collections import Counter
from hashlib import sha256
from pathlib import PurePosixPath

from case_detectors import scan_sast, scan_secrets, spring_properties
from case_sca import PomInputError, scan_sca
from case_source import advisory_database


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
                "risk": "Версия прямой зависимости может входить в диапазон опубликованного уведомления.",
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
            "column": None, "engine": policy["engine"], "level": "high" if raw["severity"] in ("HIGH", "CRITICAL") else "medium",
            "fingerprint": sha256(f"{rule}:{path}:{detail}".encode()).hexdigest()[:32],
            "title": raw["title"], "evidence": detail, "risk": raw.get("description") or policy["risk"],
            **({"sourceContext": raw["sourceContext"]} if raw.get("sourceContext") else {}),
            "fix": raw.get("fix") or policy["fix"], "verify": policy["verify"]}


def graph_sast(files):
    from analyzers import RULES as catalog, run_analysis
    rules = [rule for rule in catalog if catalog[rule]["engine"] in ("python", "config")]
    matches, stages = run_analysis({"files": files}, rules)
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
    return {"findings": items, "coverage": coverage}


def manifest_findings(files, catalog):
    matches, errors = [], {}
    for path in sorted(files):
        if files[path] is None or not applicable(path, "sca"):
            continue
        build = PurePosixPath(path)
        support = ("gradle.properties", str(build.with_name("gradle.properties")),
                   str(build.with_name("gradle.lockfile")))
        manifest = {name: files[name] for name in support if isinstance(files.get(name), str)}
        try:
            matches.extend(scan_sca(manifest | {path: files[path]}, catalog))
        except PomInputError as exc:
            errors[path] = str(exc)
    return matches, errors


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
        paths = sorted(path for path in files if applicable(path, engine))
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
