"""Compare statically resolvable direct JVM dependencies in two immutable snapshots."""
from hashlib import sha256
from pathlib import PurePosixPath

from case_sca import GRADLE_LOCK, advisory_findings, advisory_index, dependency_declarations, gradle_support_files, numeric


RULE = "DEP-PR-001"
ENGINE = "dependency_review_diff"
MANIFESTS = {"build.gradle.kts", "pom.xml"}
LIMITS = "Прямые объявления Maven и Gradle Kotlin DSL с числовой версией, включая стандартный каталог Gradle. Транзитивные зависимости и BOM вне области проверки."


def manifest_inputs(files, paths):
    """Retain Gradle settings, properties, the default catalog and module locks."""
    inputs = {}
    for path in paths:
        inputs[path] = files[path]
        build = PurePosixPath(path)
        if build.name == "build.gradle.kts":
            for support in gradle_support_files(build):
                if support in files:
                    inputs[support] = files[support]
    return inputs


def inventory(files):
    rows, unknown, errors, incomplete = [], set(), {}, set()
    provenance = {}
    paths = sorted(p for p in files if PurePosixPath(p).name in MANIFESTS)
    for path in paths:
        manifest = PurePosixPath(path)
        unit = manifest_inputs(files, [path])
        if any(text is None for text in unit.values()):
            errors[path] = "Манифест или файл версии недоступен как текст."
            incomplete.add(path)
            continue
        unresolved, diagnostics = set(), {}
        for row in dependency_declarations(unit, unresolved, errors=diagnostics, provenance=provenance):
            _, group, artifact, version, _ = row
            if numeric(version) is None:
                unknown.add((group, artifact))
                errors[path] = "Для части зависимостей не удалось определить точную числовую версию."
            else:
                rows.append(row)
        if unresolved:
            errors[path] = f"Не удалось определить координаты прямой зависимости, строка {min(unresolved)}."
            incomplete.add(path)
        lock_path = str(manifest.with_name(GRADLE_LOCK))
        if diagnostics:
            errors[path] = diagnostics.get(path) or diagnostics[lock_path]
        if (manifest.name == "pom.xml" and path in diagnostics) or lock_path in diagnostics:
            incomplete.add(path)
    return paths, rows, unknown, errors, incomplete, provenance


def compare(snapshots, catalog):
    base_paths, old, unknown, base_errors, incomplete, _ = inventory(snapshots["base"])
    head_paths, current, _, head_errors, _, provenance = inventory(snapshots["head"])
    previous = {(group, artifact, version) for _, group, artifact, version, _ in old}
    added = (row for row in current if row[1:4] not in previous and row[1:3] not in unknown)
    results = [] if incomplete else advisory_findings(added, advisory_index(catalog), provenance=provenance)
    for item in results:
        fingerprint = ":".join((RULE, item["path"], item["group"], item["artifact"], item["version"], item["advisoryId"]))
        item.update(checkId=RULE, fingerprint=sha256(fingerprint.encode()).hexdigest()[:32],
                    title="В PR добавлена уязвимая версия зависимости",
                    description="Эта версия впервые появилась в сравниваемой области. " + item["description"])
    entries = []
    for path in sorted(set(base_paths) | set(head_paths)):
        reasons = []
        if path in base_errors:
            reasons.append("База PR: " + base_errors[path])
        if path in head_errors:
            reasons.append("Версия PR: " + head_errors[path])
        entries.append({"file": path, "engine": ENGINE, "status": "error" if reasons else "done",
                        "message": " ".join(reasons) if reasons else "Сопоставлены объявления в области проверки."})
    return {"findings": results, "coverage": entries}
