"""Compare declared npm and PyPI versions with an explicitly supplied advisory catalog."""
from bisect import bisect_right
from collections import Counter
from hashlib import sha256
import json
from pathlib import PurePosixPath
import re

from case_json_keys import TOKENS
from case_sca import ADVISORY_ID, numeric
from case_severity import RANK


ENGINE = "package_review"
RULE = "PKG-001"
RULES = {
    RULE: {
        "engine": ENGINE, "level": "high", "title": "Версия пакета указана в уведомлении безопасности",
        "risk": "Справочник относит зафиксированную версию пакета к затронутым.",
        "fix": "Сверьтесь с уведомлением и обновите пакет до совместимой исправленной версии.",
        "verify": "Обновите файл зависимостей и повторите проверку с тем же справочником.",
    },
}
MANIFESTS = {"package-lock.json": "npm", "requirements.txt": "PyPI"}
PYPI_NAME = r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,212}[A-Za-z0-9])?"
NPM_NAME = re.compile(r"(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*")
SEMVER_COMPONENT = r"(?:0|[1-9][0-9]*)"
SEMVER_PRERELEASE = rf"(?:{SEMVER_COMPONENT}|[0-9]*[A-Za-z-][A-Za-z0-9-]*)"
NPM_VERSION = re.compile(
    rf"{SEMVER_COMPONENT}\.{SEMVER_COMPONENT}\.{SEMVER_COMPONENT}"
    rf"(?:-{SEMVER_PRERELEASE}(?:\.{SEMVER_PRERELEASE})*)?(?:\+[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*)?"
)
PIN = re.compile(rf"(?P<name>{PYPI_NAME})(?:\s*\[\s*{PYPI_NAME}(?:\s*,\s*{PYPI_NAME})*\s*\])?\s*==\s*(?P<version>[0-9]+(?:\.[0-9]+)*)")


def package_name(ecosystem, value):
    if not isinstance(value, str) or len(value) > 214:
        return None
    if ecosystem == "npm":
        return value if NPM_NAME.fullmatch(value) else None
    if ecosystem == "PyPI" and re.fullmatch(PYPI_NAME, value):
        return re.sub(r"[-_.]+", "-", value).lower()
    return None


def version_key(ecosystem, value):
    if not isinstance(value, str) or not 1 <= len(value) <= 128:
        return None
    if ecosystem == "PyPI":
        return numeric(value)
    return value if NPM_VERSION.fullmatch(value) else None


def package_advisory_index(catalog):
    if not isinstance(catalog, dict) or "packageVulnerabilities" not in catalog:
        return None
    entries = catalog["packageVulnerabilities"]
    if not isinstance(entries, list) or len(entries) > 1500:
        raise ValueError("Ожидается список packageVulnerabilities до 1500 записей.")

    index = {}
    for row in entries:
        if not isinstance(row, dict):
            raise ValueError("Некорректная запись packageVulnerabilities.")
        ecosystem, advisory, severity = (row.get(key) for key in ("ecosystem", "id", "severity"))
        name = package_name(ecosystem, row.get("name"))
        versions = row.get("affectedVersions")
        if (not name or not isinstance(advisory, str) or not ADVISORY_ID.fullmatch(advisory)
                or not isinstance(severity, str) or severity.lower() not in RANK
                or not isinstance(versions, list) or not versions or len(versions) > 500):
            raise ValueError("Укажите ecosystem, name, id, severity и affectedVersions в записи справочника пакетов.")
        fixed_version, source = row.get("fixedVersion"), row.get("source")
        fixed_key = version_key(ecosystem, fixed_version)
        if fixed_version is not None and fixed_key is None:
            raise ValueError("В fixedVersion укажите точную версию пакета.")
        expected_source = (f"https://github.com/advisories/{advisory}" if advisory.startswith("GHSA-")
                           else f"https://nvd.nist.gov/vuln/detail/{advisory}")
        if source is not None and source != expected_source:
            raise ValueError("URL источника должен указывать на страницу этого уведомления в GitHub Advisory Database или NVD.")
        details = (severity.upper(), fixed_version, source)
        for version in versions:
            normalized = version_key(ecosystem, version)
            if normalized is None:
                raise ValueError("В affectedVersions укажите точные версии пакета.")
            if normalized == fixed_key:
                raise ValueError("Исправленная версия не может входить в affectedVersions.")
            matches = index.setdefault((ecosystem, name, normalized), {})
            if matches.setdefault(advisory, details) != details:
                raise ValueError("Справочник содержит противоречащие друг другу записи об одной версии пакета.")
    return index


def requirements(body):
    rows, unknown, conditional = [], [], set()
    for line, text in enumerate(body.splitlines(), 1):
        text = re.split(r"\s+#", text.strip(), maxsplit=1)[0].strip()
        if not text or text.startswith("#"):
            continue
        pin, separator, marker = text.partition(";")
        match = PIN.fullmatch(pin.rstrip())
        if not match or version_key("PyPI", match["version"]) is None:
            unknown.append(line)
            continue
        if separator:
            # Validate conditions without evaluating them on the scanner's own platform.
            try:
                from packaging.markers import Marker
                Marker(marker.strip())
            except (ImportError, ValueError, RecursionError):
                unknown.append(line)
                continue
            conditional.add(line)
        rows.append((package_name("PyPI", match["name"]), match["version"], line))
    return rows, unknown, conditional


def unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("JSON содержит повторяющийся ключ.")
        result[key] = value
    return result


def package_lines(body):
    """Locate the lockfile's packages entries at their object key lines."""
    breaks = [match.start() for match in re.finditer("\n", body)]
    lines = {}
    depth = 0
    in_packages = next_packages = False
    previous = None
    for match in TOKENS.finditer(body):
        token = match[0]
        if token == ":":
            if depth == 1:
                next_packages = json.loads(previous[0]) == "packages"
            elif depth == 2 and in_packages:
                lines[json.loads(previous[0])] = bisect_right(breaks, previous.start()) + 1
        elif token in ("{", "["):
            depth += 1
            if next_packages:
                in_packages = True
                next_packages = False
        elif token in ("}", "]"):
            if depth == 2 and in_packages:
                break
            depth -= 1
        previous = match
    return lines


def npm_lock(body):
    try:
        lock = json.loads(body, object_pairs_hook=unique_keys)
    except (ValueError, RecursionError):
        raise ValueError("Некорректный package-lock.json.") from None
    if (not isinstance(lock, dict) or type(lock.get("lockfileVersion")) is not int
            or lock["lockfileVersion"] not in (2, 3) or not isinstance(lock.get("packages"), dict)):
        raise ValueError("Поддерживается package-lock.json версий 2 и 3 с разделом packages.")
    lines = package_lines(body)
    rows, unknown = [], []
    for location, record in lock["packages"].items():
        segments = location.split("/")
        if "node_modules" not in segments:
            continue
        line = lines[location]
        if not isinstance(record, dict) or any(segment in {"", ".", ".."} for segment in segments):
            unknown.append(line)
            continue
        if record.get("link") is True:
            continue
        resolved = record.get("resolved")
        if resolved is not None and (not isinstance(resolved, str) or not resolved.startswith(("https://", "http://"))):
            unknown.append(line)
            continue
        module_root = len(segments) - segments[::-1].index("node_modules")
        installed_as = "/".join(segments[module_root:])
        if not package_name("npm", installed_as):
            unknown.append(line)
            continue
        name = package_name("npm", record.get("name", installed_as))
        version = record.get("version")
        if name and version_key("npm", version):
            rows.append((name, version, line))
        else:
            unknown.append(line)
    return rows, unknown


def applies(path):
    return PurePosixPath(path).name in MANIFESTS


def inspect(files, catalog):
    index = package_advisory_index(catalog)
    ecosystems = {key[0] for key in (index or {})}
    findings, coverage = [], []
    for path, body in sorted(files.items()):
        ecosystem = MANIFESTS.get(PurePosixPath(path).name)
        if ecosystem is None:
            continue
        status = {"file": path, "engine": ENGINE, "status": "done"}
        coverage.append(status)
        if not isinstance(body, str):
            status.update(status="error", message="Файл недоступен как текст.")
            continue
        conditional = set()
        try:
            text = body.lstrip("\ufeff")
            if ecosystem == "npm":
                rows, unknown = npm_lock(text)
            else:
                rows, unknown, conditional = requirements(text)
        except ValueError as exc:
            status.update(status="error", message=str(exc))
            continue
        if rows and ecosystem not in ecosystems:
            status.update(status="error", message=f"Добавьте записи {ecosystem} в справочник packageVulnerabilities для проверки версий.")
            continue
        status["message"] = f"Сопоставлено версий: {len(rows)}."
        if conditional:
            status["message"] += f" Условных зависимостей: {len(conditional)}."
        if unknown:
            status.update(status="error", line=min(unknown),
                          message=f"{status['message']} Не удалось проверить записей: {len(unknown)}.")
        occurrences = Counter()
        rule = RULES[RULE]
        for name, version, line in rows:
            matches = index.get((ecosystem, name, version_key(ecosystem, version)), {})
            for advisory, (severity, fixed_version, source) in matches.items():
                identity = (RULE, path, ecosystem, name, version, advisory)
                occurrences[identity] += 1
                anchor = "\0".join((*identity, str(occurrences[identity])))
                finding = {
                    "category": "SCA", "checkId": RULE, "class": RULE, "path": path,
                    "line": line, "endLine": line, "severity": severity, "title": rule["title"],
                    "ecosystem": ecosystem, "group": ecosystem, "artifact": name,
                    "version": version, "advisoryId": advisory,
                    "fingerprint": sha256(anchor.encode()).hexdigest()[:32],
                    "description": f"{ecosystem}: {name} {version} указан в {advisory}.",
                    "fix": rule["fix"], "remediation": rule["fix"],
                }
                if line in conditional:
                    finding["conditional"] = True
                    finding["description"] += " Зависимость объявлена с условием окружения."
                if fixed_version:
                    finding["fixedVersion"] = fixed_version
                    finding["fix"] = finding["remediation"] = f"Сверьтесь с уведомлением и обновите пакет до {fixed_version} или совместимой исправленной версии."
                if source:
                    finding["advisorySource"] = source
                findings.append(finding)
    return {"findings": findings, "coverage": coverage}
