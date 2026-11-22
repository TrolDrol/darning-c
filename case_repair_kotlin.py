"""Deterministic repairs for Kotlin and Spring security findings."""

from collections import Counter
from pathlib import PurePosixPath
import re
from urllib.parse import urlsplit

from case_detectors import Kotlin, scan_sast, scan_secrets, spring_properties


_NAME = r"[A-Za-z_][A-Za-z_0-9]*"
_SETTING = r"[A-Za-z_][A-Za-z_0-9.-]*"
_LITERAL = r'"[^"\\$\r\n]+"'
_END_OF_CODE = r"[ \t]*;?[ \t]*(?://[^\r\n]*)?"
_DECLARATION = rf"[ \t]*(?:(?:private|internal|protected|public)[ \t]+)?(?:val|var)[ \t]+{_NAME}(?:[ \t]*:[ \t]*String\??)?[ \t]*=[ \t]*"
_LOOKUP = rf'(?:java[ \t]*\.[ \t]*lang[ \t]*\.[ \t]*)?System[ \t]*\.[ \t]*(?:getenv|getProperty)[ \t]*\([ \t]*"(?P<name>{_SETTING})"[ \t]*\)'
_KOTLIN_FALLBACK = re.compile(rf"(?P<prefix>{_DECLARATION})(?P<lookup>{_LOOKUP})[ \t]*\?:[ \t]*{_LITERAL}(?P<suffix>{_END_OF_CODE})")
_KOTLIN_FALLBACK_MASKED = re.compile(rf'{_DECLARATION}(?:java\s*\.\s*lang\s*\.\s*)?System\s*\.\s*(?:getenv|getProperty)\s*\(\s*"@\d+"\s*\)\s*\?:\s*"@\d+"{_END_OF_CODE}')
_SPRING_FALLBACK = re.compile(
    rf"(?P<prefix>[ \t]*{_SETTING}[ \t]*[:=][ \t]*)(?P<quote>[\"']?)\$\{{(?P<name>{_SETTING}):[^{{}}\"'\\\r\n]+\}}(?P=quote)(?P<suffix>[ \t]*(?:#[^\r\n]*)?)"
)
_SPRING_LITERAL_KEY = re.compile(
    r"(?P<prefix>[ \t]*(?P<key>[a-z][a-z0-9]*(?:[.-][a-z][a-z0-9]*)+)[ \t]*=[ \t]*)[^\s\\\"'$#{}]+(?P<suffix>[ \t]*)"
)
_PROPERTY_NAME = re.compile(r"^[ \t]*([A-Za-z0-9_.-]+)(?:[ \t]*[:=]|[ \t]+)")
_ORIGINS = re.compile(
    rf"(?P<prefix>[ \t]*(?:{_NAME}[ \t]*\.[ \t]*)?(?:allowedOrigins|allowedOriginPatterns)[ \t]*=[ \t]*(?:listOf|mutableListOf|arrayListOf)[ \t]*\([ \t]*)"
    rf"(?P<origins>{_LITERAL}(?:[ \t]*,[ \t]*{_LITERAL})+)(?P<suffix>[ \t]*,?[ \t]*\){_END_OF_CODE})"
)
_CORS_WILDCARD = re.compile(
    rf'(?P<prefix>[ \t]*(?P<receiver>{_NAME})\s*\.\s*allowedOriginPatterns\s*=\s*)'
    rf'(?P<edit>listOf\([ \t]*"\*"[ \t]*\))(?P<suffix>{_END_OF_CODE})'
)
_CORS_IMPORT = re.compile(r"^[ \t]*import[ \t]+org\.springframework\.web\.cors\.CorsConfiguration[ \t]*\r?$", re.M)
_CORS_REASON = "Правка убирает разрешение для сторонних источников из этой политики CORS. Перед слиянием проверьте, нужен ли межсайтовый доступ, и при необходимости укажите доверенные источники."


_REASONS = {
    "api-key": "Укажите внешний источник нового ключа и отзовите старый. Автоматическая замена доступна для однозначных настроек Spring.",
    "secret-fallback": "Уберите резервный секрет и проверьте запуск с обязательной внешней настройкой. Для автоматической правки нужна однозначная ссылка на уже заданный источник секрета.",
    "credentialed-cors": "Укажите доверенные источники или отключите передачу учётных данных, если она не нужна. Автоисправление удаляет звёздочку, когда рядом уже перечислены конкретные источники.",
}


def kotlin_repair_reason(finding):
    return _REASONS.get(finding.get("class"))


def _standalone_line(body, index):
    lines = Kotlin(body).code.splitlines()
    if index >= len(lines):
        return ""
    line = lines[index]
    following = next((part.lstrip() for part in lines[index + 1:] if part.strip()), "")
    continuation = re.match(r"(?:\.|\?\.|\?:|::|\[|[+*/%=&|<>!-]|as\b|is\b|in\b)", following)
    return "" if continuation and not line.rstrip().endswith(";") else line


def _kotlin_fallback(body, index, line):
    # Match both the literal input and lexed code so a comment or multiline string cannot be patched.
    match = _KOTLIN_FALLBACK.fullmatch(line)
    if not match or not _KOTLIN_FALLBACK_MASKED.fullmatch(_standalone_line(body, index)):
        return None
    return f"{match['prefix']}kotlin.checkNotNull({match['lookup']}){match['suffix']}"


def _spring_fallback(path, physical, index, line):
    if not spring_properties(path) or _property_continuation(physical, index):
        return None
    match = _SPRING_FALLBACK.fullmatch(line)
    if not match:
        return None
    return f"{match['prefix']}{match['quote']}${{{match['name']}}}{match['quote']}{match['suffix']}"


def _property_continuation(physical, index):
    previous = physical[index - 1].rstrip("\r\n") if index else ""
    return (len(previous) - len(previous.rstrip("\\"))) % 2 != 0


def _env_name(key):
    return re.sub(r"[.-]", "_", key).upper()


def _spring_key(path, physical, index, line):
    if (not spring_properties(path) or PurePosixPath(path).parts[-4:-1] != ("src", "main", "resources")
            or _property_continuation(physical, index)):
        return None
    match = _SPRING_LITERAL_KEY.fullmatch(line)
    if not match:
        return None
    name = _env_name(match["key"])
    if len(name) > 128:
        return None
    for other_index, row in enumerate(physical):
        if other_index == index:
            continue
        if re.search(rf"(?<![A-Za-z0-9_]){name}(?![A-Za-z0-9_])", row):
            return None
        prior = _PROPERTY_NAME.match(row)
        if prior and _env_name(prior[1]) == name:
            return None
    return match, name


def _concrete_origin(value):
    if not value.isascii() or not re.fullmatch(r"https?://[A-Za-z0-9][A-Za-z0-9.-]*(?::[0-9]{1,5})?", value):
        return False
    try:
        port = urlsplit(value).port
        return port is None or port > 0
    except ValueError:
        return False


def _cors_allowlist(body, index, line):
    match = _ORIGINS.fullmatch(line)
    if not match or not _ORIGINS.fullmatch(_standalone_line(body, index)):
        return None
    origins = re.findall(_LITERAL, match["origins"])
    retained = [origin for origin in origins if origin != '"*"']
    if len(retained) == len(origins) or not retained or not all(_concrete_origin(origin[1:-1]) for origin in retained):
        return None
    return match["prefix"] + ", ".join(retained) + match["suffix"]


def _patch_source(snapshot, finding):
    path, line = finding.get("path"), finding.get("line")
    if (not isinstance(path, str) or type(line) is not int or line < 1
            or finding.get("sourceContext") == "test"):
        return None
    body = snapshot.get(path)
    if not isinstance(body, str) or "\r" in body.replace("\r\n", ""):
        return None
    physical = body.splitlines(keepends=True)
    if line > len(physical):
        return None
    return path, body, physical, line - 1, physical[line - 1].rstrip("\r\n")


def _validated_patch(path, body, physical, index, original, replacement, rule):
    if replacement is None or replacement == original:
        return None
    replacement += physical[index][len(original):]
    patched = {path: "".join(physical[:index] + [replacement] + physical[index + 1:])}
    scanners = (scan_secrets, scan_sast)
    before = Counter((item["class"], item["line"]) for scan in scanners for item in scan({path: body}))
    target = (rule, index + 1)
    if before[target] != 1:
        return None
    del before[target]
    after = Counter((item["class"], item["line"]) for scan in scanners for item in scan(patched))
    return patched if before == after else None


def safe_kotlin_repair(snapshot, finding):
    """Change one exact finding and confirm that all other local findings remain unchanged."""
    inputs = _patch_source(snapshot, finding)
    if not inputs:
        return None
    path, body, physical, index, original = inputs
    suffix = PurePosixPath(path).suffix.lower()
    rule = finding.get("class")
    if rule == "secret-fallback" and finding.get("category") == "SECRET":
        changed = _kotlin_fallback(body, index, original) if suffix == ".kt" else _spring_fallback(path, physical, index, original)
    elif rule == "api-key" and finding.get("category") == "SECRET":
        resolved = _spring_key(path, physical, index, original)
        if not resolved:
            return None
        match, name = resolved
        changed = f"{match['prefix']}${{{name}}}{match['suffix']}"
    elif rule == "credentialed-cors" and finding.get("category") == "SAST" and suffix == ".kt":
        changed = _cors_allowlist(body, index, original)
    else:
        return None
    return _validated_patch(path, body, physical, index, original, changed, rule)


def kotlin_repair_note(snapshot, finding):
    inputs = _patch_source(snapshot, finding)
    if not inputs:
        return None
    path, _, physical, index, original = inputs
    rule = finding.get("class")
    if rule == "api-key" and (resolved := _spring_key(path, physical, index, original)):
        return f"Перед слиянием задайте {resolved[1]} в окружении приложения и перевыпустите прежний ключ."
    if rule == "secret-fallback":
        pattern = _KOTLIN_FALLBACK if PurePosixPath(path).suffix.lower() == ".kt" else _SPRING_FALLBACK
        if match := pattern.fullmatch(original):
            return f"Перед слиянием проверьте, что обязательная настройка {match['name']} задана в окружении приложения."
    return None


def cors_model_candidate(snapshot, finding):
    """Prove an exact Spring CORS patch that disables unrestricted cross-origin access."""
    if finding.get("class") != "credentialed-cors" or finding.get("category") != "SAST":
        return None
    inputs = _patch_source(snapshot, finding)
    if not inputs:
        return None
    path, body, physical, index, original = inputs
    if PurePosixPath(path).suffix != ".kt":
        return None
    origin = _CORS_WILDCARD.fullmatch(original)
    if not origin:
        return None
    unit = Kotlin(body)
    code = unit.code.splitlines()
    lexical = _standalone_line(body, index)
    if not re.fullmatch(rf'[ \t]*{origin["receiver"]}\s*\.\s*allowedOriginPatterns\s*=\s*listOf\(\s*"@\d+"\s*\){_END_OF_CODE}', lexical):
        return None
    receiver = origin["receiver"]
    prior = next((line.strip() for line in reversed(code[:index]) if line.strip()), "")
    class_ref = r"org\.springframework\.web\.cors\.CorsConfiguration"
    if _CORS_IMPORT.search(unit.code):
        class_ref = rf"(?:{class_ref}|CorsConfiguration)"
    if not re.fullmatch(rf"val\s+{receiver}\s*=\s*{class_ref}\(\s*\)\s*;?", prior):
        return None
    replacement = "emptyList()"
    changed = origin["prefix"] + replacement + origin["suffix"]
    if not _validated_patch(path, body, physical, index, original, changed, "credentialed-cors"):
        return None
    span = origin.span("edit")
    line_start = sum(len(row.encode("utf-8")) for row in physical[:index])
    start, end = (line_start + len(original[:offset].encode("utf-8")) for offset in span)
    return {"path": path, "line": index + 1, "start": start, "end": end,
            "before": origin["edit"], "replacement": replacement, "reason": _CORS_REASON}
