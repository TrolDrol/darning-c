"""Find a configured literal substring in an inert repository snapshot."""
from hashlib import sha256
import re

from case_source import MAX_FILE


ENGINE = "literal_review"
RULE = "TEXT-001"
MAX_FINDINGS = 500
RULES = {
    RULE: {
        "engine": ENGINE, "level": "medium", "title": "Совпадение с текстовым правилом",
        "risk": "В отмеченной строке есть совпадение с заданным правилом проекта.",
        "fix": "Проверьте отмеченное место и при необходимости замените значение согласно правилам проекта.",
        "verify": "Повторите проверку того же файла после правки.",
    },
}
SEVERITIES = {"low", "medium", "high", "critical"}
SUFFIX = re.compile(r"\.[A-Za-z0-9][A-Za-z0-9_.-]{0,31}")
DIRECTORY_PART = re.compile(r"[\w. -]+")


def parameters(params):
    keys = {"name", "literal", "caseSensitive", "severity", "directory", "suffix"}
    if not isinstance(params, dict) or set(params) - keys:
        raise ValueError("Проверьте параметры текстового правила.")
    name, literal = params.get("name"), params.get("literal")
    if not isinstance(name, str) or len(name) > 100 or not name.strip() or not name.isprintable():
        raise ValueError("Укажите название правила длиной до 100 символов.")
    if (not isinstance(literal, str) or not literal.strip() or len(literal) > 500
            or not literal.replace("\t", " ").isprintable()):
        raise ValueError("Укажите однострочный текст для поиска длиной до 500 символов.")
    case_sensitive = params.get("caseSensitive", True)
    if type(case_sensitive) is not bool:
        raise ValueError("Укажите, учитывать ли регистр.")
    severity = params.get("severity", "medium")
    if not isinstance(severity, str) or severity.lower() not in SEVERITIES:
        raise ValueError("Выберите допустимую критичность текстового правила.")
    normalized = {"name": name.strip(), "literal": literal, "caseSensitive": case_sensitive, "severity": severity.lower()}
    suffix = params.get("suffix", "")
    if suffix != "":
        if not isinstance(suffix, str) or not SUFFIX.fullmatch(suffix):
            raise ValueError("Укажите допустимое расширение, например .properties.")
        normalized["suffix"] = suffix.lower()
    directory = params.get("directory", "")
    if directory != "":
        if (not isinstance(directory, str) or len(directory) > 250
                or any(part in {"", ".", ".."} or not DIRECTORY_PART.fullmatch(part) for part in directory.split("/"))):
            raise ValueError("Укажите папку от корня проекта, например src/main.")
        normalized["directory"] = directory
    return normalized


def applies(path, params):
    directory, suffix = params.get("directory"), params.get("suffix")
    return (not directory or path.startswith(directory + "/")) and (not suffix or path.lower().endswith(suffix))


def match_column(line, needle, case_sensitive):
    haystack = line if case_sensitive else line.casefold()
    offset = haystack.find(needle)
    if offset < 0:
        return None
    if len(haystack) == len(line):
        return offset + 1
    # Case folding can expand one source character into multiple search characters.
    for column, char in enumerate(line, 1):
        offset -= len(char.casefold())
        if offset < 0:
            return column


def inspect(files, params):
    params = parameters(params)
    sensitive = params["caseSensitive"]
    needle = params["literal"] if sensitive else params["literal"].casefold()
    rule = RULES[RULE]
    findings, coverage = [], []
    for path, body in sorted(files.items()):
        if not applies(path, params):
            continue
        row = {"file": path, "engine": ENGINE, "status": "done", "message": "Проверено текстовым правилом."}
        coverage.append(row)
        if len(findings) == MAX_FINDINGS:
            row.update(status="error", message="Достигнут лимит совпадений текстового правила.")
            continue
        if not isinstance(body, str) or len(body.encode("utf8")) > MAX_FILE:
            row.update(status="error", message="Содержимое файла недоступно или превышает лимит размера.")
            continue
        occurrence = 0
        for line, text in enumerate(body.split("\n"), 1):
            column = match_column(text, needle, sensitive)
            if column is None:
                continue
            if len(findings) == MAX_FINDINGS:
                row.update(status="error", line=line, message="Достигнут лимит совпадений текстового правила.")
                break
            occurrence += 1
            fingerprint = sha256(f"{RULE}\0{params['name']}\0{path}\0{occurrence}".encode()).hexdigest()[:32]
            findings.append({"category": "SAST", "class": RULE, "checkId": RULE, "path": path, "line": line,
                             "endLine": line, "column": column, "fingerprint": fingerprint,
                             "severity": params["severity"].upper(), "title": rule["title"], "description": rule["risk"],
                             "fix": rule["fix"], "remediation": rule["fix"]})
    return {"findings": findings, "coverage": coverage}
