"""Prepare small Python header repairs from persisted parser diagnostics."""

import ast
from hashlib import sha256
from io import StringIO
import re
import tokenize

from analyzers import physical_source
from case_archive import valid_path
from case_source import MAX_FILE, source_candidate


RULE = "python-header-syntax"
MESSAGES = {
    "Синтаксическая ошибка Python: expected '('.": "expected '('",
    "Синтаксическая ошибка Python: expected ':'.": "expected ':'",
}
BARE_FUNCTION = re.compile(r"[ \t]*(?:async[ \t]+)?def[ \t]+([^\W\d]\w*)[ \t]*(?:#.*)?")
FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)


def python_path(path):
    return (valid_path(path) and path.lower().endswith(".py") and source_candidate(path)
            and all(not part.startswith(".") for part in path.split("/")))


def syntax_fingerprint(path, line, column, detail):
    return sha256(f"{RULE}\0{path}\0{line}\0{column}\0{detail}".encode()).hexdigest()[:32]


def repairable_syntax_findings(report):
    """Offer parser diagnostics independently of security findings."""
    result = []
    for row in report.get("coverage", ()):
        path, line, column = (row.get(key) for key in ("file", "line", "column"))
        detail = MESSAGES.get(row.get("message"))
        if (row.get("engine") != "python" or row.get("status") != "error" or not detail
                or not python_path(path) or type(line) is not int or line < 1
                or type(column) is not int or column < 1):
            continue
        result.append({"category": "SYNTAX", "class": RULE, "checkId": RULE,
                       "path": path, "line": line, "column": column, "severity": "HIGH",
                       "fingerprint": syntax_fingerprint(path, line, column, detail),
                       "title": "Синтаксическая ошибка Python", "description": row["message"],
                       "fix": "Проверить, можно ли восстановить недостающие символы в заголовке функции."})
    return result


def _function_colon(source, tree, line, column):
    starts = [node.lineno for node in ast.walk(tree) if isinstance(node, FUNCTIONS)
              and node.lineno <= line < node.body[0].lineno]
    if not starts:
        return False
    start = max(starts)
    depth = 0
    for item in tokenize.generate_tokens(StringIO(source).readline):
        if item.start[0] < start or item.type != tokenize.OP:
            continue
        if item.string == ":" and depth == 0:
            return item.start == (line, column)
        if item.start >= (line, column):
            break
        if item.string in ("(", "[", "{"):
            depth += 1
        elif item.string in (")", "]", "}"):
            depth -= 1
    return False


def _header_position(row, detail, offset):
    if detail == "expected '('":
        match = BARE_FUNCTION.fullmatch(row)
        if match and match[1].isidentifier():
            return match.end(1), "():"
        return None
    tail = row[offset:].lstrip(" \t")
    if tail and not tail.startswith("#"):
        return None
    return len(row[:offset].rstrip(" \t")), ":"


def safe_python_syntax_repair(files, finding):
    """Repair an exact header diagnostic as text, then parse the entire result."""
    path = finding.get("path")
    if finding.get("class") != RULE or not python_path(path):
        return None
    body = files.get(path)
    if not isinstance(body, str):
        return None
    size = len(body.encode())
    if size > MAX_FILE:
        return None
    original = physical_source(body)
    try:
        ast.parse(original)
    except SyntaxError as error:
        line, column, detail = error.lineno, error.offset, error.msg
    except (RecursionError, ValueError):
        return None
    else:
        return None
    if (detail not in MESSAGES.values() or not line or not column or column < 1
            or (line, column) != (finding.get("line"), finding.get("column"))
            or finding.get("fingerprint") != syntax_fingerprint(path, line, column, detail)):
        return None
    parts = re.split(r"(\r\n|\r|\n)", body)
    index = (line - 1) * 2
    if index >= len(parts) or column - 1 > len(parts[index]):
        return None
    row = parts[index]
    position = _header_position(row, detail, column - 1)
    if position is None:
        return None
    offset, punctuation = position
    if size + len(punctuation) > MAX_FILE:
        return None
    parts[index] = row[:offset] + punctuation + row[offset:]
    changed = "".join(parts)
    normalized = physical_source(changed)
    try:
        tree = ast.parse(normalized)
        if _function_colon(normalized, tree, line, offset + len(punctuation) - 1):
            return {path: changed}
    except (SyntaxError, ValueError, RecursionError, tokenize.TokenError):
        pass
    return None
