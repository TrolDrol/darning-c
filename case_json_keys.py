"""Locate shadowed JSON object keys without evaluating source code."""
from bisect import bisect_right
from hashlib import sha256
import json
import re


TOKENS = re.compile(r'"(?:[^"\\]|\\.)*"|[][{}:]')


def inspect(files):
    findings, coverage = [], []
    for path, body in sorted(files.items()):
        row = {"file": path, "engine": "json_keys", "status": "done", "message": "Проверено"}
        coverage.append(row)
        try:
            json.loads(body)
        except (ValueError, RecursionError) as error:
            row.update(status="error", message="Некорректный JSON или слишком глубокая вложенность.")
            if isinstance(error, json.JSONDecodeError):
                row.update(line=error.lineno, column=error.colno)
            continue
        starts = [0] + [m.end() for m in re.finditer("\n", body)]
        objects = []
        preceding = None
        for token in TOKENS.finditer(body):
            kind = token[0]
            if kind in ("{", "["):
                objects.append({} if kind == "{" else None)
            elif kind in ("}", "]"):
                objects.pop()
            elif kind == ":":
                key = json.loads(preceding[0])
                line = bisect_right(starts, preceding.start())
                column = preceding.start() - starts[line - 1] + 1
                first = objects[-1].setdefault(key, (line, column))
                if first != (line, column):
                    fingerprint = sha256(f"{path}:{key!r}:{line}:{column}".encode("utf8", "backslashreplace")).hexdigest()[:32]
                    findings.append({"category": "SAST", "class": "json-duplicate-key", "path": path,
                                     "line": line, "endLine": line, "column": column, "fingerprint": fingerprint,
                                     "severity": "MEDIUM", "title": "Повторяющийся ключ JSON",
                                     "description": f"Первое объявление в строке {first[0]}, столбце {first[1]}. При чтении одно значение может скрыть другое.",
                                     "fix": "Оставьте одно согласованное значение для этого ключа.",
                                     "remediation": "Удалите повтор и проверьте конфигурацию."})
            preceding = token
    return {"findings": findings, "coverage": coverage}
