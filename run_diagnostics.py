"""Analysis errors reconstructed from saved reports, including older file coverage."""

import re


def analysis_diagnostics(report):
    diagnostics = []
    covered_engines = set()
    for entry in report.get("coverage") or ():
        if entry.get("status") != "error":
            continue
        fields = {key: entry[key] for key in ("engine", "file", "message", "line", "column") if entry.get(key)}
        diagnostics.append(fields)
        covered_engines.add(entry.get("engine"))

    for stage in report.get("stages") or ():
        engine = stage.get("id")
        if stage.get("status") == "error" and engine != "deliver" and engine not in covered_engines:
            diagnostics.append({"engine": engine, "message": stage.get("message")})
    if report.get("error") and report.get("status") == "failed":
        diagnostics.append({"message": report["error"]})
    for entry in diagnostics:
        # Earlier parsers stored a line number as their entire message.
        if "line" not in entry and (match := re.fullmatch(r"Строка (\d+)", entry.get("message") or "")):
            entry["line"] = int(match[1])
    return diagnostics
