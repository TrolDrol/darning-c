"""Export findings from a saved report in SARIF 2.1.0."""
from hashlib import sha256
from urllib.parse import quote


SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def report_document(run):
    from case_archive import valid_path
    rules = {}
    results = []
    for finding in run.get("findings", ()):
        path = finding.get("path") or finding.get("file")
        if not valid_path(path):
            continue
        rule_id = next((finding[key] for key in ("checkId", "standardRule", "ruleId", "class", "category")
                        if finding.get(key)), "DARNING")
        title = finding.get("title") or rule_id
        rules.setdefault(rule_id, {"id": rule_id, "shortDescription": {"text": title}})
        location = {"artifactLocation": {"uri": quote(path, safe="/")}}
        line, column, end = (finding.get(name) for name in ("line", "column", "endLine"))
        if type(line) is int and line > 0:
            region = {"startLine": line}
            if type(column) is int and column > 0:
                region["startColumn"] = column
            if type(end) is int and end >= line:
                region["endLine"] = end
            location["region"] = region
        fingerprint = finding.get("fingerprint")
        if not fingerprint:
            fingerprint = sha256(f"{rule_id}\0{path}\0{line}\0{column}\0{finding.get('advisoryId') or ''}".encode()).hexdigest()
        properties = {"remediation": finding.get("fix") or finding.get("remediation") or ""}
        if finding.get("advisoryId"):
            properties["advisory"] = finding["advisoryId"]
        results.append({"ruleId": rule_id, "level": LEVEL.get((finding.get("severity") or finding.get("level") or "").lower(), "warning"),
                        "message": {"text": finding.get("description") or finding.get("risk") or title},
                        "locations": [{"physicalLocation": location}],
                        "partialFingerprints": {"darning/v1": fingerprint},
                        "properties": properties})
    return {"$schema": SCHEMA, "version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "Darning", "rules": list(rules.values())}}, "results": results,
        "invocations": [{"executionSuccessful": run.get("status") in {"review", "passed"}}],
    }]}
