"""Bounded subprocess for passive static checks of submitted text."""
import json
import os
from pathlib import Path
import sys

def main():
    if os.name=="posix":
        import resource
        resource.setrlimit(resource.RLIMIT_CPU,(20,22))
        resource.setrlimit(resource.RLIMIT_AS,(320*1024**2,320*1024**2))
    sys.path.insert(0,str(Path(__file__).resolve().parent))
    from case_detectors import scan_secrets
    from case_unified import graph_sast, manifest_findings, file_coverage, sca_paths
    kind, files, advisories = json.load(sys.stdin.buffer)
    from case_metrics import coordinates
    try:
        if kind == "sast":
            findings = graph_sast(files)
        elif kind in ("github_actions", "dockerfile"):
            from case_pipeline_checks import inspect
            findings = inspect(kind, files)
        elif kind == "java_review":
            from case_java_review import inspect
            findings = inspect(files)
        elif kind == "spring_review":
            from case_spring_review import inspect
            from case_jvm_crypto import inspect as inspect_crypto
            from case_kotlin_jpa import inspect as inspect_jpa
            findings = inspect(files)
            findings["findings"].extend(inspect_jpa(files))
            covered = {row["file"] for row in findings["coverage"]}
            for path, body in sorted(files.items()):
                if not path.lower().endswith((".kt", ".java")):
                    continue
                findings["findings"].extend(inspect_crypto(path, body))
                if path not in covered:
                    findings["coverage"].append({"file":path, "engine":kind, "status":"done", "message":"Проверены вызовы MessageDigest."})
        elif kind == "spring_routes":
            from case_spring_routes import inspect
            findings = inspect(files) | {"findings": []}
        elif kind == "ai_review":
            from case_ai_review import candidates
            findings = candidates(files)
        elif kind == "json_keys":
            from case_json_keys import inspect
            findings = inspect(files)
        elif kind == "dependency_review":
            from case_dependency_review import compare
            findings = compare(files, advisories)
        elif kind == "package_review":
            from case_package_review import inspect
            findings = inspect(files, advisories)
        elif kind == "literal_review":
            from case_literal_review import inspect
            findings = inspect(files, advisories)
        elif kind == "sca":
            items, errors = manifest_findings(files, advisories)
            paths = sca_paths(files)
            findings = {"findings": items, "coverage": [dict(entry, engine=kind) for entry in file_coverage(paths, items, errors)]}
        else:
            findings = {"secrets":scan_secrets,"coordinates":coordinates}[kind](files)
    except ValueError as error:
        findings = {"inputError":str(error)}
    output = json.dumps(findings,ensure_ascii=False).encode()
    if len(output)>6_000_000:
        raise ValueError("report limit")
    sys.stdout.buffer.write(output)

if __name__=="__main__":
    main()
