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
    from case_unified import graph_sast, applicable, manifest_findings, file_coverage
    kind, files, advisories = json.load(sys.stdin.buffer)
    from case_metrics import coordinates
    try:
        if kind == "sast":
            findings = graph_sast(files)
        elif kind == "sca":
            items, errors = manifest_findings(files, advisories)
            paths = sorted(path for path in files if applicable(path, kind))
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
