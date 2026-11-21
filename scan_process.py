"""Run the built-in static checks with bounded resources and a clean environment."""

import json
import sys

from analyzers import run_analysis


def main():
    if sys.platform != "win32":
        import resource
        resource.setrlimit(resource.RLIMIT_AS, (192 * 1024**2, 192 * 1024**2))
        resource.setrlimit(resource.RLIMIT_CPU, (25, 26))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    payload = json.load(sys.stdin)
    results = {}
    for name, sources in payload["snapshots"].items():
        findings, stages = run_analysis(sources, payload["rules"])
        results[name] = [findings, stages]
    json.dump(results, sys.stdout, ensure_ascii=True)


if __name__ == "__main__":
    main()
