"""Bounded regex matching for named workflow sockets."""
import json
import re
import signal
import sys


MAX_MATCHES = 2048


def validate_parameters(params):
    if set(params) - {"pattern", "values"}:
        raise ValueError("Проверьте настройки регулярного выражения.")
    pattern = params.get("pattern")
    if not isinstance(pattern, str) or not 1 <= len(pattern) <= 128:
        raise ValueError("Введите регулярное выражение длиной до 128 символов.")
    try:
        re.compile(pattern)
    except (re.error, OverflowError) as error:
        raise ValueError("Проверьте синтаксис регулярного выражения.") from error
    values = params.get("values", [])
    if (not isinstance(values, list) or len(values) > 256
            or any(not isinstance(value, str) or len(value) > 1024 for value in values)
            or sum(map(len, values)) > 32768):
        raise ValueError("Допустимо до 256 строк по 1024 символа и до 32768 символов суммарно.")
    return {"pattern": pattern, "values": list(values)}


def match_values(pattern, values):
    from pathlib import Path
    import subprocess
    # Connected lists can originate from a repository snapshot or another regex.
    if (not isinstance(values, list) or len(values) > MAX_MATCHES
            or any(not isinstance(item, str) or len(item) > 1024 for item in values)
            or sum(map(len, values)) > 525000):
        raise ValueError("Список для проверки превышает допустимый размер.")
    try:
        result = subprocess.run(
            [sys.executable, "-I", "-S", "-B", str(Path(__file__).resolve())],
            input=json.dumps([pattern, values]).encode("ascii"),
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=12 if hasattr(signal, "setitimer") else 2, check=False,
        )
    except subprocess.TimeoutExpired as error:
        if hasattr(signal, "setitimer"):
            raise ValueError("Процесс проверки Regex не ответил вовремя. Повторите запуск.") from error
        raise ValueError("Проверка Regex превысила 2 секунды. Упростите выражение.") from error
    if hasattr(signal, "SIGALRM") and result.returncode == -signal.SIGALRM:
        raise ValueError("Проверка Regex превысила 2 секунды. Упростите выражение.")
    if result.returncode == 3:
        raise ValueError("Найдено больше 2048 совпадений. Уточните выражение.")
    if result.returncode:
        raise ValueError("Проверка Regex превысила доступные ресурсы. Упростите выражение.")
    matches = json.loads(result.stdout)
    return {"matches": matches, "count": len(matches), "found": bool(matches)}


if __name__ == "__main__":
    if sys.platform.startswith("linux"):
        import resource
        resource.setrlimit(resource.RLIMIT_AS, (128 * 1024**2, 128 * 1024**2))
    expression, entries = json.load(sys.stdin)
    # On POSIX the matching budget starts after interpreter startup and JSON input.
    if hasattr(signal, "setitimer"):
        signal.setitimer(signal.ITIMER_REAL, 2)
    compiled = re.compile(expression)
    output = []
    for entry in entries:
        for match in compiled.finditer(entry):
            if len(output) == MAX_MATCHES:
                sys.exit(3)
            output.append(match.group())
    if hasattr(signal, "setitimer"):
        signal.setitimer(signal.ITIMER_REAL, 0)
    json.dump(output, sys.stdout)
