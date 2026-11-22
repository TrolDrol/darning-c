"""Review explicit JVM MessageDigest calls in Java and Kotlin sources."""
from collections import Counter
from hashlib import sha256
import re

from case_detectors import ID, Kotlin, LIT


RULE_ID = "JVM-001"
RULES = {
    RULE_ID: {
        "engine": "spring_review", "level": "medium", "title": "Устаревший алгоритм MessageDigest",
        "risk": "MD5 и SHA-1 имеют известные коллизии. Проверьте, зависит ли от этого хеша безопасность приложения.",
        "fix": "Для проверки целостности используйте SHA-256 или более стойкий алгоритм. Для хранения паролей используйте специализированную функцию, например Argon2id.",
        "verify": "Повторите проверку и протестируйте совместимость с уже сохранёнными значениями и внешними сервисами.",
    },
}

ALGORITHMS = {"md5": "MD5", "sha-1": "SHA-1"}
MESSAGE_DIGEST = "java.security.MessageDigest"
IMPORT = re.compile(
    rf"^[ \t]*import[ \t]+(?P<package>{ID}(?:[ \t]*\.[ \t]*{ID})+)"
    rf"(?:[ \t]+as[ \t]+(?P<alias>{ID}))?[ \t]*(?:;|$)", re.MULTILINE,
)
DECLARED_NAME = re.compile(
    rf"\b(?:enum(?:\s+class)?|class|interface|object|record|typealias|val|var|fun)\s+({ID})\b"
    rf"|\b({ID})\s*:(?!:)|\b{ID}\s+({ID})\s*(?=[=;,)\[\]])",
)


def applies(path):
    return path.lower().endswith((".kt", ".java"))


def inspect(path, source):
    if not applies(path):
        return []

    unit = Kotlin(source.replace("\r\n", "\n"))
    hidden = {next(name for name in match.groups() if name) for match in DECLARED_NAME.finditer(unit.code)}
    imports = {}
    for match in IMPORT.finditer(unit.code):
        name = re.sub(r"[ \t]+", "", match["package"])
        imports.setdefault(match["alias"] or name.rsplit(".", 1)[-1], set()).add(name)
    receivers = [
        re.escape(name) for name, targets in imports.items()
        if targets == {MESSAGE_DIGEST} and name not in hidden
    ]
    if "java" not in hidden:
        receivers.append(r"java\s*\.\s*security\s*\.\s*MessageDigest")
    if not receivers:
        return []

    calls = re.compile(
        rf"\b(?:{'|'.join(receivers)})\s*\.\s*getInstance\s*\(\s*(?P<value>{LIT})(?=\s*[,\)])",
    )
    rows = []
    occurrences = Counter()
    rule = RULES[RULE_ID]
    for match in calls.finditer(unit.code):
        previous = match.start() - 1
        while previous >= 0 and unit.code[previous].isspace():
            previous -= 1
        if previous >= 0 and unit.code[previous] in ".$":
            continue
        algorithm = ALGORITHMS.get(unit.strings[match["value"]].lower())
        if algorithm is None:
            continue
        line = unit.line(match.start())
        occurrences[algorithm] += 1
        identity = f"{RULE_ID}\0{path}\0{algorithm}\0{occurrences[algorithm]}"
        rows.append({
            "category": "SAST", "class": RULE_ID, "checkId": RULE_ID,
            "path": path, "line": line, "endLine": line,
            "fingerprint": sha256(identity.encode()).hexdigest()[:32],
            "severity": rule["level"].upper(), "title": rule["title"],
            "description": f"java.security.MessageDigest запрашивает {algorithm}. {rule['risk']}",
            "fix": rule["fix"], "remediation": rule["fix"],
        })
    return rows
