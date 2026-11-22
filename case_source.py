"""Read bounded Kotlin project snapshots as inert text. No build or checkout hooks."""
import json
from pathlib import Path, PurePosixPath

MAX_BYTES = 3_000_000
MAX_FILE = 300_000
SKIP = {".git", ".gradle", ".idea", "build", "out", "target", "node_modules", ".venv", "venv", "__pycache__", "dist"}
EXTENSIONS = {".kt", ".kts", ".properties", ".toml", ".yml", ".yaml", ".xml", ".json", ".lockfile", ".sql", ".conf", ".env"}
IGNORED_DIRECTORIES = SKIP | {"vendor", ".hg", ".svn", ".cache", ".tox", ".mypy_cache", ".pytest_cache", ".secrets"}
ENV_NAMES = {".env", ".env.local", ".env.production", ".env.production.local", ".env.prod",
             ".env.staging", ".env.development.local"}
PRIVATE_KEY_NAMES = {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_ecdsa_sk", "id_ed25519_sk",
                     "private.key", "private.pem", "server.key"}
SENSITIVE_NAMES = ENV_NAMES | PRIVATE_KEY_NAMES
KEY_SUFFIXES = {".key", ".pem", ".p12", ".pfx", ".jks", ".keystore"}
BINARY_EXTENSIONS = set((".png .jpg .jpeg .gif .webp .avif .ico .bmp .pdf .zip .gz .tgz .xz .bz2 .7z .rar "
                         ".tar .jar .war .class .so .dll .exe .obj .o .a .bin .wasm .pyc .db .sqlite .sqlite3 "
                         ".woff .woff2 .ttf .otf .eot .mp3 .mp4 .mov .webm .wav .ogg .docx .xlsx .pptx").split())


def source_candidate(path):
    *directories, name = path.casefold().split("/")
    suffix = "." + name.rsplit(".", 1)[1] if "." in name else ""
    return (not IGNORED_DIRECTORIES.intersection(directories) and name not in SENSITIVE_NAMES
            and not name.startswith(".env.") and suffix not in BINARY_EXTENSIONS and suffix not in KEY_SUFFIXES)

def supported(path):
    parts = path.split("/")
    return (not any(part in SKIP for part in parts)
            and (PurePosixPath(path).suffix.lower() in EXTENSIONS or parts[-1] in (".env", "settings.gradle")))

def validate_files(files):
    if not isinstance(files, dict) or not 1 <= len(files) <= 1500:
        raise ValueError("Выберите папку проекта с файлами .kt, build.gradle.kts или pom.xml (до 1500 исходных файлов).")
    total = 0
    clean = {}
    for name, value in files.items():
        if (not isinstance(name, str) or not name or len(name) > 350 or "\\" in name
                or ":" in name or any(p in {"", ".", ".."} for p in name.split("/"))):
            raise ValueError("Неверный относительный путь.")
        if not supported(name):
            continue
        if not isinstance(value, str) or "\x00" in value:
            raise ValueError("Исходники должны быть текстом UTF-8.")
        size = len(value.encode())
        total += size
        if size > MAX_FILE:
            raise ValueError(f"Файл {name} превышает 300 КБ. Выберите меньший модуль проекта.")
        if total > MAX_BYTES:
            raise ValueError("Выбранные исходники превышают 3 МБ. Выберите папку одного модуля.")
        clean[name] = value
    if not any(p.endswith(".kt") or PurePosixPath(p).name in ("build.gradle.kts","pom.xml") for p in clean):
        raise ValueError("В выбранных файлах нет .kt, build.gradle.kts или pom.xml. Выберите корень проекта или его модуль. Для Python и JSON откройте «Запуски».")
    return clean

def advisory_database():
    directory = Path(__file__).parent / "case_data"
    maven = json.loads((directory / "vulnerabilities.json").read_text(encoding="utf-8"))
    supplement = json.loads((directory / "maven-supplement.json").read_text(encoding="utf-8"))
    packages = json.loads((directory / "package-advisories.json").read_text(encoding="utf-8"))
    maven["vulnerabilities"].extend(supplement["vulnerabilities"])
    return maven | packages
