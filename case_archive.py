"""Read bounded text files from an uploaded project without extracting to disk."""
import base64
import binascii
from collections import Counter
from io import BytesIO
from pathlib import PurePosixPath
import re
import stat
import struct
from zipfile import BadZipFile, ZIP_DEFLATED, ZIP_STORED, ZipFile
from zlib import error as ZlibError

from case_source import (MAX_BYTES, MAX_FILE, IGNORED_DIRECTORIES, SENSITIVE_NAMES, KEY_SUFFIXES, ENV_NAMES,
                         BINARY_EXTENSIONS, source_candidate, supported, validate_files)
from workspace import WorkspaceError

MAX_ARCHIVE = 8_000_000
MAX_ENTRIES = 12_000
EXAMPLE_DIRECTORIES = {"example", "examples", "sample", "samples", "demo", "demos", "test", "tests", "__tests__",
                       "testdata", "test-data", "testfixtures", "test-fixtures", "fixture", "fixtures", "__fixtures__",
                       "mock", "mocks", "__mocks__", "template", "templates"}
SOURCE_POLICY = {"ignoredDirectories": sorted(IGNORED_DIRECTORIES), "metadataOnlyNames": sorted(SENSITIVE_NAMES),
                 "metadataOnlyPrefixes": [".env."], "metadataOnlySuffixes": sorted(KEY_SUFFIXES),
                 "binaryExtensions": sorted(BINARY_EXTENSIONS)}


def valid_path(path):
    return (isinstance(path, str) and 0 < len(path) <= 512 and not any(c in path for c in "\\:")
            and not any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in path)
            and all(part not in ("", ".", "..") for part in path.split("/")))


def matches_filter(path, filters):
    from case_sca import GRADLE_CATALOG, GRADLE_LOCK, GRADLE_SETTINGS, gradle_support_files
    filename = PurePosixPath(path)
    name = filename.name
    support = {"python": path.lower().endswith(".py"), "config": path.lower().endswith(".json"),
               "sast": path.lower().endswith(".kt"), "secrets": True,
               "sca": name in ("pom.xml", "build.gradle.kts", GRADLE_LOCK, "gradle.properties", *GRADLE_SETTINGS)
                      or filename.parts[-2:] == PurePosixPath(GRADLE_CATALOG).parts}
    for engine, selected in filters.items():
        if support.get(engine) and (not selected or selected == path):
            return True
        if engine == "sca" and selected and PurePosixPath(selected).name == "build.gradle.kts":
            if path in gradle_support_files(PurePosixPath(selected)):
                return True
    return False


def repository_inventory(paths, *, filters=None, empty_repository=False):
    """Count regular source-tree paths. Only canonical sensitive filenames leave the reader."""
    scoped = bool(filters and any(filters.values()))
    extensions = Counter()
    sensitive = []
    seen = set()
    total_bytes = 0
    for path in paths:
        if not valid_path(path) or path in seen:
            raise WorkspaceError("Снимок содержит некорректный или повторяющийся путь.")
        seen.add(path)
        total_bytes += len(path.encode("utf-8"))
        if len(seen) > MAX_ENTRIES or total_bytes > 2_000_000:
            raise WorkspaceError("Инвентарь превышает лимит путей. Выберите меньший модуль.", 413)
        parts = path.casefold().split("/")
        dirs, name = set(parts[:-1]), parts[-1]
        if dirs & IGNORED_DIRECTORIES or (scoped and not matches_filter(path, filters)):
            continue
        suffix = ".env" if name in ENV_NAMES else PurePosixPath(name).suffix
        if suffix and not re.fullmatch(r"\.[a-z0-9][a-z0-9_+-]{0,15}", suffix):
            suffix = "(other)"
        extensions[suffix] += 1
        if name in SENSITIVE_NAMES and not dirs & EXAMPLE_DIRECTORIES:
            if len(sensitive) >= 100:
                raise WorkspaceError("Более 100 файлов с признаками секретов в именах. Выберите меньший модуль.", 413)
            sensitive.append(path)
    total = sum(extensions.values())
    if len(extensions) > 64:
        other = extensions.pop("(other)", 0)
        for ext, count in sorted(extensions.items(), key=lambda item: (-item[1], item[0]))[63:]:
            other += extensions.pop(ext)
        extensions["(other)"] = other
    return {"totalFiles": total, "extensions": dict(sorted(extensions.items())),
            "sensitivePaths": sorted(sensitive), "scope": "paths" if scoped else "repository",
            "emptyRepository": empty_repository}


def accepts(path, mode):
    if mode == "repository":
        return source_candidate(path)
    if mode == "kotlin":
        return supported(path)
    if mode == "python":
        return not IGNORED_DIRECTORIES.intersection(path.casefold().split("/")[:-1]) and path.lower().endswith((".py", ".json"))
    raise WorkspaceError("Выберите проверку Python/JSON или студию Kotlin/Spring.")


def validated(files, mode):
    if mode == "kotlin":
        try:
            return validate_files(files)
        except ValueError as exc:
            raise WorkspaceError(str(exc)) from None
    if mode not in ("python", "repository"):
        raise WorkspaceError("Выберите проверку Python/JSON или студию Kotlin/Spring.")
    return files


def decode_archive(value):
    if not isinstance(value, str) or len(value) > ((MAX_ARCHIVE + 2) // 3) * 4:
        raise WorkspaceError("Выберите ZIP до 8 МБ или загрузите папку отдельного модуля.", 413)
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise WorkspaceError("Не удалось прочитать ZIP. Выберите файл ещё раз.") from None


def archive_snapshot(raw, mode, github_wrapper=False):
    if len(raw) > MAX_ARCHIVE:
        raise WorkspaceError("ZIP превышает 8 МБ. Выберите папку одного модуля.", 413)
    # Bound central-directory allocation before ZipFile constructs a ZipInfo per entry.
    end = raw.rfind(b"PK\x05\x06", max(0, len(raw)-65557))
    if end < 0 or end+22 > len(raw):
        raise WorkspaceError("Файл не является целым ZIP-архивом. Скачайте ZIP заново.")
    disk, start_disk, on_disk, count, directory_size, offset, comment = struct.unpack_from("<4H2IH", raw, end+4)
    if (disk or start_disk or on_disk != count or count > MAX_ENTRIES or directory_size > 2_000_000
            or offset+directory_size != end or end+22+comment != len(raw)):
        raise WorkspaceError("Нужен обычный ZIP до 12 000 записей. Выберите архив одного модуля.")
    files = {}
    total = 0
    try:
        with ZipFile(BytesIO(raw)) as archive:
            if len(archive.infolist()) != count:
                raise WorkspaceError("Число записей ZIP не совпало с каталогом архива.")
            regular = []
            for item in archive.infolist():
                path = item.orig_filename.rstrip("/")
                if not valid_path(path):
                    raise WorkspaceError("ZIP содержит недопустимый путь. Создайте архив из каталога проекта.")
                kind = stat.S_IFMT(item.external_attr >> 16)
                if not item.is_dir() and kind in (0, stat.S_IFREG):
                    regular.append((path, item))
            roots = {path.partition("/")[0] for path, _ in regular}
            # GitHub adds one transport directory. For an upload, keep source
            # paths unless a single enclosing directory clearly wraps the project.
            prefix = ""
            if len(roots) == 1 and all("/" in path for path, _ in regular):
                root = next(iter(roots))
                markers = {"build.gradle.kts","pom.xml","requirements.txt","pyproject.toml","README.md","settings.json"}
                if github_wrapper or any(path[len(root)+1:] in markers for path, _ in regular):
                    prefix = root+"/"
            names = {path.removeprefix(prefix) for path, _ in regular}
            if len(names) != len(regular):
                raise WorkspaceError("В ZIP найдены повторяющиеся пути. Устраните дубликаты.")
            for path, item in regular:
                if not path.startswith(prefix):
                    continue
                name = path[len(prefix):]
                if not accepts(name, mode):
                    continue
                if name in files:
                    raise WorkspaceError(f"В ZIP два файла с путём {name}. Устраните дубликат.")
                if item.flag_bits & 1 or item.compress_type not in (ZIP_STORED, ZIP_DEFLATED):
                    raise WorkspaceError("Сохраните ZIP без пароля с обычным сжатием Deflate.")
                if item.file_size > MAX_FILE:
                    raise WorkspaceError(f"Файл {name} превышает 300 КБ. Выберите папку одного модуля.", 413)
                total += item.file_size
                if total > MAX_BYTES or len(files) >= (1500 if mode=="kotlin" else 250):
                    raise WorkspaceError("Слишком много исходников. Выберите один модуль до 3 МБ.", 413)
                try:
                    content = archive.read(item).decode("utf-8-sig")
                except UnicodeDecodeError:
                    if mode == "repository":
                        continue
                    raise WorkspaceError(f"Сохраните {name} в UTF-8 и повторите загрузку.") from None
                if "\x00" in content:
                    if mode == "repository":
                        continue
                    raise WorkspaceError(f"Файл {name} содержит двоичные данные. Выберите текстовые исходники.")
                files[name] = content
    except (BadZipFile, ZlibError, EOFError, NotImplementedError):
        raise WorkspaceError("ZIP повреждён или использует неподдерживаемый способ сжатия.") from None
    if mode in ("python", "repository"):
        return {"files": files, "inventory": repository_inventory(names)}
    return {"files": validated(files, mode)}


def archive_files(raw, mode, github_wrapper=False):
    return archive_snapshot(raw, mode, github_wrapper)["files"]
