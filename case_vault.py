"""Encrypt operator-provisioned integration credentials with AES-256-GCM."""

import argparse
import base64
import getpass
import os
from pathlib import Path
import sys
import tempfile


PREFIX = "DARNING-VAULT-v1:"
KEY_PATH = "/run/secrets/bank_integration_key"
NAMES = (
    "BANK_SMTP_PASSWORD", "BANK_ACCOUNT_SMTP_PASSWORD", "BANK_AI_KEY", "BANK_GITHUB_PRIVATE_KEY", "BANK_GITHUB_WEBHOOK_SECRET",
    "BANK_TELEGRAM_BOT_TOKEN", "BANK_TELEGRAM_WEBHOOK_SECRET", "BANK_METRICS_GITHUB_TOKEN",
)
MAX_BYTES = 65536


def _decode(encoded):
    return base64.b64decode(encoded.encode("ascii"), altchars=b"-_", validate=True)


def _cipher(key_path):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    try:
        with Path(key_path).open("rb") as source:
            key = _decode(source.read(128).strip().decode("ascii"))
        if len(key) != 32:
            raise ValueError()
    except (OSError, ValueError, UnicodeError):
        raise ValueError("Файл мастер-ключа недоступен или повреждён.") from None
    return AESGCM(key)


def _aad(name):
    if name not in NAMES:
        raise ValueError("Указан неизвестный тип секрета.")
    return (PREFIX + name).encode("ascii")


def seal(name, value, key_path):
    data = value.encode("utf-8")
    if not 1 <= len(data) <= MAX_BYTES or "\0" in value:
        raise ValueError("Проверьте длину и формат секрета.")
    nonce = os.urandom(12)
    ciphertext = _cipher(key_path).encrypt(nonce, data, _aad(name))
    return PREFIX + base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")


def unseal(name, envelope):
    from cryptography.exceptions import InvalidTag

    cipher = _cipher(os.getenv("BANK_VAULT_KEY_FILE") or KEY_PATH)
    try:
        if not envelope.startswith(PREFIX) or len(envelope) > (MAX_BYTES + 64) * 2:
            raise ValueError()
        raw = _decode(envelope[len(PREFIX):])
        data = cipher.decrypt(raw[:12], raw[12:], _aad(name))
        return data.decode("utf-8")
    except (InvalidTag, ValueError, UnicodeError):
        raise ValueError("Проверка подлинности или формата зашифрованного секрета не пройдена.") from None


def _save(path, contents, replace=False):
    path = Path(path)
    fd, name = tempfile.mkstemp(prefix=".darning-key-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="ascii", newline="\n") as target:
            target.write(contents + "\n")
            target.flush()
            os.fsync(target.fileno())
        if replace:
            os.replace(name, path)
        else:
            # Publish a complete private file with exclusive-create semantics.
            os.link(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    keygen = commands.add_parser("keygen", help="Создать новый мастер-ключ.")
    keygen.add_argument("path", type=Path)
    put = commands.add_parser("put", help="Зашифровать значение и записать его в файл.")
    put.add_argument("name", choices=NAMES)
    put.add_argument("path", type=Path)
    put.add_argument("--key-file", default=os.getenv("BANK_VAULT_KEY_FILE") or KEY_PATH)
    put.add_argument("--stdin", action="store_true", help="Прочитать UTF-8 или PEM из stdin.")
    put.add_argument("--replace", action="store_true", help="Атомарно заменить существующий выходной файл.")
    args = parser.parse_args(argv)
    try:
        if args.operation == "keygen":
            _save(args.path, base64.urlsafe_b64encode(os.urandom(32)).decode("ascii"))
        else:
            if args.stdin:
                raw = sys.stdin.buffer.read(MAX_BYTES + 1)
                if len(raw) > MAX_BYTES:
                    raise ValueError("Слишком длинное значение.")
                value = raw.decode("utf-8-sig").rstrip("\r\n")
            else:
                if not sys.stdin.isatty():
                    raise ValueError("Для чтения из канала используйте --stdin.")
                value = getpass.getpass("Значение секрета: ")
            _save(args.path, seal(args.name, value, args.key_file), args.replace)
    except FileExistsError:
        parser.exit(2, "Файл уже существует. Для ротации секрета используйте --replace.\n")
    except (ValueError, OSError, EOFError, ImportError):
        parser.exit(2, "Не удалось записать секрет. Проверьте ключ, формат ввода и права на каталог.\n")
    print("Файл мастер-ключа создан." if args.operation == "keygen" else f"{args.name}: ••••••••")


if __name__ == "__main__":
    main()
