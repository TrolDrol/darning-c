"""Configuration shared by the local and container entry points."""

import os
from pathlib import Path
from urllib.parse import urlsplit


def secret(name):
    file = os.getenv(f"{name}_FILE")
    value = os.getenv(name, "")
    if file:
        try:
            value = Path(file).read_text(encoding="utf-8-sig").rstrip("\r\n")
        except FileNotFoundError:
            pass
    if value.startswith("DARNING-VAULT-"):
        from case_vault import unseal
        return unseal(name, value)
    if value and os.getenv("BANK_VAULT_REQUIRED") == "1":
        from case_vault import NAMES
        if name in NAMES:
            raise ValueError("Для настроенной интеграции требуется зашифрованный секрет.")
    return value


def public_url():
    value = os.getenv("BANK_PUBLIC_URL", "").rstrip("/")
    parsed = urlsplit(value)
    if (
        not parsed.hostname or parsed.path or parsed.query or parsed.fragment
        or parsed.username is not None or parsed.password is not None
        or (parsed.scheme != "https" and (
            parsed.scheme != "http" or parsed.hostname not in ("localhost", "127.0.0.1", "::1")
        ))
    ):
        raise ValueError("BANK_PUBLIC_URL должен быть HTTPS-адресом стенда либо локальным HTTP-адресом.")
    host = parsed.hostname
    host = f"[{host}]" if ":" in host else host.encode("idna").decode()
    default_port = 443 if parsed.scheme == "https" else 80
    if parsed.port and parsed.port != default_port:
        host = f"{host}:{parsed.port}"
    return f"{parsed.scheme}://{host}"
