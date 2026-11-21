"""Create installation credentials once in their separate Docker volumes."""
import base64
import os
from pathlib import Path
import secrets
from tempfile import NamedTemporaryFile


def initialize(path, generate):
    if path.is_file() and path.stat().st_size:
        return
    with NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
    try:
        temporary.write_text(generate() + "\n", encoding="ascii")
        temporary.chmod(0o444)
        try:
            os.link(temporary, path)
        except FileExistsError:
            if not path.is_file() or not path.stat().st_size:
                raise RuntimeError(f"Restore the missing credential at {path} from a backup.")
    finally:
        temporary.unlink()


if __name__ == "__main__":
    root = Path("/run/darning")
    for service in ("db", "postgres", "admin"):
        initialize(root / service / "password", lambda: secrets.token_urlsafe(36))
    initialize(root / "key/master", lambda: base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii"))
