"""Password verification and server-side browser sessions."""

import base64
import binascii
import hashlib
import hmac
import re
import struct
import zlib
from dataclasses import dataclass
from http.cookies import CookieError, SimpleCookie
from secrets import token_bytes, token_urlsafe
from threading import BoundedSemaphore

from redis.exceptions import RedisError

from workspace import WorkspaceError


USERNAME = re.compile(r"[A-Za-z0-9_.-]{1,64}")
TOKEN = re.compile(r"[A-Za-z0-9_-]{43}")
SESSION_TIME = 12 * 60 * 60


def avatar_png(value):
    if value is None:
        return None
    prefix = "data:image/png;base64,"
    error = WorkspaceError("Выберите изображение PNG до 96 × 96 пикселей и 45 КБ.")
    if not isinstance(value, str) or not value.startswith(prefix) or len(value) > len(prefix) + 61440:
        raise error
    try:
        raw = base64.b64decode(value[len(prefix):], validate=True)
        if raw[:8] != b"\x89PNG\r\n\x1a\n" or raw[8:16] != b"\0\0\0\rIHDR":
            raise error
        width, height, depth, color, comp, filt, interlace = struct.unpack(">IIBBBBB", raw[16:29])
        if not (1 <= width <= 96 and 1 <= height <= 96 and depth == 8 and color in (2, 6)
                and (comp, filt, interlace) == (0, 0, 0)):
            raise error
        offset = 8
        compressed = bytearray()
        while offset + 12 <= len(raw):
            size, kind = struct.unpack(">I4s", raw[offset:offset+8])
            end = offset + 8 + size
            if end + 4 > len(raw) or zlib.crc32(raw[offset+4:end]) != int.from_bytes(raw[end:end+4], "big"):
                raise error
            if kind == b"IDAT":
                compressed.extend(raw[offset+8:end])
            if kind == b"IEND":
                if size or end+4 != len(raw):
                    raise error
                break
            offset = end + 4
        else:
            raise error
        stride = width * (4 if color == 6 else 3) + 1
        decoder = zlib.decompressobj()
        pixels = decoder.decompress(compressed, height * stride + 1)
        if (not decoder.eof or decoder.unused_data or len(pixels) != height * stride
                or any(line > 4 for line in pixels[::stride])):
            raise error
    except (ValueError, struct.error, zlib.error):
        raise error from None
    return value


@dataclass(frozen=True)
class Viewer:
    username: str
    display_name: str
    role: str
    avatar: str | None = None
    session_generation: int = 0

    @property
    def super_admin(self):
        return self.role == "super_admin"

    def public(self):
        result = {"username": self.username, "displayName": self.display_name, "role": self.role}
        if self.avatar:
            result["avatar"] = self.avatar
        return result


class AccountAuth:
    def __init__(self, directory, signals, accounts, url):
        self.directory = directory
        self.signals = signals
        self.accounts = accounts
        self.secure = url.startswith("https://")
        self.cookie_name = "__Host-bank_session" if self.secure else "bank_session"
        self.password_slots = BoundedSemaphore(1)
        self.dummy_hash = self.hash_password(token_urlsafe(32))

    def viewer(self, account):
        username = account["username"]
        role = "user" if account["passwordHash"] is not None else self.accounts.get(username, (None, "user"))[1]
        return Viewer(username, account["displayName"], role, account.get("avatar"), account["session_generation"])

    def derive(self, password, salt):
        if not self.password_slots.acquire(timeout=2):
            raise WorkspaceError("Повторите попытку через несколько секунд.", 429)
        try:
            return hashlib.scrypt(password.encode(), salt=salt, n=32768, r=8, p=3, maxmem=64 * 1024**2)
        finally:
            self.password_slots.release()

    def hash_password(self, password):
        salt = token_bytes(16)
        return f"{salt.hex()}:{self.derive(password, salt).hex()}"

    def login(self, payload):
        username, password = payload.get("username"), payload.get("password")
        if not isinstance(username, str) or not USERNAME.fullmatch(username) or (
            not isinstance(password, str) or not 1 <= len(password) <= 128
        ):
            raise WorkspaceError("Неверный логин или пароль.", 401)
        self.signals.limit("global", "login-total", 40, required=True)
        self.signals.limit(username, "login", 8, required=True)
        account = self.directory.get_account(username)
        configured = self.accounts.get(username)
        if configured:
            valid = hmac.compare_digest(configured[0], password.encode())
        else:
            stored = account and account["passwordHash"]
            salt, reference = (stored or self.dummy_hash).split(":")
            valid = hmac.compare_digest(self.derive(password, bytes.fromhex(salt)), bytes.fromhex(reference))
            valid = valid and bool(stored)
        if not account or not valid:
            raise WorkspaceError("Неверный логин или пароль.", 401)
        return self.viewer(account)

    def basic(self, authorization):
        if not authorization or len(authorization) > 2048:
            return None
        scheme, _, encoded = authorization.partition(" ")
        if scheme.lower() != "basic":
            return None
        try:
            raw = base64.b64decode(encoded, validate=True)
            user, separator, supplied = raw.partition(b":")
            username = user.decode("ascii")
        except (ValueError, binascii.Error):
            return None
        reference, role = self.accounts.get(username, (b"invalid-user", None))
        if separator and hmac.compare_digest(reference, supplied) and role:
            return self.viewer(self.directory.get_account(username))
        return None

    def cookie_token(self, header):
        if not header or len(header) > 4096:
            return None
        try:
            cookie = SimpleCookie(header).get(self.cookie_name)
        except CookieError:
            return None
        return cookie.value if cookie and TOKEN.fullmatch(cookie.value) else None

    @staticmethod
    def key(token):
        return "bank:session:" + hashlib.sha256(token.encode()).hexdigest()

    def session(self, header):
        token = self.cookie_token(header)
        if not token:
            return None
        try:
            value = self.signals.redis.get(self.key(token))
        except RedisError:
            raise WorkspaceError("Сессии временно недоступны.", 503) from None
        if not value:
            return None
        username, _, generation = value.decode().partition(":")
        account = self.directory.get_account(username)
        # Sessions issued before migration 026 contained only the username.
        if account and str(account["session_generation"]) == (generation or "0"):
            return self.viewer(account)
        return None

    def cookie(self, value, duration):
        secure = "; Secure" if self.secure else ""
        return f"{self.cookie_name}={value}; Max-Age={duration}; Path=/; HttpOnly; SameSite=Lax{secure}"

    def start(self, viewer, previous=None):
        token = token_urlsafe(32)
        old = self.cookie_token(previous)
        try:
            with self.signals.redis.pipeline() as pipe:
                if old:
                    pipe.delete(self.key(old))
                pipe.set(self.key(token), f"{viewer.username}:{viewer.session_generation}", ex=SESSION_TIME).execute()
        except RedisError:
            raise WorkspaceError("Сессии временно недоступны.", 503) from None
        return self.cookie(token, SESSION_TIME)

    def end(self, header):
        token = self.cookie_token(header)
        if token:
            try:
                self.signals.redis.delete(self.key(token))
            except RedisError:
                raise WorkspaceError("Сессии временно недоступны.", 503) from None
        return self.cookie("", 0)
