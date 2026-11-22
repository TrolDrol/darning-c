"""Reuse a scanner response only within the graph execution that requested it."""
from collections import OrderedDict
from collections.abc import Callable
from hashlib import sha256


class ScanCache:
    """Keep bounded immutable responses. Callers decode JSON independently on every read."""

    def __init__(self, *, max_bytes: int = 8_000_000, max_entries: int = 16):
        self._responses: OrderedDict[bytes, bytes] = OrderedDict()
        self._size = 0
        self._max_bytes = max_bytes
        self._max_entries = max_entries

    def run(self, request: bytes, invoke: Callable[[], bytes], *, settings: bytes = b"") -> bytes:
        """Use the exact worker request and any separately serialized node settings."""
        digest = sha256(len(request).to_bytes(8, "big"))
        digest.update(request)
        digest.update(settings)
        key = digest.digest()
        if key in self._responses:
            self._responses.move_to_end(key)
            return self._responses[key]

        response = bytes(invoke())
        if self._max_entries <= 0 or len(response) > self._max_bytes:
            return response
        while len(self._responses) >= self._max_entries or self._size + len(response) > self._max_bytes:
            _, evicted = self._responses.popitem(last=False)
            self._size -= len(evicted)
        self._responses[key] = response
        self._size += len(response)
        return response
