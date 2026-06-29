from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any


def canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(data: Any) -> str:
    encoded = canonical_json(data).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def merkle_root(items: list[str]) -> str:
    if not items:
        return digest([])
    level = sorted(items)
    while len(level) > 1:
        nxt: list[str] = []
        for idx in range(0, len(level), 2):
            left = level[idx]
            right = level[idx + 1] if idx + 1 < len(level) else left
            nxt.append(digest({"left": left, "right": right}))
        level = nxt
    return level[0]


class HMACSigner:
    """Deterministic signer used for experiment-grade receipt verification."""

    def __init__(self, key: str):
        self.key = key.encode("utf-8")

    def sign(self, payload: Any) -> str:
        msg = canonical_json(payload).encode("utf-8")
        return hmac.new(self.key, msg, hashlib.sha256).hexdigest()

    def verify(self, payload: Any, signature: str) -> bool:
        expected = self.sign(payload)
        return hmac.compare_digest(expected, signature)
