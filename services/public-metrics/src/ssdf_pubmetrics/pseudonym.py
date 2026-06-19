"""Keyed, consistent, irreversible surrogates for de-identification.

HMAC-SHA256 over ``kind:real_value`` keyed by the sovereign PUBLIC_PSEUDONYM_KEY.
Same key+kind+value always yields the same surrogate (series continuity); the hash
is one-way and the public side cannot recompute it without the key.
"""

from __future__ import annotations

import hashlib
import hmac

PREFIXES: dict[str, str] = {
    "host": "h_",
    "firewall": "fw_",
    "segment": "seg_",
    "port": "p_",
    "vmid": "vm_",
}

_BASE_LENGTH = 10  # hex chars of digest after the prefix


def surrogate(key: bytes, kind: str, real_value: str, length: int = _BASE_LENGTH) -> str:
    """Return the per-kind-prefixed keyed surrogate for ``real_value``."""
    if kind not in PREFIXES:
        raise ValueError(f"unknown pseudonym kind: {kind}")
    message = f"{kind}:{real_value}".encode("utf-8")
    digest = hmac.new(key, message, hashlib.sha256).hexdigest()
    return PREFIXES[kind] + digest[:length]


def mint_surrogate(existing: dict[tuple[str, str], str], key: bytes, kind: str,
                   real_value: str, base_length: int = _BASE_LENGTH) -> str:
    """Return the authoritative surrogate, reusing the map and lengthening on collision.

    ``existing`` maps ``(kind, real_value) -> surrogate`` (the current pseudonym_map).
    Reuse a prior surrogate verbatim. Otherwise mint at ``base_length``; if that
    surrogate is already bound to a DIFFERENT real_value, lengthen the hex slice until
    it no longer collides. The map remains authoritative.
    """
    prior = existing.get((kind, real_value))
    if prior is not None:
        return prior
    taken = {sur: rv for (k, rv), sur in existing.items() if k == kind}
    length = base_length
    while True:
        candidate = surrogate(key, kind, real_value, length=length)
        collides_with = taken.get(candidate)
        if collides_with is None or collides_with == real_value:
            return candidate
        length += 2
