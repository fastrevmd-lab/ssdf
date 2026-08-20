"""Entity/correlation taxonomy constants and deterministic id hashing.

Mirrors services/topo/src/ssdf_topo/models.py but for the semantic entity layer:
the id namespace is separate so entity ids never collide with topology node ids.
"""

from __future__ import annotations

import hashlib

# --- entity kinds ---
ASSET = "asset"
POLICY = "policy"
IDENTITY = "identity"  # seam only in M6a (populated when an IDaaS source lands)
ENTITY_KINDS = {ASSET, POLICY, IDENTITY}

# --- edge types ---
COMMUNICATED_WITH = "communicated_with"
GOVERNED_BY = "governed_by"
AUTHENTICATED_AS = "authenticated_as"  # seam only in M6a
EDGE_TYPES = {COMMUNICATED_WITH, GOVERNED_BY, AUTHENTICATED_AS}

# --- provenance ---
OBSERVED = "observed"
CONFIGURED = "configured"  # reserved; populated in M6b


def _hash16(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()[:16]


def entity_id(tenant: str, kind: str, canonical_key: str) -> str:
    """Stable 16-hex id for an entity, namespaced by tenant + kind + 'entity'."""
    return _hash16(f"{tenant}|entity|{kind}|{canonical_key}")


def edge_id(tenant: str, src_id: str, dst_id: str, edge_type: str, source: str) -> str:
    """Stable 16-hex id for a directed, typed, provenance-tagged entity edge."""
    return _hash16(f"{tenant}|entity_edge|{src_id}|{dst_id}|{edge_type}|{source}")
