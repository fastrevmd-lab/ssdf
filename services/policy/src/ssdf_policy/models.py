"""Entity taxonomy + deterministic id hashing for the configured-policy layer.

The id functions are BYTE-IDENTICAL to services/entity/src/ssdf_entity/models.py so
configured entities/edges share one id namespace with the M6a observed entities.
"""

from __future__ import annotations

import hashlib

# --- entity kinds ---
ASSET = "asset"
POLICY = "policy"
FIREWALL = "firewall"   # NEW in M6b: a device whose configured ruleset we ingest

# --- edge types ---
GOVERNED_BY = "governed_by"

# --- provenance ---
OBSERVED = "observed"
CONFIGURED = "configured"


def _hash16(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()[:16]


def entity_id(tenant: str, kind: str, canonical_key: str) -> str:
    """Stable 16-hex id for an entity, namespaced by tenant + kind + 'entity'."""
    return _hash16(f"{tenant}|entity|{kind}|{canonical_key}")


def edge_id(tenant: str, src_id: str, dst_id: str, edge_type: str, source: str) -> str:
    """Stable 16-hex id for a directed, typed, provenance-tagged entity edge."""
    return _hash16(f"{tenant}|entity_edge|{src_id}|{dst_id}|{edge_type}|{source}")
