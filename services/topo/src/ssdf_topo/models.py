# src/ssdf_topo/models.py
"""Topology graph value types, taxonomy constants, and deterministic id hashing."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

# --- node kinds ---
DEVICE = "device"
INTERFACE = "interface"
HOST = "host"
IDENTITY = "identity"
SEGMENT = "segment"
ZONE = "zone"
RULE = "rule"
NODE_KINDS = {DEVICE, INTERFACE, HOST, IDENTITY, SEGMENT, ZONE, RULE}

# --- edge types ---
PHYSICAL_LINK = "physical_link"
ATTACHES_TO = "attaches_to"
HAS_ADDRESS = "has_address"
MEMBER_OF = "member_of"
ROUTES_TO = "routes_to"
TUNNEL = "tunnel"
HOSTS = "hosts"
TALKED_TO = "talked_to"
GOVERNED_BY = "governed_by"
IN_ZONE = "in_zone"
AUTHENTICATED_AS = "authenticated_as"
EDGE_TYPES = {
    PHYSICAL_LINK,
    ATTACHES_TO,
    HAS_ADDRESS,
    MEMBER_OF,
    ROUTES_TO,
    TUNNEL,
    HOSTS,
    TALKED_TO,
    GOVERNED_BY,
    IN_ZONE,
    AUTHENTICATED_AS,
}

LAYERS = {"l1", "l2", "l3", "virt", "flow"}


@dataclass(frozen=True)
class Observation:
    """One normalized fact a collector observed about the topology."""

    observed_at: str  # ISO-8601 UTC, e.g. "2026-06-07T12:00:00+00:00"
    collector: str
    source_device: str
    layer: str
    observation_type: str
    subj_kind: str
    subj_id: str
    obj_kind: str = ""
    obj_id: str = ""
    attrs: dict[str, str] = field(default_factory=dict)
    raw: str = ""
    tenant_id: str = "t_main"


def _hash16(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()[:16]


def node_id(tenant: str, kind: str, canonical_key: str) -> str:
    """Stable 16-hex id for a node, namespaced by tenant + kind."""
    return _hash16(f"{tenant}|{kind}|{canonical_key}")


def edge_id(tenant: str, src_id: str, dst_id: str, edge_type: str, layer: str) -> str:
    """Stable 16-hex id for a directed, typed, layered edge."""
    return _hash16(f"{tenant}|{src_id}|{dst_id}|{edge_type}|{layer}")
