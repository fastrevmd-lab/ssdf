"""lab_topology_snapshot: a deliberately narrow, de-identified topology projection.

The example.com living-topology hero needs to draw the lab without learning
anything about it. `topology_snapshot` cannot serve that: it returns real node
names, identifiers, attributes and edge metadata.

This builds a projection that is safe to publish by construction rather than by
redaction. It emits ONLY booleans, an enum, and snapshot-local opaque ids — there
is no field in the output that could carry a name, address or timestamp, so a
future change cannot accidentally widen it. Anything not explicitly allowlisted is
absent, so a newly discovered device is invisible until an operator adds it.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import secrets
from dataclasses import dataclass

# Points at an operator-local, uncommitted JSON file mapping a committed placeholder
# selector (e.g. "ap-1") to the real graph node name on this deployment. Lets an
# operator whose devices are named after rooms, people, or anything else identifying
# publish without ever committing that name to a public repo.
_OVERRIDE_ENV_VAR = "SSDF_PUBLIC_SNAPSHOT_NAME_OVERRIDES"

SCHEMA_VERSION = 1

# Bounded output: the consumer is a static web page, and an unbounded graph would
# be both a rendering problem and a bigger disclosure surface than intended.
MAX_NODES = 64
MAX_EDGES = 256


@dataclass(frozen=True)
class DisplayDevice:
    """One device an operator has explicitly cleared for public display.

    `name` matches the graph node and is NEVER emitted — it is the selector only.
    `site` and `ollama` are operator-declared: SSDF has no signal for either, and
    inventing one would be worse than declaring it.
    """

    name: str
    site: str  # "primary" | "remote"
    ollama: bool = False


# Adding a device here makes it publicly visible. That is the entire point of the
# list being explicit and in code: it gets a diff and a reviewer.
#
# Names here are committed and therefore public — keep them generic (role-based,
# not room- or person-based). An operator whose actual graph nodes are named
# differently (e.g. after a room) points SSDF_PUBLIC_SNAPSHOT_NAME_OVERRIDES at an
# uncommitted local file to remap a placeholder selector to the real node name; see
# _resolve_allowlist below.
_ALLOWLIST_DEFAULTS: tuple[DisplayDevice, ...] = (
    DisplayDevice("vsrx-prod", "primary"),
    DisplayDevice("vsrx-ci", "primary"),
    DisplayDevice("panosvm", "primary"),
    DisplayDevice("Gateway Max", "primary"),
    # pve2 hosts the gbrain guests, which run local Ollama inference.
    DisplayDevice("pve2", "primary", ollama=True),
    DisplayDevice("pve3", "primary"),
    DisplayDevice("USW Pro HD 24 PoE", "primary"),
    DisplayDevice("USW Pro XG 8 PoE", "primary"),
    DisplayDevice("USW Flex 2.5G 8", "primary"),
    DisplayDevice("USP RPS", "primary"),
    DisplayDevice("ap-1", "primary"),
    DisplayDevice("ap-2", "primary"),
    DisplayDevice("ap-3", "primary"),
    DisplayDevice("ap-4", "primary"),
)


def _resolve_allowlist(
    defaults: tuple[DisplayDevice, ...] = _ALLOWLIST_DEFAULTS,
) -> tuple[DisplayDevice, ...]:
    """Rename allowlist selectors to match this deployment's real graph node names.

    The override file (JSON object of placeholder -> real name) is read from disk
    at import time, never committed, and entirely optional: with no env var set,
    the committed generic placeholders are used as-is and match nothing on a real
    graph until an operator opts in.
    """
    override_path = os.environ.get(_OVERRIDE_ENV_VAR)
    if not override_path:
        return defaults
    with open(override_path, encoding="utf-8") as f:
        overrides: dict[str, str] = json.load(f)
    return tuple(DisplayDevice(overrides.get(d.name, d.name), d.site, d.ollama) for d in defaults)


ALLOWLIST: tuple[DisplayDevice, ...] = _resolve_allowlist()

_BY_NAME = {d.name: d for d in ALLOWLIST}


def _within(last_seen: str, now: _dt.datetime, hours: float) -> bool:
    """True if `last_seen` falls inside the window ending at `now`."""
    if not last_seen:
        return False
    try:
        seen = _dt.datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
    except ValueError:
        return False
    if seen.tzinfo is None:
        seen = seen.replace(tzinfo=_dt.timezone.utc)
    return (now - seen).total_seconds() <= hours * 3600.0


def build_snapshot(
    nodes: list[dict],
    edges: list[dict],
    *,
    now: _dt.datetime,
    salt: str,
    reachable_within_hours: float = 1.0,
    activity_within_hours: float = 24.0,
) -> dict:
    """Project allowlisted devices and the edges between them into public shape.

    Opaque ids are ordered by a salted digest rather than by name, so the ordering
    itself carries no information about which node is which. The salt is fresh per
    snapshot, so two snapshots cannot be correlated node-for-node even before the
    downstream publisher does its own remapping.
    """
    # One entry per allowlisted device, keeping the freshest row. graph_nodes keys
    # on node_id, so a device that changed identity leaves its previous row behind
    # until TTL expires it; both rows carry the same name, and emitting both would
    # over-report the lab (observed live as 17 nodes for 14 allowlisted devices).
    freshest: dict[str, dict] = {}
    for n in nodes:
        if n.get("kind") != "device" or n.get("name") not in _BY_NAME:
            continue
        current = freshest.get(n["name"])
        if current is None or n.get("last_seen", "") > current.get("last_seen", ""):
            freshest[n["name"]] = n
    selected = list(freshest.values())
    ordered = sorted(
        selected, key=lambda n: hashlib.sha256((salt + n["name"]).encode()).hexdigest()
    )

    nodes_truncated = len(ordered) > MAX_NODES
    ordered = ordered[:MAX_NODES]

    opaque: dict[str, str] = {}
    out_nodes = []
    for index, node in enumerate(ordered, start=1):
        display = _BY_NAME[node["name"]]
        oid = f"n{index}"
        opaque[node["node_id"]] = oid
        out_nodes.append(
            {
                "id": oid,
                "reachable": _within(node.get("last_seen", ""), now, reachable_within_hours),
                "ollama": display.ollama,
                "site": display.site,
            }
        )

    out_edges = []
    seen_pairs: set[tuple[str, str]] = set()
    edges_truncated = False
    for edge in edges:
        src, dst = opaque.get(edge.get("src_id", "")), opaque.get(edge.get("dst_id", ""))
        # An edge is emitted only when BOTH endpoints are returned nodes, so an
        # endpoint can never reference something the consumer cannot see.
        if not src or not dst or src == dst:
            continue
        pair = tuple(sorted((src, dst)))
        if pair in seen_pairs:
            continue
        if len(out_edges) >= MAX_EDGES:
            edges_truncated = True
            break
        seen_pairs.add(pair)
        a = _BY_NAME[_name_for(ordered, edge["src_id"])]
        b = _BY_NAME[_name_for(ordered, edge["dst_id"])]
        out_edges.append(
            {
                "source": src,
                "target": dst,
                "remote": a.site == "remote" or b.site == "remote",
                # A boolean, never the window, the timestamp, or a count.
                "recent_activity": _within(edge.get("last_seen", ""), now, activity_within_hours),
            }
        )

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": now.isoformat(timespec="milliseconds"),
        "nodes": out_nodes,
        "edges": out_edges,
        "node_count": len(out_nodes),
        "edge_count": len(out_edges),
        # Truncation is reported rather than silently emitting a partial graph.
        "truncated": nodes_truncated or edges_truncated,
    }


def _name_for(ordered: list[dict], node_id: str) -> str:
    for n in ordered:
        if n["node_id"] == node_id:
            return n["name"]
    raise KeyError(node_id)


class PublicSnapshotTools:
    """Sovereign tool producing the publishable projection."""

    def __init__(self, graph_store, activity_within_hours: float = 24.0):
        self._graph = graph_store
        self._activity = activity_within_hours

    def lab_topology_snapshot(self) -> dict:
        """Build the snapshot from current graph state."""
        now = _dt.datetime.now(_dt.timezone.utc)
        since = (now - _dt.timedelta(hours=self._activity)).isoformat(timespec="milliseconds")
        # Nodes come from current-state inventory, NOT the edge-derived subgraph:
        # an isolated device (no edges) is still part of the lab and must appear.
        nodes = self._graph.nodes_by_attr(kind="device")
        _subgraph_nodes, edges = self._graph.load_subgraph(since)
        return build_snapshot(
            nodes,
            edges,
            now=now,
            salt=secrets.token_hex(16),
            activity_within_hours=self._activity,
        )
