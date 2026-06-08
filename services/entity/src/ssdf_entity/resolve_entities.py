"""Resolve flow aggregates (+ segment-scoped ARP bindings) into Asset/Policy
entities and edges.

Pure function, deterministic. Asset identity is MAC when an ARP binding for the
flow's segment (firewall vantage) binds the IP→MAC, else a segment-local key
ip:<segment>:<ip>. Two IPs sharing a MAC collapse to one Asset; the same IP in
different segments never merges. Observed Policy is keyed (provider, rule_name).
"""

from __future__ import annotations

from .models import (
    ASSET, POLICY, COMMUNICATED_WITH, GOVERNED_BY, OBSERVED,
    entity_id, edge_id,
)


def normalize_segment(name: str | None) -> str:
    """Reduce a firewall vantage name to a comparable segment key.

    Takes the first dotted label, lowercased, so the flow-side ECS
    observer.hostname (often an FQDN) and the binding-side source_device
    (a short device name) agree. Empty/unknown collapses to 'unknown'.
    """
    label = (name or "").split(".")[0].strip().lower()
    return label or "unknown"


def build_binding_map(bindings: list[dict]) -> tuple[dict[tuple[str, str], str], set[tuple[str, str]]]:
    """Build {(segment, ip) -> mac} (latest observation wins) and the set of
    (segment, ip) keys claimed by >1 MAC (genuine same-segment IP conflicts)."""
    latest: dict[tuple[str, str], tuple[str, str]] = {}   # key -> (observed_at, mac)
    macs_seen: dict[tuple[str, str], set[str]] = {}
    for binding in bindings:
        segment = normalize_segment(binding.get("source_device"))
        ip = binding.get("ip") or ""
        mac = (binding.get("mac") or "").lower()
        if not ip or not mac:
            continue
        key = (segment, ip)
        macs_seen.setdefault(key, set()).add(mac)
        observed_at = binding.get("observed_at") or ""
        if key not in latest or observed_at > latest[key][0]:
            latest[key] = (observed_at, mac)
    binding_map = {key: value[1] for key, value in latest.items()}
    conflict = {key for key, macs in macs_seen.items() if len(macs) > 1}
    return binding_map, conflict



def _bump_window(record: dict, first_seen: str, last_seen: str) -> None:
    """Widen a record's [first_seen, last_seen] window (lexical ISO compare)."""
    record["first_seen"] = min(record["first_seen"], first_seen) if record["first_seen"] else first_seen
    record["last_seen"] = max(record["last_seen"], last_seen) if record["last_seen"] else last_seen


def _add_ip(entity: dict, ip: str) -> None:
    """Record an observed IP under ip / ip2 / ip3 … (deduped) so mapValues lookup matches any."""
    identifiers = entity["identifiers"]
    seen = {value for key, value in identifiers.items() if key.startswith("ip")}
    if ip in seen:
        return
    key = "ip" if "ip" not in identifiers else f"ip{len(seen) + 1}"
    identifiers[key] = ip


def _merge_set_attr(attrs: dict, key: str, values) -> None:
    """Maintain a comma-joined sorted set of string values in attrs[key]."""
    current = set(filter(None, attrs.get(key, "").split(",")))
    current.update(str(value) for value in values if str(value))
    attrs[key] = ",".join(sorted(current))


def resolve_entities(flow_aggregates: list[dict], bindings: list[dict],
                     tenant: str) -> tuple[list[dict], list[dict]]:
    binding_map, conflict = build_binding_map(bindings)
    entities: dict[str, dict] = {}
    edges: dict[str, dict] = {}

    def asset_for(ip: str, segment: str, first_seen: str, last_seen: str) -> dict:
        mac = binding_map.get((segment, ip))
        canonical = f"mac:{mac}" if mac else f"ip:{segment}:{ip}"
        eid = entity_id(tenant, ASSET, canonical)
        entity = entities.get(eid)
        if entity is None:
            entity = {
                "entity_id": eid, "tenant_id": tenant, "kind": ASSET,
                "name": mac or ip, "identifiers": {}, "source": OBSERVED,
                "identity_basis": "mac" if mac else "ip_only",
                "confidence": 1.0 if mac else 0.5,
                "attrs": {}, "first_seen": "", "last_seen": "",
            }
            if mac:
                entity["identifiers"]["mac"] = mac
            entities[eid] = entity
        _add_ip(entity, ip)
        if mac and (segment, ip) in conflict:
            entity["attrs"]["ip_conflict"] = ip
        _bump_window(entity, first_seen, last_seen)
        return entity

    def policy_for(provider: str, rule: str, first_seen: str, last_seen: str) -> dict:
        eid = entity_id(tenant, POLICY, f"{provider}:{rule}")
        entity = entities.get(eid)
        if entity is None:
            entity = {
                "entity_id": eid, "tenant_id": tenant, "kind": POLICY,
                "name": rule, "identifiers": {"rule": rule, "provider": provider},
                "source": OBSERVED, "identity_basis": "", "confidence": 1.0,
                "attrs": {"provider": provider}, "first_seen": "", "last_seen": "",
            }
            entities[eid] = entity
        _bump_window(entity, first_seen, last_seen)
        return entity

    for row in flow_aggregates:
        first_seen, last_seen = row["first_seen"], row["last_seen"]
        segment = normalize_segment(row.get("observer_hostname"))
        src = asset_for(row["src_ip"], segment, first_seen, last_seen)
        dst = asset_for(row["dst_ip"], segment, first_seen, last_seen)

        src_ip, dst_ip = row["src_ip"], row["dst_ip"]
        comm_eid = edge_id(tenant, f"ip:{src_ip}", f"ip:{dst_ip}",
                           COMMUNICATED_WITH, OBSERVED)
        comm = edges.get(comm_eid)
        if comm is None:
            comm = {
                "edge_id": comm_eid, "tenant_id": tenant,
                "src_id": src["entity_id"], "dst_id": dst["entity_id"],
                "edge_type": COMMUNICATED_WITH, "source": OBSERVED, "confidence": 1.0,
                "attrs": {"sessions": "0", "bytes": "0", "ports": "", "providers": "",
                          "transports": "", "observer_hosts": ""},
                "first_seen": "", "last_seen": "",
            }
            edges[comm_eid] = comm
        comm["attrs"]["sessions"] = str(int(comm["attrs"]["sessions"]) + int(row.get("flows", 0)))
        comm["attrs"]["bytes"] = str(int(comm["attrs"]["bytes"]) + int(row.get("bytes", 0)))
        _merge_set_attr(comm["attrs"], "ports", row.get("ports") or [])
        _merge_set_attr(comm["attrs"], "providers", [row.get("provider", "")])
        _merge_set_attr(comm["attrs"], "transports", [row.get("transport", "")])
        observer = row.get("observer_hostname")
        _merge_set_attr(comm["attrs"], "observer_hosts", [observer] if observer else [])
        _bump_window(comm, first_seen, last_seen)

        rule = (row.get("rule_name") or "").strip()
        provider = (row.get("provider") or "").strip()
        if not rule:
            continue
        policy = policy_for(provider, rule, first_seen, last_seen)
        gov_eid = edge_id(tenant, comm_eid, policy["entity_id"], GOVERNED_BY, OBSERVED)
        gov = edges.get(gov_eid)
        if gov is None:
            gov = {
                "edge_id": gov_eid, "tenant_id": tenant,
                "src_id": comm_eid, "dst_id": policy["entity_id"],
                "edge_type": GOVERNED_BY, "source": OBSERVED, "confidence": 1.0,
                "attrs": {"rule": rule, "provider": provider},
                "first_seen": "", "last_seen": "",
            }
            edges[gov_eid] = gov
        _bump_window(gov, first_seen, last_seen)

    return list(entities.values()), list(edges.values())
