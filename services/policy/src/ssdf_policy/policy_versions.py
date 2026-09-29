"""Append-only rule-content history (MEC-566). Pure diff, no I/O.

ssdf.entities (004_entities.sql) is a ReplacingMergeTree snapshot of CURRENT
policy state only -- resolve_policies.py's own docstring says there is no
rule-version history. This module decides, deterministically and without
touching ClickHouse, which policy entities from a fresh collection pass
represent a genuine content change and therefore need a new
ssdf.policy_versions row; the caller (chwriter.py) does the actual read of
last-known hashes and the INSERT.
"""

from __future__ import annotations

import hashlib
import json

from .models import POLICY

# The rule fields whose change actually matters for history purposes. Deliberately
# excludes source/dest addresses, application and service: those churn far more
# often (address-book membership, app-id updates) and would turn "what changed"
# into noise dominated by list contents rather than rule intent (action/zones/
# enabled/position). Revisit if rule_history needs finer granularity.
VERSION_ATTRS = ("action", "from_zone", "to_zone", "enabled", "position")


def content_hash(policy_entity: dict) -> str:
    """Stable hash over the version-relevant attrs of one policy entity."""
    attrs = policy_entity["attrs"]
    payload = json.dumps({k: attrs.get(k, "") for k in VERSION_ATTRS}, sort_keys=True)
    return hashlib.sha1(payload.encode("utf-8")).hexdigest()


def version_key(policy_entity: dict) -> tuple[str, str, str]:
    """(provider, device_name, rule_name): the natural key rule_history/rule_usage key on."""
    attrs = policy_entity["attrs"]
    return (attrs["provider"], attrs["device_name"], policy_entity["name"])


def diff_new_versions(policy_entities: list[dict], last_hash_by_key: dict) -> list[dict]:
    """Return one append-row per policy entity whose content hash changed (or is new).

    ``last_hash_by_key`` maps ``version_key(entity) -> content_hash`` from the
    latest known ssdf.policy_versions row for that rule, or is missing the key
    entirely for a rule never seen before (also produces a new row: the rule's
    first version).
    """
    versions: list[dict] = []
    for policy in policy_entities:
        if policy.get("kind") != POLICY:
            continue
        key = version_key(policy)
        new_hash = content_hash(policy)
        if last_hash_by_key.get(key) == new_hash:
            continue
        attrs = policy["attrs"]
        versions.append(
            {
                "tenant_id": policy["tenant_id"],
                "provider": attrs["provider"],
                "device_name": attrs["device_name"],
                "rule_name": policy["name"],
                "valid_from": policy["last_seen"],
                "content_hash": new_hash,
                "action": attrs.get("action", ""),
                "from_zone": attrs.get("from_zone", ""),
                "to_zone": attrs.get("to_zone", ""),
                "enabled": attrs.get("enabled", "") == "true",
                "position": attrs.get("position", ""),
            }
        )
    return versions
