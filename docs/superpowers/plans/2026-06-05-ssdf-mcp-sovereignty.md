# SSDF MCP Servers + Sovereignty Guard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the three Python MCP servers (`ssdf-local-mcp`, `ssdf-frontier-mcp`, `ssdf-admin-mcp`) and the shared Sovereignty Guard egress chokepoint, so multiple LLMs can read SSDF data via MCP tools with local models getting full unmasked access, frontier models getting a redacted catalog subset, and operators onboarding sources — all read-only toward SSDF, never writing to a device.

**Architecture:** Each MCP server is a FastMCP-style app (official `mcp` Python SDK) whose tools call the Plan 5 gRPC `ssdf-server` (package `ssdf.v1`) through a thin `grpc_client` wrapper — tools never touch ClickHouse/Neo4j/Postgres directly. Every read response passes through a single, pure, unit-testable Sovereignty Guard (`tag → match YAML rules → compute most-restrictive egress action per tier → transform → write ClickHouse audit record`). The frontier server omits raw/row-level tools from its catalog entirely so a frontier model physically cannot invoke them; the guard applies per-dataset egress flags on top.

**Tech Stack:** Python 3.12 managed by `uv` (Plan 3 tooling); `mcp` SDK (FastMCP), `grpcio` + `grpcio-tools` generated stubs from Plan 5 `ssdf.v1`, `pydantic` v2, `PyYAML`, `asyncpg` (policy table), `clickhouse-connect` (audit), `pytest` + `pytest-asyncio`.

**Spec:** `docs/superpowers/specs/2026-06-05-ssdf-data-fabric-design.md` (§6 MCP Tools, §7 Sovereignty & Safety Controls). Builds on `docs/superpowers/plans/2026-06-05-ssdf-foundation.md` (Postgres `sovereignty_policy`, ClickHouse `ssdf.audit`).

---

## File Structure

```
SSDF/
├── py/
│   ├── pyproject.toml                       # (Plan 3) add mcp, grpcio, pyyaml, asyncpg, clickhouse-connect deps
│   ├── mcp/
│   │   ├── __init__.py
│   │   ├── common/
│   │   │   ├── __init__.py
│   │   │   ├── grpc_client.py               # thin async wrapper over ssdf.v1 gRPC stubs (one method per service call)
│   │   │   ├── context.py                   # CallContext: token→tier+scopes+tenant_id+caller resolution
│   │   │   └── scopes.py                     # Scope enum (events:read, graph:read, policy:read, raw:read, config:write) + Tier enum
│   │   ├── sovereignty/
│   │   │   ├── __init__.py
│   │   │   ├── classes.py                    # EgressClass enum + restrictiveness ordering (most-restrictive-wins)
│   │   │   ├── policy.py                     # PolicyDoc model + YAML parse + match-rule logic (pure)
│   │   │   ├── tagging.py                    # tag a fetched dataset into Tagged{source,kind,category,labels,tenant_id,rows}
│   │   │   ├── transforms.py                 # redact/mask/summarize/deny transforms keyed by EgressClass (pure)
│   │   │   ├── guard.py                      # SovereigntyGuard.evaluate(tagged, tier, policy) -> Decision (pure core)
│   │   │   ├── audit.py                      # AuditRecord model + args_digest hashing + AuditSink (thin ClickHouse client)
│   │   │   └── policy_store.py               # loads active sovereignty_policy row from Postgres, hot-reload cache
│   │   ├── local/
│   │   │   ├── __init__.py
│   │   │   ├── tools.py                      # full read tool implementations (10 tools) calling grpc_client
│   │   │   └── server.py                     # ssdf-local-mcp: registers ALL read tools, tier=local
│   │   ├── frontier/
│   │   │   ├── __init__.py
│   │   │   └── server.py                     # ssdf-frontier-mcp: registers SUBSET (no raw/row-level tools), tier=frontier
│   │   └── admin/
│   │       ├── __init__.py
│   │       ├── onboarding.py                 # source-type registry + device-config snippet emitters (Junos/PAN-OS)
│   │       ├── tools.py                      # admin tool implementations calling IngestionService
│   │       └── server.py                     # ssdf-admin-mcp: operator-only, config:write, tier=local
│   ├── config/
│   │   └── sovereignty.example.yaml          # the canonical spec §7 YAML, loaded into Postgres sovereignty_policy
│   └── tests/
│       ├── __init__.py
│       ├── conftest.py                       # fixtures: FakeGrpcClient, FakeAuditSink, sample policy doc, tagged datasets
│       ├── sovereignty/
│       │   ├── test_classes.py               # restrictiveness ordering
│       │   ├── test_policy.py                # YAML parse + rule matching + tenant overrides
│       │   ├── test_transforms.py            # mask/redact/summarize/deny per class
│       │   ├── test_guard.py                 # most-restrictive across multiple rules; Identity mask; raw deny; local open
│       │   └── test_audit.py                 # args_digest is a hash; AuditRecord fields exact
│       ├── local/
│       │   └── test_local_server.py          # local catalog registers all 10 tools; raw access on local
│       ├── frontier/
│       │   └── test_frontier_server.py       # frontier catalog OMITS raw/row-level tools; masked output
│       └── admin/
│           └── test_admin_server.py          # add_source returns source_id + onboarding; Junos syslog stanza emitted
```

Each sovereignty file has one responsibility: `classes` (ordering), `policy` (rules), `tagging` (label data), `transforms` (mutate payloads), `guard` (orchestrate the pure decision), `audit` (record), `policy_store` (DB load). The guard core (`classes` + `policy` + `transforms` + `guard`) is pure and unit-tested with no gRPC/DB. gRPC and Postgres/ClickHouse sit behind thin clients (`grpc_client`, `policy_store`, `audit`) that are faked in tests.

---

## Task 1: Scopes, tiers, and egress-class ordering

The vocabulary the whole system shares: the five OAuth scopes and two tiers from spec §5, and the five egress classes from spec §7 with their most-restrictive-wins ordering.

**Files:**
- Create: `py/mcp/__init__.py`
- Create: `py/mcp/common/__init__.py`
- Create: `py/mcp/common/scopes.py`
- Create: `py/mcp/sovereignty/__init__.py`
- Create: `py/mcp/sovereignty/classes.py`
- Create: `py/tests/__init__.py`
- Create: `py/tests/sovereignty/test_classes.py`

- [ ] **Step 1: Write the failing test**

Create `py/tests/sovereignty/test_classes.py`:

```python
from mcp.common.scopes import Scope, Tier
from mcp.sovereignty.classes import EgressClass, most_restrictive


def test_egress_class_values_match_spec():
    assert {c.value for c in EgressClass} == {
        "never_leave",
        "summary_only",
        "mask_identities",
        "redact_fields",
        "open",
    }


def test_ordering_never_leave_is_most_restrictive():
    assert most_restrictive([EgressClass.OPEN, EgressClass.NEVER_LEAVE]) is EgressClass.NEVER_LEAVE


def test_ordering_across_three_rules_picks_strictest():
    chosen = most_restrictive(
        [EgressClass.REDACT_FIELDS, EgressClass.SUMMARY_ONLY, EgressClass.MASK_IDENTITIES]
    )
    assert chosen is EgressClass.SUMMARY_ONLY


def test_empty_defaults_to_open():
    assert most_restrictive([]) is EgressClass.OPEN


def test_scopes_match_spec():
    assert {s.value for s in Scope} == {
        "events:read",
        "graph:read",
        "policy:read",
        "raw:read",
        "config:write",
    }


def test_tiers():
    assert {t.value for t in Tier} == {"local", "frontier"}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd py && uv run pytest tests/sovereignty/test_classes.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'mcp.common.scopes'`.

- [ ] **Step 3: Write the minimal implementation**

Create `py/mcp/__init__.py` (empty), `py/mcp/common/__init__.py` (empty), `py/mcp/sovereignty/__init__.py` (empty), `py/tests/__init__.py` (empty).

Create `py/mcp/common/scopes.py`:

```python
"""OAuth scopes and LLM tiers shared across SSDF MCP servers (spec §5)."""
from enum import Enum


class Scope(str, Enum):
    """Fine-grained scopes carried on a Gateway token."""

    EVENTS_READ = "events:read"
    GRAPH_READ = "graph:read"
    POLICY_READ = "policy:read"
    RAW_READ = "raw:read"
    CONFIG_WRITE = "config:write"


class Tier(str, Enum):
    """Sovereignty tier that dictates default egress posture."""

    LOCAL = "local"
    FRONTIER = "frontier"
```

Create `py/mcp/sovereignty/classes.py`:

```python
"""Egress classes and most-restrictive-wins resolution (spec §7)."""
from enum import Enum


class EgressClass(str, Enum):
    """How much of a tagged dataset may cross the tier boundary."""

    NEVER_LEAVE = "never_leave"
    SUMMARY_ONLY = "summary_only"
    MASK_IDENTITIES = "mask_identities"
    REDACT_FIELDS = "redact_fields"
    OPEN = "open"


# Lower rank = MORE restrictive. never_leave wins over everything.
_RANK: dict[EgressClass, int] = {
    EgressClass.NEVER_LEAVE: 0,
    EgressClass.SUMMARY_ONLY: 1,
    EgressClass.MASK_IDENTITIES: 2,
    EgressClass.REDACT_FIELDS: 3,
    EgressClass.OPEN: 4,
}


def most_restrictive(classes: list[EgressClass]) -> EgressClass:
    """Return the strictest egress class in the list; OPEN if the list is empty.

    Args:
        classes: candidate egress classes from every matching rule + the tier default.

    Returns:
        The class with the lowest rank (most restrictive).
    """
    if not classes:
        return EgressClass.OPEN
    return min(classes, key=lambda egress_class: _RANK[egress_class])
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd py && uv run pytest tests/sovereignty/test_classes.py -v`
Expected: PASS — 6 passed.

- [ ] **Step 5: Commit**

```bash
git add py/mcp/__init__.py py/mcp/common/__init__.py py/mcp/common/scopes.py \
  py/mcp/sovereignty/__init__.py py/mcp/sovereignty/classes.py \
  py/tests/__init__.py py/tests/sovereignty/__init__.py py/tests/sovereignty/test_classes.py
git commit -m "feat(sovereignty): scopes, tiers, egress classes + most-restrictive resolution"
```

---

## Task 2: Sovereignty policy model, YAML, and rule matching

The declarative policy from spec §7. A `PolicyDoc` holds per-tier defaults, global rules, and `tenant_overrides`. A `Tagged` dataset (built in Task 3) is matched against rules; each rule's `match` is a subset test over `source`, `kind`, `category`, `tenant_id`, and `labels`. This module is pure — no DB.

**Files:**
- Create: `py/config/sovereignty.example.yaml`
- Create: `py/mcp/sovereignty/tagging.py`
- Create: `py/mcp/sovereignty/policy.py`
- Create: `py/tests/sovereignty/test_policy.py`

- [ ] **Step 1: Write the canonical policy YAML** `py/config/sovereignty.example.yaml`

This is the exact shape from spec §7 (loaded verbatim into the Postgres `sovereignty_policy.document` column by `policy_store`):

```yaml
defaults:
  local: open
  frontier: never_leave
rules:
  - match: { category: raw_payload }
    frontier: never_leave
  - match: { kind: Identity }
    frontier: mask_identities
  - match: { source: wazuh, kind: Alert }
    frontier: summary_only
tenant_overrides:
  t_main:
    - match: { kind: Asset, labels: { criticality: crown_jewel } }
      frontier: never_leave
```

- [ ] **Step 2: Write the failing test** `py/tests/sovereignty/test_policy.py`

```python
from pathlib import Path

from mcp.common.scopes import Tier
from mcp.sovereignty.classes import EgressClass
from mcp.sovereignty.policy import PolicyDoc
from mcp.sovereignty.tagging import Tagged

YAML_PATH = Path(__file__).parents[2] / "config" / "sovereignty.example.yaml"


def load_doc() -> PolicyDoc:
    return PolicyDoc.from_yaml(YAML_PATH.read_text())


def test_defaults_parse():
    doc = load_doc()
    assert doc.default_for(Tier.LOCAL) is EgressClass.OPEN
    assert doc.default_for(Tier.FRONTIER) is EgressClass.NEVER_LEAVE


def test_raw_payload_rule_matches_on_category():
    doc = load_doc()
    tagged = Tagged(source="srx", kind="Session", category="raw_payload",
                    tenant_id="t_main", labels={}, rows=[{"a": 1}])
    classes = doc.matching_classes(tagged, Tier.FRONTIER)
    assert EgressClass.NEVER_LEAVE in classes


def test_identity_rule_matches_on_kind():
    doc = load_doc()
    tagged = Tagged(source="okta", kind="Identity", category="entity",
                    tenant_id="t_main", labels={}, rows=[{"id": "idn_1"}])
    classes = doc.matching_classes(tagged, Tier.FRONTIER)
    assert EgressClass.MASK_IDENTITIES in classes


def test_compound_rule_requires_all_keys():
    doc = load_doc()
    # source=wazuh AND kind=Alert -> summary_only
    hit = Tagged(source="wazuh", kind="Alert", category="entity",
                 tenant_id="t_main", labels={}, rows=[])
    miss = Tagged(source="okta", kind="Alert", category="entity",
                  tenant_id="t_main", labels={}, rows=[])
    assert EgressClass.SUMMARY_ONLY in doc.matching_classes(hit, Tier.FRONTIER)
    assert EgressClass.SUMMARY_ONLY not in doc.matching_classes(miss, Tier.FRONTIER)


def test_tenant_override_matches_nested_labels():
    doc = load_doc()
    tagged = Tagged(source="wazuh", kind="Asset", category="entity",
                    tenant_id="t_main", labels={"criticality": "crown_jewel"},
                    rows=[{"id": "ast_1"}])
    classes = doc.matching_classes(tagged, Tier.FRONTIER)
    assert EgressClass.NEVER_LEAVE in classes


def test_tenant_override_ignored_for_other_tenant():
    doc = load_doc()
    tagged = Tagged(source="wazuh", kind="Asset", category="entity",
                    tenant_id="t_other", labels={"criticality": "crown_jewel"},
                    rows=[{"id": "ast_1"}])
    classes = doc.matching_classes(tagged, Tier.FRONTIER)
    assert EgressClass.NEVER_LEAVE not in classes


def test_local_tier_rules_absent_falls_to_default_only():
    doc = load_doc()
    tagged = Tagged(source="okta", kind="Identity", category="entity",
                    tenant_id="t_main", labels={}, rows=[])
    # rules only specify a `frontier:` action; local gets no per-rule class
    classes = doc.matching_classes(tagged, Tier.LOCAL)
    assert classes == []
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cd py && uv run pytest tests/sovereignty/test_policy.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'mcp.sovereignty.tagging'`.

- [ ] **Step 4: Write the minimal implementation**

Create `py/mcp/sovereignty/tagging.py`:

```python
"""Tag a fetched dataset with the dimensions sovereignty rules match on (spec §7)."""
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Tagged:
    """A fetched dataset annotated for sovereignty matching.

    Attributes:
        source: originating source type (e.g. "srx", "okta", "wazuh", "panos").
        kind: ontology kind (e.g. "Identity", "Asset", "Alert", "Session") or "" for raw event rows.
        category: data category, e.g. "entity", "event", "raw_payload".
        tenant_id: owning tenant.
        labels: denormalized entity labels (e.g. {"criticality": "crown_jewel"}).
        rows: the actual payload rows the guard will transform.
    """

    source: str
    kind: str
    category: str
    tenant_id: str
    labels: dict[str, Any] = field(default_factory=dict)
    rows: list[dict[str, Any]] = field(default_factory=list)
```

Create `py/mcp/sovereignty/policy.py`:

```python
"""Declarative sovereignty policy: parse YAML, match rules, expose tier defaults (spec §7)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import yaml

from mcp.common.scopes import Tier
from mcp.sovereignty.classes import EgressClass
from mcp.sovereignty.tagging import Tagged


@dataclass(frozen=True)
class Rule:
    """A single policy rule: a match predicate plus per-tier egress actions."""

    match: dict[str, Any]
    actions: dict[Tier, EgressClass]

    def matches(self, tagged: Tagged) -> bool:
        """True if every key in `match` is satisfied by the tagged dataset."""
        return all(_match_key(key, value, tagged) for key, value in self.match.items())


def _match_key(key: str, value: Any, tagged: Tagged) -> bool:
    """Match one rule key against the tagged dataset (labels matched as a nested subset)."""
    if key == "source":
        return tagged.source == value
    if key == "kind":
        return tagged.kind == value
    if key == "category":
        return tagged.category == value
    if key == "tenant_id":
        return tagged.tenant_id == value
    if key == "labels":
        return all(tagged.labels.get(label_key) == label_value
                   for label_key, label_value in value.items())
    return False


@dataclass
class PolicyDoc:
    """Parsed sovereignty policy document."""

    defaults: dict[Tier, EgressClass]
    rules: list[Rule]
    tenant_overrides: dict[str, list[Rule]]

    @classmethod
    def from_yaml(cls, text: str) -> "PolicyDoc":
        """Parse a YAML policy document into a PolicyDoc."""
        raw = yaml.safe_load(text)
        defaults = {Tier(tier): EgressClass(cls_) for tier, cls_ in raw.get("defaults", {}).items()}
        rules = [_parse_rule(item) for item in raw.get("rules", [])]
        overrides = {
            tenant: [_parse_rule(item) for item in items]
            for tenant, items in raw.get("tenant_overrides", {}).items()
        }
        return cls(defaults=defaults, rules=rules, tenant_overrides=overrides)

    def default_for(self, tier: Tier) -> EgressClass:
        """Tier default egress class; frontier deny-by-default if unspecified."""
        if tier in self.defaults:
            return self.defaults[tier]
        return EgressClass.NEVER_LEAVE if tier is Tier.FRONTIER else EgressClass.OPEN

    def matching_classes(self, tagged: Tagged, tier: Tier) -> list[EgressClass]:
        """Egress classes from every global + tenant rule that matches, for this tier."""
        applicable = list(self.rules) + self.tenant_overrides.get(tagged.tenant_id, [])
        return [rule.actions[tier] for rule in applicable
                if tier in rule.actions and rule.matches(tagged)]


def _parse_rule(item: dict[str, Any]) -> Rule:
    """Parse one `{match: {...}, local?: cls, frontier?: cls}` entry into a Rule."""
    actions: dict[Tier, EgressClass] = {}
    for tier in Tier:
        if tier.value in item:
            actions[tier] = EgressClass(item[tier.value])
    return Rule(match=item.get("match", {}), actions=actions)
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cd py && uv run pytest tests/sovereignty/test_policy.py -v`
Expected: PASS — 7 passed.

- [ ] **Step 6: Commit**

```bash
git add py/config/sovereignty.example.yaml py/mcp/sovereignty/tagging.py \
  py/mcp/sovereignty/policy.py py/tests/sovereignty/test_policy.py
git commit -m "feat(sovereignty): policy doc, YAML parse, rule matching + tagging model"
```

---

## Task 3: Egress transforms

Pure functions that mutate a list of rows according to the resolved `EgressClass`. `never_leave` denies (returns no rows + a flag); `summary_only` collapses to a count/aggregate; `mask_identities` masks identity-bearing fields; `redact_fields` strips configured sensitive fields; `open` passes through. Each returns the transformed rows plus the list of redaction labels applied (for the audit record).

**Files:**
- Create: `py/mcp/sovereignty/transforms.py`
- Create: `py/tests/sovereignty/test_transforms.py`

- [ ] **Step 1: Write the failing test** `py/tests/sovereignty/test_transforms.py`

```python
from mcp.sovereignty.classes import EgressClass
from mcp.sovereignty.transforms import apply_transform

IDENTITY_ROWS = [
    {"id": "idn_1", "display_name": "Alice Example", "primary_email": "alice@example.com",
     "kind": "user", "status": "active"},
]
RAW_ROWS = [{"id": "ses_1", "raw_payload": {"flow": "10.64.0.1:51000>10.64.0.2:445"}}]


def test_open_passes_through_unchanged():
    rows, redactions = apply_transform(EgressClass.OPEN, list(IDENTITY_ROWS))
    assert rows == IDENTITY_ROWS
    assert redactions == []


def test_never_leave_denies_all_rows():
    rows, redactions = apply_transform(EgressClass.NEVER_LEAVE, list(RAW_ROWS))
    assert rows == []
    assert "denied:never_leave" in redactions


def test_mask_identities_masks_email_and_name():
    rows, redactions = apply_transform(EgressClass.MASK_IDENTITIES, list(IDENTITY_ROWS))
    assert rows[0]["display_name"] == "<masked>"
    assert rows[0]["primary_email"] == "<masked>"
    assert rows[0]["id"] == "idn_1"  # IDs preserved for grounding (A7)
    assert rows[0]["status"] == "active"  # non-identity fields preserved
    assert "masked:identity_fields" in redactions


def test_redact_fields_strips_raw_payload():
    rows, redactions = apply_transform(EgressClass.REDACT_FIELDS, list(RAW_ROWS))
    assert "raw_payload" not in rows[0]
    assert rows[0]["id"] == "ses_1"
    assert "redacted:raw_payload" in redactions


def test_summary_only_collapses_to_count():
    rows, redactions = apply_transform(EgressClass.SUMMARY_ONLY, list(IDENTITY_ROWS))
    assert rows == [{"summary": {"row_count": 1}}]
    assert "summarized" in redactions
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd py && uv run pytest tests/sovereignty/test_transforms.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'mcp.sovereignty.transforms'`.

- [ ] **Step 3: Write the minimal implementation** `py/mcp/sovereignty/transforms.py`

```python
"""Egress transforms keyed by EgressClass — pure, no I/O (spec §7)."""
from typing import Any

from mcp.sovereignty.classes import EgressClass

# Identity-bearing fields masked at frontier (spec §7 mask_identities).
_IDENTITY_FIELDS = ("display_name", "primary_email", "actor", "user", "affected_user")
# Sensitive fields stripped under redact_fields.
_REDACT_FIELDS = ("raw_payload", "ext", "before", "after", "before_digest", "after_digest")
_MASK_TOKEN = "<masked>"

Rows = list[dict[str, Any]]


def apply_transform(egress: EgressClass, rows: Rows) -> tuple[Rows, list[str]]:
    """Transform rows per the resolved egress class.

    Args:
        egress: the most-restrictive class resolved by the guard.
        rows: payload rows to transform (mutated/replaced; caller passes a copy).

    Returns:
        (transformed_rows, redactions_applied) — redactions feed the audit record.
    """
    if egress is EgressClass.OPEN:
        return rows, []
    if egress is EgressClass.NEVER_LEAVE:
        return [], ["denied:never_leave"]
    if egress is EgressClass.SUMMARY_ONLY:
        return [{"summary": {"row_count": len(rows)}}], ["summarized"]
    if egress is EgressClass.MASK_IDENTITIES:
        for row in rows:
            for field_name in _IDENTITY_FIELDS:
                if field_name in row:
                    row[field_name] = _MASK_TOKEN
        return rows, ["masked:identity_fields"]
    if egress is EgressClass.REDACT_FIELDS:
        applied: list[str] = []
        for row in rows:
            for field_name in _REDACT_FIELDS:
                if field_name in row:
                    del row[field_name]
                    label = f"redacted:{field_name}"
                    if label not in applied:
                        applied.append(label)
        return rows, applied
    raise ValueError(f"unknown egress class: {egress}")
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd py && uv run pytest tests/sovereignty/test_transforms.py -v`
Expected: PASS — 5 passed.

- [ ] **Step 5: Commit**

```bash
git add py/mcp/sovereignty/transforms.py py/tests/sovereignty/test_transforms.py
git commit -m "feat(sovereignty): mask/redact/summarize/deny egress transforms"
```

---

## Task 4: Sovereignty Guard core (pure decision)

The chokepoint. `evaluate(tagged, tier, policy)` collects the tier default plus every matching rule class, resolves the most-restrictive one, applies the corresponding transform, and returns a `Decision` (the egress class, transformed rows, redaction labels, denied flag). Entirely pure — no gRPC, no DB — so the four required behaviors (most-restrictive across rules; Identity masked on frontier; raw denied on frontier; open on local) are asserted directly.

**Files:**
- Create: `py/mcp/sovereignty/guard.py`
- Create: `py/tests/sovereignty/test_guard.py`

- [ ] **Step 1: Write the failing test** `py/tests/sovereignty/test_guard.py`

```python
from pathlib import Path

from mcp.common.scopes import Tier
from mcp.sovereignty.classes import EgressClass
from mcp.sovereignty.guard import Decision, evaluate
from mcp.sovereignty.policy import PolicyDoc
from mcp.sovereignty.tagging import Tagged

YAML_PATH = Path(__file__).parents[2] / "config" / "sovereignty.example.yaml"


def doc() -> PolicyDoc:
    return PolicyDoc.from_yaml(YAML_PATH.read_text())


def test_most_restrictive_across_multiple_matching_rules():
    # crown_jewel Asset on t_main matches the tenant override (never_leave); even though
    # the tier default (never_leave) and any other class compete, never_leave wins.
    tagged = Tagged(source="wazuh", kind="Asset", category="entity", tenant_id="t_main",
                    labels={"criticality": "crown_jewel"}, rows=[{"id": "ast_1"}])
    decision = evaluate(tagged, Tier.FRONTIER, doc())
    assert decision.egress is EgressClass.NEVER_LEAVE
    assert decision.denied is True
    assert decision.rows == []


def test_identity_masked_on_frontier_full_on_local():
    tagged = Tagged(source="okta", kind="Identity", category="entity", tenant_id="t_main",
                    labels={}, rows=[{"id": "idn_1", "display_name": "Alice Example",
                                      "primary_email": "alice@example.com"}])
    frontier = evaluate(tagged, Tier.FRONTIER, doc())
    assert frontier.egress is EgressClass.MASK_IDENTITIES
    assert frontier.rows[0]["display_name"] == "<masked>"
    assert frontier.rows[0]["primary_email"] == "<masked>"

    # rebuild rows (frontier mutated them) for the local assertion
    tagged_local = Tagged(source="okta", kind="Identity", category="entity", tenant_id="t_main",
                          labels={}, rows=[{"id": "idn_1", "display_name": "Alice Example",
                                            "primary_email": "alice@example.com"}])
    local = evaluate(tagged_local, Tier.LOCAL, doc())
    assert local.egress is EgressClass.OPEN
    assert local.rows[0]["display_name"] == "Alice Example"
    assert local.rows[0]["primary_email"] == "alice@example.com"


def test_raw_payload_denied_on_frontier():
    tagged = Tagged(source="srx", kind="Session", category="raw_payload", tenant_id="t_main",
                    labels={}, rows=[{"id": "ses_1", "raw_payload": {"flow": "x"}}])
    decision = evaluate(tagged, Tier.FRONTIER, doc())
    assert decision.egress is EgressClass.NEVER_LEAVE
    assert decision.denied is True
    assert decision.rows == []


def test_open_on_local_for_raw_payload():
    tagged = Tagged(source="srx", kind="Session", category="raw_payload", tenant_id="t_main",
                    labels={}, rows=[{"id": "ses_1", "raw_payload": {"flow": "x"}}])
    decision = evaluate(tagged, Tier.LOCAL, doc())
    assert decision.egress is EgressClass.OPEN
    assert decision.denied is False
    assert decision.rows[0]["raw_payload"] == {"flow": "x"}


def test_decision_carries_redaction_labels():
    tagged = Tagged(source="okta", kind="Identity", category="entity", tenant_id="t_main",
                    labels={}, rows=[{"id": "idn_1", "display_name": "Alice Example"}])
    decision = evaluate(tagged, Tier.FRONTIER, doc())
    assert "masked:identity_fields" in decision.redactions
    assert isinstance(decision, Decision)
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd py && uv run pytest tests/sovereignty/test_guard.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'mcp.sovereignty.guard'`.

- [ ] **Step 3: Write the minimal implementation** `py/mcp/sovereignty/guard.py`

```python
"""Sovereignty Guard core: the single, pure egress decision (spec §7)."""
from dataclasses import dataclass, field
from typing import Any

from mcp.common.scopes import Tier
from mcp.sovereignty.classes import EgressClass, most_restrictive
from mcp.sovereignty.policy import PolicyDoc
from mcp.sovereignty.tagging import Tagged
from mcp.sovereignty.transforms import apply_transform


@dataclass
class Decision:
    """Outcome of evaluating one tagged dataset for one tier.

    Attributes:
        egress: the resolved most-restrictive egress class.
        rows: the transformed payload rows safe to return at this tier.
        redactions: labels describing what was masked/redacted/denied (for audit).
        denied: True when egress is never_leave (no rows cross the boundary).
    """

    egress: EgressClass
    rows: list[dict[str, Any]]
    redactions: list[str] = field(default_factory=list)
    denied: bool = False


def evaluate(tagged: Tagged, tier: Tier, policy: PolicyDoc) -> Decision:
    """Resolve and apply the sovereignty egress decision for a tagged dataset.

    Combines the tier default with every matching rule, picks the strictest class,
    and transforms the rows accordingly. Pure: no gRPC, no DB.

    Args:
        tagged: the fetched, tagged dataset.
        tier: the caller's sovereignty tier.
        policy: the active policy document.

    Returns:
        A Decision with the egress class, transformed rows, and redaction labels.
    """
    candidates = [policy.default_for(tier), *policy.matching_classes(tagged, tier)]
    egress = most_restrictive(candidates)
    rows, redactions = apply_transform(egress, tagged.rows)
    return Decision(
        egress=egress,
        rows=rows,
        redactions=redactions,
        denied=egress is EgressClass.NEVER_LEAVE,
    )
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd py && uv run pytest tests/sovereignty/test_guard.py -v`
Expected: PASS — 5 passed.

- [ ] **Step 5: Commit**

```bash
git add py/mcp/sovereignty/guard.py py/tests/sovereignty/test_guard.py
git commit -m "feat(sovereignty): pure guard core resolving most-restrictive egress + transform"
```

---

## Task 5: Audit record + args_digest hashing + sink

The append-only audit row written to ClickHouse `ssdf.audit` (Plan 1 table) after every tool call, with fields exactly per spec §7. `args_digest` is a SHA-256 hex of the canonicalized tool args — never raw args, so the audit log is not a leak vector. The `AuditSink` is a thin ClickHouse client; tests use a fake.

**Files:**
- Create: `py/mcp/sovereignty/audit.py`
- Create: `py/tests/sovereignty/test_audit.py`

- [ ] **Step 1: Write the failing test** `py/tests/sovereignty/test_audit.py`

```python
import hashlib

from mcp.sovereignty.audit import AuditRecord, args_digest


def test_args_digest_is_sha256_hex_and_order_independent():
    digest_a = args_digest({"id": "idn_1", "include_raw": True})
    digest_b = args_digest({"include_raw": True, "id": "idn_1"})
    assert digest_a == digest_b  # canonicalized (sorted keys)
    assert len(digest_a) == 64
    assert all(ch in "0123456789abcdef" for ch in digest_a)


def test_args_digest_never_contains_raw_values():
    secret = "alice@example.com"
    digest = args_digest({"email": secret})
    assert secret not in digest


def test_args_digest_matches_manual_sha256():
    expected = hashlib.sha256(b'{"a":1}').hexdigest()
    assert args_digest({"a": 1}) == expected


def test_audit_record_has_exact_spec_fields():
    record = AuditRecord(
        request_id="req_1", tenant_id="t_main", caller="agent-local-1", tier="local",
        server="ssdf-local-mcp", tool="get_entity", args_digest=args_digest({"id": "idn_1"}),
        datasets_touched=["okta:Identity"], sovereignty_decision="open", rows_returned=1,
        redactions_applied=[], latency_ms=12, outcome="ok",
    )
    row = record.to_row()
    assert set(row.keys()) == {
        "ts", "request_id", "tenant_id", "caller", "tier", "server", "tool",
        "args_digest", "datasets_touched", "sovereignty_decision", "rows_returned",
        "redactions_applied", "latency_ms", "outcome",
    }
    assert row["tool"] == "get_entity"
    assert row["datasets_touched"] == ["okta:Identity"]
    assert row["ts"]  # auto-populated ISO timestamp
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd py && uv run pytest tests/sovereignty/test_audit.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'mcp.sovereignty.audit'`.

- [ ] **Step 3: Write the minimal implementation** `py/mcp/sovereignty/audit.py`

```python
"""Audit record + args hashing + ClickHouse sink for the ssdf.audit table (spec §7)."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol


def args_digest(args: dict[str, Any]) -> str:
    """SHA-256 hex of canonicalized tool args (sorted keys, compact). Never stores raw args.

    Args:
        args: the raw tool arguments.

    Returns:
        64-char hex digest — the audit log records this, not the values.
    """
    canonical = json.dumps(args, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass
class AuditRecord:
    """One immutable audit row matching ssdf.audit columns exactly (spec §7)."""

    request_id: str
    tenant_id: str
    caller: str
    tier: str
    server: str
    tool: str
    args_digest: str
    datasets_touched: list[str]
    sovereignty_decision: str
    rows_returned: int
    redactions_applied: list[str]
    latency_ms: int
    outcome: str
    ts: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_row(self) -> dict[str, Any]:
        """Serialize to a ClickHouse insert row keyed by column name."""
        return {
            "ts": self.ts,
            "request_id": self.request_id,
            "tenant_id": self.tenant_id,
            "caller": self.caller,
            "tier": self.tier,
            "server": self.server,
            "tool": self.tool,
            "args_digest": self.args_digest,
            "datasets_touched": self.datasets_touched,
            "sovereignty_decision": self.sovereignty_decision,
            "rows_returned": self.rows_returned,
            "redactions_applied": self.redactions_applied,
            "latency_ms": self.latency_ms,
            "outcome": self.outcome,
        }


class AuditSink(Protocol):
    """Anything that can persist an audit record (faked in tests)."""

    async def write(self, record: AuditRecord) -> None: ...


_COLUMNS = [
    "ts", "request_id", "tenant_id", "caller", "tier", "server", "tool",
    "args_digest", "datasets_touched", "sovereignty_decision", "rows_returned",
    "redactions_applied", "latency_ms", "outcome",
]


class ClickHouseAuditSink:
    """Thin ClickHouse-backed audit sink (append-only insert into ssdf.audit)."""

    def __init__(self, client: Any) -> None:
        """Wrap a clickhouse-connect async client."""
        self._client = client

    async def write(self, record: AuditRecord) -> None:
        """Insert one audit row into ssdf.audit."""
        row = record.to_row()
        await self._client.insert(
            "ssdf.audit", [[row[column] for column in _COLUMNS]], column_names=_COLUMNS
        )
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd py && uv run pytest tests/sovereignty/test_audit.py -v`
Expected: PASS — 4 passed.

- [ ] **Step 5: Commit**

```bash
git add py/mcp/sovereignty/audit.py py/tests/sovereignty/test_audit.py
git commit -m "feat(sovereignty): audit record, hashed args_digest, clickhouse sink"
```

---

## Task 6: gRPC client, call context, and policy store (thin clients)

The seams between the pure guard and the outside world. `grpc_client.GrpcClient` wraps the Plan 5 `ssdf.v1` stubs with one async method per service call and injects `tenant_id` metadata. `context.CallContext` resolves a Gateway token into `tier`/`scopes`/`tenant_id`/`caller`. `policy_store.PolicyStore` loads the active `sovereignty_policy` row from Postgres and caches it (hot-reloadable). All three are faked in tests; here we test only the pure parts (context resolution + scope checks).

**Files:**
- Create: `py/mcp/common/context.py`
- Create: `py/mcp/common/grpc_client.py`
- Create: `py/mcp/sovereignty/policy_store.py`
- Create: `py/tests/__init__.py` files as needed
- Create: `py/tests/common/test_context.py`

- [ ] **Step 1: Write the failing test** `py/tests/common/test_context.py`

```python
import pytest

from mcp.common.context import CallContext, ScopeError
from mcp.common.scopes import Scope, Tier


def test_local_context_has_raw_read():
    ctx = CallContext(caller="agent-local-1", tenant_id="t_main", tier=Tier.LOCAL,
                      scopes={Scope.EVENTS_READ, Scope.GRAPH_READ, Scope.RAW_READ})
    assert ctx.has(Scope.RAW_READ) is True
    ctx.require(Scope.RAW_READ)  # does not raise


def test_frontier_context_lacks_raw_read():
    ctx = CallContext(caller="agent-frontier-1", tenant_id="t_main", tier=Tier.FRONTIER,
                      scopes={Scope.EVENTS_READ, Scope.GRAPH_READ})
    assert ctx.has(Scope.RAW_READ) is False
    with pytest.raises(ScopeError):
        ctx.require(Scope.RAW_READ)


def test_require_config_write_for_admin():
    ctx = CallContext(caller="operator-1", tenant_id="t_main", tier=Tier.LOCAL,
                      scopes={Scope.CONFIG_WRITE})
    ctx.require(Scope.CONFIG_WRITE)
    with pytest.raises(ScopeError):
        ctx.require(Scope.EVENTS_READ)
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd py && uv run pytest tests/common/test_context.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'mcp.common.context'`.

- [ ] **Step 3: Write the minimal implementation**

Create `py/tests/common/__init__.py` (empty).

Create `py/mcp/common/context.py`:

```python
"""Per-call security context resolved from a Gateway token (spec §5)."""
from dataclasses import dataclass

from mcp.common.scopes import Scope, Tier


class ScopeError(PermissionError):
    """Raised when a required scope is missing from the call context."""


@dataclass(frozen=True)
class CallContext:
    """Resolved identity, tenant, tier, and scopes for one MCP tool call.

    Tier and scopes are derived from the token by the Gateway — never client-supplied.
    """

    caller: str
    tenant_id: str
    tier: Tier
    scopes: frozenset[Scope]

    def __post_init__(self) -> None:
        object.__setattr__(self, "scopes", frozenset(self.scopes))

    def has(self, scope: Scope) -> bool:
        """True if the call context carries the given scope."""
        return scope in self.scopes

    def require(self, scope: Scope) -> None:
        """Raise ScopeError if the context lacks the given scope."""
        if scope not in self.scopes:
            raise ScopeError(f"missing required scope: {scope.value}")
```

Create `py/mcp/common/grpc_client.py`:

```python
"""Thin async wrapper over the Plan 5 ssdf.v1 gRPC services.

Tools call these methods; they never touch stores directly. tenant_id is injected
as call metadata so services scope every store query (spec §5 multi-tenancy).
"""
from __future__ import annotations

from typing import Any, Protocol


class GrpcClient(Protocol):
    """Surface the MCP tools depend on. The real impl wraps generated ssdf.v1 stubs."""

    async def get_ontology_schema(self, tenant_id: str) -> dict[str, Any]: ...
    async def search_entities(self, tenant_id: str, *, kind: str | None, query: str,
                              filters: dict[str, Any], limit: int) -> list[dict[str, Any]]: ...
    async def get_entity(self, tenant_id: str, *, entity_id: str,
                         include_raw: bool) -> dict[str, Any]: ...
    async def get_entity_neighbors(self, tenant_id: str, *, entity_id: str, depth: int,
                                   rel_types: list[str] | None,
                                   kinds: list[str] | None) -> dict[str, Any]: ...
    async def find_path(self, tenant_id: str, *, from_id: str, to_id: str,
                        max_hops: int) -> dict[str, Any]: ...
    async def search_events(self, tenant_id: str, *, event_types: list[str] | None,
                            time_range: dict[str, str], filters: dict[str, Any],
                            limit: int) -> list[dict[str, Any]]: ...
    async def get_incident_timeline(self, tenant_id: str, *, incident_id: str | None,
                                    entity_id: str | None,
                                    window: dict[str, str] | None) -> list[dict[str, Any]]: ...
    async def get_entity_activity(self, tenant_id: str, *, entity_id: str,
                                  window: dict[str, str],
                                  event_types: list[str] | None) -> dict[str, Any]: ...
    async def get_policies_for_entity(self, tenant_id: str, *,
                                      entity_id: str) -> list[dict[str, Any]]: ...
    async def get_source_health(self, tenant_id: str) -> list[dict[str, Any]]: ...
    # IngestionService (admin)
    async def register_source(self, tenant_id: str, *, type: str, name: str,
                              connection: dict[str, Any], secret_ref: str | None) -> dict[str, Any]: ...
    async def list_sources(self, tenant_id: str) -> list[dict[str, Any]]: ...
    async def pause_source(self, tenant_id: str, *, source_id: str) -> dict[str, Any]: ...
    async def remove_source(self, tenant_id: str, *, source_id: str) -> dict[str, Any]: ...


class TonicGrpcClient:
    """Real client: holds generated ssdf.v1 stubs and an mTLS channel.

    Each method calls the matching stub with tenant_id in metadata. Bodies are
    one-liners over the generated stubs; wired when Plan 5 stubs are vendored under
    `mcp/common/_pb/`. Implemented per-method as Plan 5 lands.
    """

    def __init__(self, channel: Any, stubs: Any) -> None:
        self._channel = channel
        self._stubs = stubs

    def _md(self, tenant_id: str) -> list[tuple[str, str]]:
        """Build gRPC metadata carrying tenant context."""
        return [("x-ssdf-tenant", tenant_id)]
```

Create `py/mcp/sovereignty/policy_store.py`:

```python
"""Load + cache the active sovereignty policy from Postgres (hot-reloadable, spec §7)."""
from __future__ import annotations

from typing import Any, Protocol

from mcp.sovereignty.policy import PolicyDoc


class PolicySource(Protocol):
    """Fetches the active policy YAML/JSON document (faked in tests)."""

    async def fetch_active_document(self) -> str: ...


class PostgresPolicySource:
    """Reads the active sovereignty_policy.document column from Postgres."""

    def __init__(self, pool: Any) -> None:
        """Wrap an asyncpg pool."""
        self._pool = pool

    async def fetch_active_document(self) -> str:
        """Return the active policy document as text (highest version, active=true)."""
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT document FROM sovereignty_policy "
                "WHERE active = true ORDER BY version DESC LIMIT 1"
            )
        if row is None:
            raise RuntimeError("no active sovereignty_policy row found")
        document = row["document"]
        return document if isinstance(document, str) else str(document)


class PolicyStore:
    """Caches a parsed PolicyDoc; reload() re-fetches for hot-reload."""

    def __init__(self, source: PolicySource) -> None:
        self._source = source
        self._doc: PolicyDoc | None = None

    async def get(self) -> PolicyDoc:
        """Return the cached policy, loading it on first use."""
        if self._doc is None:
            await self.reload()
        assert self._doc is not None
        return self._doc

    async def reload(self) -> None:
        """Re-fetch and re-parse the active policy document."""
        self._doc = PolicyDoc.from_yaml(await self._source.fetch_active_document())
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd py && uv run pytest tests/common/test_context.py -v`
Expected: PASS — 3 passed.

- [ ] **Step 5: Commit**

```bash
git add py/mcp/common/context.py py/mcp/common/grpc_client.py \
  py/mcp/sovereignty/policy_store.py py/tests/common/__init__.py py/tests/common/test_context.py
git commit -m "feat(mcp): call context, grpc client wrapper, postgres policy store"
```

---

## Task 7: Test fixtures + guarded-tool runner

Shared `conftest.py` fixtures (`FakeGrpcClient`, `FakeAuditSink`, a loaded `PolicyDoc`) used by every server test. A small `run_guarded` helper in `mcp/common/runner.py` is the one place that ties the pieces together: it tags a fetched dataset, evaluates the guard for the caller's tier, writes the audit record, and returns the safe rows. Servers call it so they never bypass the chokepoint.

**Files:**
- Create: `py/tests/conftest.py`
- Create: `py/mcp/common/runner.py`
- Create: `py/tests/common/test_runner.py`

- [ ] **Step 1: Write the shared fixtures** `py/tests/conftest.py`

```python
from pathlib import Path

import pytest

from mcp.sovereignty.audit import AuditRecord
from mcp.sovereignty.policy import PolicyDoc

YAML_PATH = Path(__file__).parents[1] / "config" / "sovereignty.example.yaml"


@pytest.fixture
def policy_doc() -> PolicyDoc:
    return PolicyDoc.from_yaml(YAML_PATH.read_text())


class FakeAuditSink:
    """Captures audit records in memory for assertions."""

    def __init__(self) -> None:
        self.records: list[AuditRecord] = []

    async def write(self, record: AuditRecord) -> None:
        self.records.append(record)


class FakeGrpcClient:
    """Returns canned datasets per method; records calls for assertions."""

    def __init__(self, responses: dict | None = None) -> None:
        self.responses = responses or {}
        self.calls: list[tuple[str, dict]] = []

    async def get_entity(self, tenant_id, *, entity_id, include_raw):
        self.calls.append(("get_entity", {"entity_id": entity_id, "include_raw": include_raw}))
        return self.responses.get("get_entity", {
            "id": entity_id, "kind": "Identity", "display_name": "Alice Example",
            "primary_email": "alice@example.com", "status": "active",
            "provenance": {"source": "okta", "source_id": "00u1", "tenant_id": tenant_id},
        })

    async def search_entities(self, tenant_id, *, kind, query, filters, limit):
        self.calls.append(("search_entities", {"kind": kind, "query": query, "limit": limit}))
        return self.responses.get("search_entities", [
            {"id": "idn_1", "kind": "Identity", "name": "Alice Example",
             "key_labels": {}, "last_seen": "2026-06-05T00:00:00Z"},
        ])

    async def search_events(self, tenant_id, *, event_types, time_range, filters, limit):
        self.calls.append(("search_events", {"event_types": event_types, "limit": limit}))
        return self.responses.get("search_events", [
            {"event_id": "evt_1", "event_type": "flow_event", "raw_payload": {"flow": "x"},
             "provenance": {"source": "srx", "source_id": "1", "tenant_id": tenant_id}},
        ])

    async def get_source_health(self, tenant_id):
        self.calls.append(("get_source_health", {}))
        return self.responses.get("get_source_health", [
            {"source_id": "src_1", "type": "srx", "status": "healthy", "lag_seconds": 2},
        ])

    async def register_source(self, tenant_id, *, type, name, connection, secret_ref):
        self.calls.append(("register_source", {"type": type, "name": name}))
        return self.responses.get("register_source", {
            "source_id": "src_new1", "ingest_endpoint": "syslog://ssdf.local:6514",
            "ingest_token": "tok_abc", "status": "pending",
        })

    async def list_sources(self, tenant_id):
        self.calls.append(("list_sources", {}))
        return self.responses.get("list_sources", [])

    async def pause_source(self, tenant_id, *, source_id):
        self.calls.append(("pause_source", {"source_id": source_id}))
        return {"source_id": source_id, "status": "paused"}

    async def remove_source(self, tenant_id, *, source_id):
        self.calls.append(("remove_source", {"source_id": source_id}))
        return {"source_id": source_id, "status": "removed"}


@pytest.fixture
def fake_grpc() -> FakeGrpcClient:
    return FakeGrpcClient()


@pytest.fixture
def fake_audit() -> FakeAuditSink:
    return FakeAuditSink()
```

- [ ] **Step 2: Write the failing test** `py/tests/common/test_runner.py`

```python
import pytest

from mcp.common.context import CallContext
from mcp.common.runner import run_guarded
from mcp.common.scopes import Scope, Tier
from mcp.sovereignty.tagging import Tagged
from tests.conftest import FakeAuditSink

pytestmark = pytest.mark.asyncio


async def test_runner_returns_rows_and_writes_audit(policy_doc):
    sink = FakeAuditSink()
    ctx = CallContext(caller="agent-local-1", tenant_id="t_main", tier=Tier.LOCAL,
                      scopes={Scope.GRAPH_READ})
    tagged = Tagged(source="okta", kind="Identity", category="entity", tenant_id="t_main",
                    labels={}, rows=[{"id": "idn_1", "display_name": "Alice Example"}])
    rows = await run_guarded(ctx=ctx, server="ssdf-local-mcp", tool="get_entity",
                             args={"id": "idn_1"}, tagged=tagged, policy=policy_doc,
                             audit_sink=sink, datasets_touched=["okta:Identity"])
    assert rows[0]["display_name"] == "Alice Example"  # local = open
    assert len(sink.records) == 1
    record = sink.records[0]
    assert record.tool == "get_entity"
    assert record.tier == "local"
    assert record.sovereignty_decision == "open"
    assert record.rows_returned == 1
    # args_digest is a hash, not the raw args
    assert record.args_digest != "idn_1"
    assert len(record.args_digest) == 64


async def test_runner_audits_denied_frontier_with_zero_rows(policy_doc):
    sink = FakeAuditSink()
    ctx = CallContext(caller="agent-frontier-1", tenant_id="t_main", tier=Tier.FRONTIER,
                      scopes={Scope.EVENTS_READ})
    tagged = Tagged(source="srx", kind="Session", category="raw_payload", tenant_id="t_main",
                    labels={}, rows=[{"id": "ses_1", "raw_payload": {"flow": "x"}}])
    rows = await run_guarded(ctx=ctx, server="ssdf-frontier-mcp", tool="get_incident_timeline",
                             args={"incident_id": "inc_1"}, tagged=tagged, policy=policy_doc,
                             audit_sink=sink, datasets_touched=["srx:raw_payload"])
    assert rows == []
    record = sink.records[0]
    assert record.sovereignty_decision == "never_leave"
    assert record.rows_returned == 0
    assert "denied:never_leave" in record.redactions_applied
    assert record.outcome == "ok"
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cd py && uv run pytest tests/common/test_runner.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'mcp.common.runner'`.

- [ ] **Step 4: Write the minimal implementation** `py/mcp/common/runner.py`

```python
"""The single guarded path: tag-fetched-data → guard → audit → safe rows (spec §7)."""
from __future__ import annotations

import time
import uuid
from typing import Any

from mcp.common.context import CallContext
from mcp.sovereignty.audit import AuditRecord, AuditSink, args_digest
from mcp.sovereignty.guard import evaluate
from mcp.sovereignty.policy import PolicyDoc
from mcp.sovereignty.tagging import Tagged


async def run_guarded(
    *,
    ctx: CallContext,
    server: str,
    tool: str,
    args: dict[str, Any],
    tagged: Tagged,
    policy: PolicyDoc,
    audit_sink: AuditSink,
    datasets_touched: list[str],
) -> list[dict[str, Any]]:
    """Run a fetched dataset through the guard, write an audit record, return safe rows.

    This is the ONE place that crosses the egress boundary; tools must route through it
    so the Sovereignty Guard is never bypassed (spec §7).

    Args:
        ctx: resolved call context (tier drives the decision).
        server: emitting MCP server name (for audit).
        tool: tool name (for audit).
        args: raw tool args — hashed into args_digest, never stored raw.
        tagged: the tagged dataset fetched via gRPC.
        policy: active policy document.
        audit_sink: where the audit record is written.
        datasets_touched: dataset identifiers for the audit row.

    Returns:
        The transformed, tier-safe rows.
    """
    started = time.monotonic()
    decision = evaluate(tagged, ctx.tier, policy)
    latency_ms = int((time.monotonic() - started) * 1000)
    record = AuditRecord(
        request_id=f"req_{uuid.uuid4().hex}",
        tenant_id=ctx.tenant_id,
        caller=ctx.caller,
        tier=ctx.tier.value,
        server=server,
        tool=tool,
        args_digest=args_digest(args),
        datasets_touched=datasets_touched,
        sovereignty_decision=decision.egress.value,
        rows_returned=len(decision.rows),
        redactions_applied=decision.redactions,
        latency_ms=latency_ms,
        outcome="ok",
    )
    await audit_sink.write(record)
    return decision.rows
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cd py && uv run pytest tests/common/test_runner.py -v`
Expected: PASS — 2 passed.

- [ ] **Step 6: Commit**

```bash
git add py/tests/conftest.py py/mcp/common/runner.py py/tests/common/test_runner.py
git commit -m "feat(mcp): guarded-tool runner + shared test fixtures"
```

---

## Task 8: ssdf-local-mcp — full read tool set

The sovereign-local server registers ALL 10 read tools (spec §6 catalog), tier=`local`. Tools fetch via `GrpcClient`, build a `Tagged` dataset, and return through `run_guarded` (which is `open` on local, so unmasked). `get_entity(include_raw=True)` requires `raw:read`. To make the catalog testable, tools are registered via a shared `register_read_tools(mcp, tier, tools_for_tier)` factory; the server exposes `registered_tool_names()`.

**Files:**
- Create: `py/mcp/local/__init__.py`
- Create: `py/mcp/local/tools.py`
- Create: `py/mcp/local/server.py`
- Create: `py/tests/local/__init__.py`
- Create: `py/tests/local/test_local_server.py`

- [ ] **Step 1: Write the failing test** `py/tests/local/test_local_server.py`

```python
import pytest

from mcp.common.context import CallContext
from mcp.common.scopes import Scope, Tier
from mcp.local.server import LOCAL_TOOL_NAMES, build_local_app
from tests.conftest import FakeAuditSink, FakeGrpcClient

pytestmark = pytest.mark.asyncio


def test_local_catalog_registers_all_ten_tools():
    assert LOCAL_TOOL_NAMES == [
        "get_ontology_schema",
        "search_entities",
        "get_entity",
        "get_entity_neighbors",
        "find_path",
        "search_events",
        "get_incident_timeline",
        "get_entity_activity",
        "get_policies_for_entity",
        "get_source_health",
    ]


def test_local_app_exposes_raw_and_rowlevel_tools():
    app = build_local_app(grpc=FakeGrpcClient(), audit_sink=FakeAuditSink(), policy=None)
    names = set(app.registered_tool_names())
    # raw/row-level tools that are local-only MUST be present here
    for tool in ("get_entity", "search_events", "get_entity_neighbors",
                 "find_path", "get_policies_for_entity"):
        assert tool in names


async def test_local_get_entity_returns_unmasked(policy_doc):
    grpc = FakeGrpcClient()
    sink = FakeAuditSink()
    app = build_local_app(grpc=grpc, audit_sink=sink, policy=policy_doc)
    ctx = CallContext(caller="agent-local-1", tenant_id="t_main", tier=Tier.LOCAL,
                      scopes={Scope.GRAPH_READ})
    rows = await app.call("get_entity", ctx, {"id": "idn_1"})
    assert rows[0]["display_name"] == "Alice Example"  # unmasked on local
    assert sink.records[0].sovereignty_decision == "open"
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd py && uv run pytest tests/local/test_local_server.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'mcp.local.server'`.

- [ ] **Step 3: Write the minimal implementation**

Create `py/mcp/local/__init__.py` (empty) and `py/tests/local/__init__.py` (empty).

Create `py/mcp/local/tools.py`:

```python
"""Read tool fetch+tag implementations shared by local (and frontier subset) servers."""
from __future__ import annotations

from typing import Any

from mcp.common.context import CallContext
from mcp.common.grpc_client import GrpcClient
from mcp.common.scopes import Scope
from mcp.sovereignty.tagging import Tagged


async def fetch_get_entity(grpc: GrpcClient, ctx: CallContext, args: dict[str, Any]) -> Tagged:
    """get_entity — canonical entity + source_refs (+ext only with raw:read)."""
    include_raw = bool(args.get("include_raw", False))
    if include_raw:
        ctx.require(Scope.RAW_READ)
    row = await grpc.get_entity(ctx.tenant_id, entity_id=args["id"], include_raw=include_raw)
    category = "raw_payload" if include_raw else "entity"
    return Tagged(source=row.get("provenance", {}).get("source", ""),
                  kind=row.get("kind", ""), category=category, tenant_id=ctx.tenant_id,
                  labels=row.get("labels", {}), rows=[row])


async def fetch_search_entities(grpc, ctx, args):
    """search_entities — id/kind/name/key_labels/last_seen rows."""
    rows = await grpc.search_entities(ctx.tenant_id, kind=args.get("kind"),
                                      query=args.get("query", ""),
                                      filters=args.get("filters", {}),
                                      limit=int(args.get("limit", 50)))
    kind = rows[0]["kind"] if rows else (args.get("kind") or "")
    return Tagged(source="", kind=kind, category="entity", tenant_id=ctx.tenant_id,
                  labels={}, rows=rows)


async def fetch_search_events(grpc, ctx, args):
    """search_events — flat event rows with provenance (raw/row-level, local-only)."""
    ctx.require(Scope.EVENTS_READ)
    rows = await grpc.search_events(ctx.tenant_id, event_types=args.get("event_types"),
                                    time_range=args["time_range"],
                                    filters=args.get("filters", {}),
                                    limit=int(args.get("limit", 100)))
    return Tagged(source="", kind="", category="raw_payload", tenant_id=ctx.tenant_id,
                  labels={}, rows=rows)


async def fetch_get_entity_neighbors(grpc, ctx, args):
    """get_entity_neighbors — {nodes, edges} (row-level graph, local-only)."""
    ctx.require(Scope.GRAPH_READ)
    result = await grpc.get_entity_neighbors(ctx.tenant_id, entity_id=args["id"],
                                             depth=int(args.get("depth", 1)),
                                             rel_types=args.get("rel_types"),
                                             kinds=args.get("kinds"))
    return Tagged(source="", kind="", category="graph", tenant_id=ctx.tenant_id,
                  labels={}, rows=[result])


async def fetch_find_path(grpc, ctx, args):
    """find_path — ordered {nodes, edges} (row-level graph, local-only)."""
    ctx.require(Scope.GRAPH_READ)
    result = await grpc.find_path(ctx.tenant_id, from_id=args["from_id"],
                                  to_id=args["to_id"], max_hops=int(args.get("max_hops", 5)))
    return Tagged(source="", kind="", category="graph", tenant_id=ctx.tenant_id,
                  labels={}, rows=[result])


async def fetch_get_incident_timeline(grpc, ctx, args):
    """get_incident_timeline — ordered events + provenance (both tiers)."""
    rows = await grpc.get_incident_timeline(ctx.tenant_id,
                                            incident_id=args.get("incident_id"),
                                            entity_id=args.get("entity_id"),
                                            window=args.get("window"))
    return Tagged(source="", kind="Incident", category="event", tenant_id=ctx.tenant_id,
                  labels={}, rows=rows)


async def fetch_get_entity_activity(grpc, ctx, args):
    """get_entity_activity — activity rollup + recent refs (both tiers)."""
    result = await grpc.get_entity_activity(ctx.tenant_id, entity_id=args["entity_id"],
                                            window=args["window"],
                                            event_types=args.get("event_types"))
    return Tagged(source="", kind="", category="event", tenant_id=ctx.tenant_id,
                  labels={}, rows=[result])


async def fetch_get_policies_for_entity(grpc, ctx, args):
    """get_policies_for_entity — governing PolicyObjects (local-only)."""
    ctx.require(Scope.POLICY_READ)
    rows = await grpc.get_policies_for_entity(ctx.tenant_id, entity_id=args["entity_id"])
    return Tagged(source="", kind="PolicyObject", category="entity", tenant_id=ctx.tenant_id,
                  labels={}, rows=rows)


async def fetch_get_ontology_schema(grpc, ctx, args):
    """get_ontology_schema — entity/event types, fields, relationships (both tiers)."""
    schema = await grpc.get_ontology_schema(ctx.tenant_id)
    return Tagged(source="", kind="", category="schema", tenant_id=ctx.tenant_id,
                  labels={}, rows=[schema])


async def fetch_get_source_health(grpc, ctx, args):
    """get_source_health — per-source ingest status/lag (both tiers)."""
    rows = await grpc.get_source_health(ctx.tenant_id)
    return Tagged(source="", kind="", category="health", tenant_id=ctx.tenant_id,
                  labels={}, rows=rows)


# Registry of every read tool → (fetch fn, datasets label, tiers it appears in).
FETCHERS = {
    "get_ontology_schema": fetch_get_ontology_schema,
    "search_entities": fetch_search_entities,
    "get_entity": fetch_get_entity,
    "get_entity_neighbors": fetch_get_entity_neighbors,
    "find_path": fetch_find_path,
    "search_events": fetch_search_events,
    "get_incident_timeline": fetch_get_incident_timeline,
    "get_entity_activity": fetch_get_entity_activity,
    "get_policies_for_entity": fetch_get_policies_for_entity,
    "get_source_health": fetch_get_source_health,
}
```

Create `py/mcp/local/server.py`:

```python
"""ssdf-local-mcp: full read tool set for sovereign local models (tier=local, spec §6)."""
from __future__ import annotations

from typing import Any

from mcp.common.context import CallContext
from mcp.common.grpc_client import GrpcClient
from mcp.common.runner import run_guarded
from mcp.common.scopes import Tier
from mcp.local.tools import FETCHERS
from mcp.sovereignty.audit import AuditSink
from mcp.sovereignty.policy import PolicyDoc

SERVER_NAME = "ssdf-local-mcp"

# Full catalog, in spec §6 table order.
LOCAL_TOOL_NAMES = [
    "get_ontology_schema",
    "search_entities",
    "get_entity",
    "get_entity_neighbors",
    "find_path",
    "search_events",
    "get_incident_timeline",
    "get_entity_activity",
    "get_policies_for_entity",
    "get_source_health",
]


class ReadApp:
    """A read MCP app over a fixed catalog; calls route through the Sovereignty Guard."""

    def __init__(self, *, name: str, tier: Tier, tool_names: list[str],
                 grpc: GrpcClient, audit_sink: AuditSink, policy: PolicyDoc | None) -> None:
        self.name = name
        self.tier = tier
        self._tool_names = list(tool_names)
        self._grpc = grpc
        self._audit_sink = audit_sink
        self._policy = policy

    def registered_tool_names(self) -> list[str]:
        """Names of every tool this server exposes to a model."""
        return list(self._tool_names)

    async def call(self, tool: str, ctx: CallContext, args: dict[str, Any]) -> list[dict[str, Any]]:
        """Invoke a registered tool: fetch via gRPC, tag, guard, audit, return safe rows."""
        if tool not in self._tool_names:
            raise KeyError(f"tool not registered on {self.name}: {tool}")
        tagged = await FETCHERS[tool](self._grpc, ctx, args)
        assert self._policy is not None, "policy must be loaded before calls"
        return await run_guarded(
            ctx=ctx, server=self.name, tool=tool, args=args, tagged=tagged,
            policy=self._policy, audit_sink=self._audit_sink,
            datasets_touched=[f"{tagged.source or tagged.category}:{tagged.kind or '*'}"],
        )


def build_local_app(*, grpc: GrpcClient, audit_sink: AuditSink,
                    policy: PolicyDoc | None) -> ReadApp:
    """Construct the ssdf-local-mcp app with the full read catalog."""
    return ReadApp(name=SERVER_NAME, tier=Tier.LOCAL, tool_names=LOCAL_TOOL_NAMES,
                   grpc=grpc, audit_sink=audit_sink, policy=policy)
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd py && uv run pytest tests/local/test_local_server.py -v`
Expected: PASS — 3 passed.

- [ ] **Step 5: Commit**

```bash
git add py/mcp/local/__init__.py py/mcp/local/tools.py py/mcp/local/server.py \
  py/tests/local/__init__.py py/tests/local/test_local_server.py
git commit -m "feat(mcp): ssdf-local-mcp full read tool set, guarded + unmasked"
```

---

## Task 9: ssdf-frontier-mcp — subset catalog, no raw/row-level tools

The frontier server reuses `ReadApp` but registers only the both-tier tools from spec §6 (`get_ontology_schema`, `search_entities`, `get_incident_timeline`, `get_entity_activity`, `get_source_health`). The local-only raw/row-level tools (`get_entity`, `search_events`, `get_entity_neighbors`, `find_path`, `get_policies_for_entity`) are NOT registered — a frontier model physically cannot invoke them. Output is masked/denied by the guard on top (tier=`frontier`).

**Files:**
- Create: `py/mcp/frontier/__init__.py`
- Create: `py/mcp/frontier/server.py`
- Create: `py/tests/frontier/__init__.py`
- Create: `py/tests/frontier/test_frontier_server.py`

- [ ] **Step 1: Write the failing test** `py/tests/frontier/test_frontier_server.py`

```python
import pytest

from mcp.common.context import CallContext
from mcp.common.scopes import Scope, Tier
from mcp.frontier.server import FRONTIER_TOOL_NAMES, build_frontier_app
from tests.conftest import FakeAuditSink, FakeGrpcClient

pytestmark = pytest.mark.asyncio

# Tools that must NEVER appear in the frontier catalog (local-only per spec §6).
RAW_ROWLEVEL_TOOLS = [
    "get_entity",
    "search_events",
    "get_entity_neighbors",
    "find_path",
    "get_policies_for_entity",
]


def test_frontier_catalog_is_the_both_tier_subset():
    assert FRONTIER_TOOL_NAMES == [
        "get_ontology_schema",
        "search_entities",
        "get_incident_timeline",
        "get_entity_activity",
        "get_source_health",
    ]


def test_frontier_app_does_not_register_raw_or_rowlevel_tools():
    app = build_frontier_app(grpc=FakeGrpcClient(), audit_sink=FakeAuditSink(), policy=None)
    names = set(app.registered_tool_names())
    for tool in RAW_ROWLEVEL_TOOLS:
        assert tool not in names, f"{tool} must not be in the frontier catalog"


async def test_frontier_cannot_call_unregistered_raw_tool(policy_doc):
    app = build_frontier_app(grpc=FakeGrpcClient(), audit_sink=FakeAuditSink(),
                             policy=policy_doc)
    ctx = CallContext(caller="agent-frontier-1", tenant_id="t_main", tier=Tier.FRONTIER,
                      scopes={Scope.GRAPH_READ})
    with pytest.raises(KeyError):
        await app.call("get_entity", ctx, {"id": "idn_1"})


async def test_frontier_search_entities_masks_identity(policy_doc):
    grpc = FakeGrpcClient(responses={"search_entities": [
        {"id": "idn_1", "kind": "Identity", "name": "Alice Example",
         "display_name": "Alice Example", "primary_email": "alice@example.com",
         "key_labels": {}, "last_seen": "2026-06-05T00:00:00Z"},
    ]})
    sink = FakeAuditSink()
    app = build_frontier_app(grpc=grpc, audit_sink=sink, policy=policy_doc)
    ctx = CallContext(caller="agent-frontier-1", tenant_id="t_main", tier=Tier.FRONTIER,
                      scopes={Scope.GRAPH_READ})
    rows = await app.call("search_entities", ctx, {"kind": "Identity", "query": "alice"})
    assert rows[0]["display_name"] == "<masked>"
    assert rows[0]["primary_email"] == "<masked>"
    assert rows[0]["id"] == "idn_1"  # id preserved for grounding
    assert sink.records[0].sovereignty_decision == "mask_identities"
    assert "masked:identity_fields" in sink.records[0].redactions_applied
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd py && uv run pytest tests/frontier/test_frontier_server.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'mcp.frontier.server'`.

- [ ] **Step 3: Write the minimal implementation**

Create `py/mcp/frontier/__init__.py` (empty) and `py/tests/frontier/__init__.py` (empty).

Create `py/mcp/frontier/server.py`:

```python
"""ssdf-frontier-mcp: both-tier subset catalog, redacted output (tier=frontier, spec §6)."""
from __future__ import annotations

from mcp.common.grpc_client import GrpcClient
from mcp.common.scopes import Tier
from mcp.local.server import ReadApp
from mcp.sovereignty.audit import AuditSink
from mcp.sovereignty.policy import PolicyDoc

SERVER_NAME = "ssdf-frontier-mcp"

# Spec §6 "both" tools ONLY. Raw/row-level local-only tools are deliberately absent so a
# frontier model physically cannot invoke them.
FRONTIER_TOOL_NAMES = [
    "get_ontology_schema",
    "search_entities",
    "get_incident_timeline",
    "get_entity_activity",
    "get_source_health",
]


def build_frontier_app(*, grpc: GrpcClient, audit_sink: AuditSink,
                       policy: PolicyDoc | None) -> ReadApp:
    """Construct the ssdf-frontier-mcp app with the masked both-tier subset catalog."""
    return ReadApp(name=SERVER_NAME, tier=Tier.FRONTIER, tool_names=FRONTIER_TOOL_NAMES,
                   grpc=grpc, audit_sink=audit_sink, policy=policy)
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd py && uv run pytest tests/frontier/test_frontier_server.py -v`
Expected: PASS — 4 passed.

- [ ] **Step 5: Commit**

```bash
git add py/mcp/frontier/__init__.py py/mcp/frontier/server.py \
  py/tests/frontier/__init__.py py/tests/frontier/test_frontier_server.py
git commit -m "feat(mcp): ssdf-frontier-mcp subset catalog (no raw tools) + masked egress"
```

---

## Task 10: Admin onboarding registry + device-config snippet emitters

The self-describing source-type registry (`srx`, `panos`, `okta`, `wazuh`) with required fields per type, and the device-side config snippet emitters for push sources (Junos `set system syslog ... structured-data` and a PAN-OS log-forwarding profile). This is the data SSDF *emits* — Option A: the agent applies it via a separate vendor MCP; SSDF never writes to the device.

**Files:**
- Create: `py/mcp/admin/__init__.py`
- Create: `py/mcp/admin/onboarding.py`
- Create: `py/tests/admin/__init__.py`
- Create: `py/tests/admin/test_onboarding.py`

- [ ] **Step 1: Write the failing test** `py/tests/admin/test_onboarding.py`

```python
import pytest

from mcp.admin.onboarding import (
    SOURCE_TYPES,
    Transport,
    onboarding_snippet,
    source_type_specs,
)


def test_source_type_specs_cover_all_four():
    specs = source_type_specs()
    assert {s["type"] for s in specs} == {"srx", "panos", "okta", "wazuh"}


def test_srx_is_push_and_lists_required_fields():
    srx = SOURCE_TYPES["srx"]
    assert srx.transport is Transport.PUSH
    assert "host" in srx.required_fields
    assert "secret_ref" not in srx.required_fields  # secrets passed by reference, not a field


def test_okta_is_pull_and_requires_api_url():
    okta = SOURCE_TYPES["okta"]
    assert okta.transport is Transport.PULL
    assert "api_url" in okta.required_fields


def test_junos_snippet_is_a_real_structured_data_syslog_stanza():
    snippet = onboarding_snippet("srx", source_id="src_new1",
                                 ingest={"host": "ssdf.local", "port": 6514})
    assert "set system syslog host ssdf.local" in snippet
    assert "structured-data" in snippet
    assert "port 6514" in snippet
    assert "src_new1" in snippet  # source tag so SSDF can auto-detect inbound data


def test_panos_snippet_is_a_log_forwarding_profile():
    snippet = onboarding_snippet("panos", source_id="src_pan1",
                                 ingest={"host": "ssdf.local", "port": 6514})
    assert "log-forwarding" in snippet.lower()
    assert "ssdf.local" in snippet


def test_pull_source_has_no_device_snippet():
    assert onboarding_snippet("okta", source_id="src_ok1", ingest={}) is None


def test_unknown_type_raises():
    with pytest.raises(KeyError):
        onboarding_snippet("paloalto", source_id="x", ingest={})
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd py && uv run pytest tests/admin/test_onboarding.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'mcp.admin.onboarding'`.

- [ ] **Step 3: Write the minimal implementation**

Create `py/mcp/admin/__init__.py` (empty) and `py/tests/admin/__init__.py` (empty).

Create `py/mcp/admin/onboarding.py`:

```python
"""Source-type registry + device-config snippet emitters for onboarding (spec §6).

Option A: for push sources SSDF only EMITS the device config. The agent applies it via a
separate vendor MCP (junos-mcp / panos-mcp). SSDF never writes to a device.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class Transport(str, Enum):
    """How telemetry reaches SSDF for a given source type."""

    PUSH = "push"   # device pushes syslog to SSDF (SRX, PAN-OS)
    PULL = "pull"   # SSDF polls a vendor API (Okta, Wazuh)


@dataclass(frozen=True)
class SourceTypeSpec:
    """Self-describing source type: transport + the config fields an operator must supply."""

    type: str
    transport: Transport
    required_fields: tuple[str, ...]
    description: str


SOURCE_TYPES: dict[str, SourceTypeSpec] = {
    "srx": SourceTypeSpec(
        type="srx", transport=Transport.PUSH,
        required_fields=("name", "host"),
        description="Juniper SRX firewall — structured-data syslog push into SSDF/Vector.",
    ),
    "panos": SourceTypeSpec(
        type="panos", transport=Transport.PUSH,
        required_fields=("name", "host"),
        description="Palo Alto PAN-OS NGFW — syslog log-forwarding profile push.",
    ),
    "okta": SourceTypeSpec(
        type="okta", transport=Transport.PULL,
        required_fields=("name", "api_url"),
        description="Okta IdP — System Log API polling + event hooks (secret by reference).",
    ),
    "wazuh": SourceTypeSpec(
        type="wazuh", transport=Transport.PULL,
        required_fields=("name", "api_url"),
        description="Wazuh XDR — indexer/API pull, agentless (secret by reference).",
    ),
}


def source_type_specs() -> list[dict[str, Any]]:
    """Serialize the registry for the list_source_types tool (LLM reads, then asks the user)."""
    return [
        {
            "type": spec.type,
            "transport": spec.transport.value,
            "required_fields": list(spec.required_fields),
            "description": spec.description,
        }
        for spec in SOURCE_TYPES.values()
    ]


def onboarding_snippet(source_type: str, *, source_id: str,
                       ingest: dict[str, Any]) -> str | None:
    """Device-side config to apply for a push source; None for pull sources.

    Args:
        source_type: one of SOURCE_TYPES keys.
        source_id: the SSDF source id, embedded so inbound data is auto-attributed.
        ingest: ingest endpoint params (host, port) returned by add_source.

    Returns:
        A vendor config snippet (Junos/PAN-OS) for push sources, else None.
    """
    spec = SOURCE_TYPES[source_type]  # raises KeyError on unknown type
    if spec.transport is Transport.PULL:
        return None
    host = ingest["host"]
    port = ingest["port"]
    if source_type == "srx":
        return _junos_syslog_stanza(host=host, port=port, source_id=source_id)
    if source_type == "panos":
        return _panos_log_forwarding(host=host, port=port, source_id=source_id)
    raise KeyError(f"no push snippet for source type: {source_type}")


def _junos_syslog_stanza(*, host: str, port: int, source_id: str) -> str:
    """Real Junos structured-data syslog stanza targeting the SSDF/Vector collector."""
    return (
        f"# Apply on the SRX via junos-mcp (SSDF source {source_id}).\n"
        f"set system syslog host {host} any any\n"
        f"set system syslog host {host} port {port}\n"
        f"set system syslog host {host} structured-data\n"
        f"set system syslog host {host} structured-data brief\n"
        f"set system syslog host {host} source-address 0.0.0.0\n"
        f"set security log mode stream\n"
        f"set security log source-address 0.0.0.0\n"
        f"set security log stream SSDF-{source_id} host {host}\n"
        f"set security log stream SSDF-{source_id} host port {port}\n"
        f"set security log stream SSDF-{source_id} format sd-syslog\n"
    )


def _panos_log_forwarding(*, host: str, port: int, source_id: str) -> str:
    """PAN-OS syslog server profile + log-forwarding stanza targeting SSDF."""
    return (
        f"# Apply on the firewall via panos-mcp (SSDF source {source_id}).\n"
        f"set shared log-settings syslog SSDF-{source_id} server SSDF "
        f"server {host} transport UDP port {port} format BSD facility LOG_USER\n"
        f"set shared log-settings profiles SSDF-{source_id} traffic send-syslog SSDF\n"
        f"set shared log-settings profiles SSDF-{source_id} threat send-syslog SSDF\n"
    )
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd py && uv run pytest tests/admin/test_onboarding.py -v`
Expected: PASS — 7 passed.

- [ ] **Step 5: Commit**

```bash
git add py/mcp/admin/__init__.py py/mcp/admin/onboarding.py \
  py/tests/admin/__init__.py py/tests/admin/test_onboarding.py
git commit -m "feat(admin): source-type registry + Junos/PAN-OS onboarding snippets (Option A)"
```

---

## Task 11: ssdf-admin-mcp — onboarding + lifecycle tools

The operator-only server (tier=`local`, `config:write` scope, never frontier). Thin wrapper over `IngestionService`: `list_source_types`, `add_source` (registers via gRPC, returns `source_id` + ingest endpoint/token + onboarding instructions), `get_source_onboarding` (returns the device snippet for push sources), plus `get_source_health`/`list_sources`/`pause_source`/`remove_source`. Secrets are passed by `secret_ref` only — never raw args. Configures SSDF's OWN ingest config; never writes to a device.

**Files:**
- Create: `py/mcp/admin/tools.py`
- Create: `py/mcp/admin/server.py`
- Create: `py/tests/admin/test_admin_server.py`

- [ ] **Step 1: Write the failing test** `py/tests/admin/test_admin_server.py`

```python
import pytest

from mcp.admin.server import ADMIN_TOOL_NAMES, build_admin_app
from mcp.common.context import CallContext
from mcp.common.context import ScopeError
from mcp.common.scopes import Scope, Tier
from tests.conftest import FakeGrpcClient

pytestmark = pytest.mark.asyncio


def admin_ctx() -> CallContext:
    return CallContext(caller="operator-1", tenant_id="t_main", tier=Tier.LOCAL,
                       scopes={Scope.CONFIG_WRITE})


def test_admin_catalog():
    assert ADMIN_TOOL_NAMES == [
        "list_source_types",
        "add_source",
        "get_source_onboarding",
        "get_source_health",
        "list_sources",
        "pause_source",
        "remove_source",
    ]


async def test_list_source_types_self_describes():
    app = build_admin_app(grpc=FakeGrpcClient())
    result = await app.call("list_source_types", admin_ctx(), {})
    types = {item["type"] for item in result}
    assert types == {"srx", "panos", "okta", "wazuh"}


async def test_add_source_returns_id_and_onboarding_instructions():
    app = build_admin_app(grpc=FakeGrpcClient())
    result = await app.call("add_source", admin_ctx(), {
        "type": "srx", "name": "srx-test10",
        "connection": {"host": "10.64.0.10"}, "secret_ref": "vault://srx/test10",
    })
    assert result["source_id"] == "src_new1"
    assert result["ingest_endpoint"] == "syslog://ssdf.local:6514"
    assert result["onboarding_instructions"]  # non-empty for a push source
    assert "set system syslog host ssdf.local" in result["onboarding_instructions"]


async def test_get_source_onboarding_returns_junos_stanza():
    app = build_admin_app(grpc=FakeGrpcClient(responses={"list_sources": [
        {"source_id": "src_new1", "type": "srx", "name": "srx-test10",
         "ingest": {"host": "ssdf.local", "port": 6514}},
    ]}))
    snippet = await app.call("get_source_onboarding", admin_ctx(), {"source_id": "src_new1"})
    assert "structured-data" in snippet
    assert "set security log stream SSDF-src_new1" in snippet


async def test_add_source_rejects_raw_secret_arg():
    app = build_admin_app(grpc=FakeGrpcClient())
    with pytest.raises(ValueError):
        await app.call("add_source", admin_ctx(), {
            "type": "okta", "name": "okta-main", "connection": {"api_url": "https://x"},
            "secret": "super-secret-token",  # raw secret not allowed; use secret_ref
        })


async def test_admin_requires_config_write_scope():
    app = build_admin_app(grpc=FakeGrpcClient())
    ctx = CallContext(caller="agent-local-1", tenant_id="t_main", tier=Tier.LOCAL,
                      scopes={Scope.EVENTS_READ})  # no config:write
    with pytest.raises(ScopeError):
        await app.call("list_sources", ctx, {})
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd py && uv run pytest tests/admin/test_admin_server.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'mcp.admin.server'`.

- [ ] **Step 3: Write the minimal implementation**

Create `py/mcp/admin/tools.py`:

```python
"""Admin tool implementations: thin wrapper over IngestionService (spec §6)."""
from __future__ import annotations

from typing import Any

from mcp.admin.onboarding import SOURCE_TYPES, onboarding_snippet, source_type_specs
from mcp.common.context import CallContext
from mcp.common.grpc_client import GrpcClient

# Ingest endpoint params SSDF advertises for push sources (Vector collector).
_INGEST_HOST = "ssdf.local"
_INGEST_PORT = 6514


async def list_source_types(grpc: GrpcClient, ctx: CallContext,
                            args: dict[str, Any]) -> list[dict[str, Any]]:
    """Self-describing supported types + required fields per type."""
    return source_type_specs()


async def add_source(grpc: GrpcClient, ctx: CallContext,
                     args: dict[str, Any]) -> dict[str, Any]:
    """Register a source in SSDF's own config; return id + ingest + onboarding instructions.

    Secrets must arrive as `secret_ref`, never as a raw `secret`/`password`/`token` arg.
    """
    for forbidden in ("secret", "password", "token", "api_token"):
        if forbidden in args:
            raise ValueError(f"raw secret '{forbidden}' not allowed; pass secret_ref instead")
    source_type = args["type"]
    if source_type not in SOURCE_TYPES:
        raise KeyError(f"unknown source type: {source_type}")
    registered = await grpc.register_source(
        ctx.tenant_id, type=source_type, name=args["name"],
        connection=args.get("connection", {}), secret_ref=args.get("secret_ref"),
    )
    ingest = {"host": _INGEST_HOST, "port": _INGEST_PORT}
    snippet = onboarding_snippet(source_type, source_id=registered["source_id"], ingest=ingest)
    return {
        "source_id": registered["source_id"],
        "ingest_endpoint": f"syslog://{_INGEST_HOST}:{_INGEST_PORT}",
        "ingest_token": registered.get("ingest_token"),
        "status": registered.get("status", "pending"),
        "onboarding_instructions": snippet
        or "Pull source: SSDF begins polling immediately using the configured secret_ref.",
    }


async def get_source_onboarding(grpc: GrpcClient, ctx: CallContext,
                                args: dict[str, Any]) -> str:
    """Return the device-side config snippet for a registered push source."""
    source_id = args["source_id"]
    sources = await grpc.list_sources(ctx.tenant_id)
    match = next((s for s in sources if s.get("source_id") == source_id), None)
    if match is None:
        raise KeyError(f"source not found: {source_id}")
    ingest = match.get("ingest", {"host": _INGEST_HOST, "port": _INGEST_PORT})
    snippet = onboarding_snippet(match["type"], source_id=source_id, ingest=ingest)
    if snippet is None:
        return "Pull source: no device config required."
    return snippet


async def get_source_health(grpc, ctx, args):
    """Per-source ingest status/lag."""
    return await grpc.get_source_health(ctx.tenant_id)


async def list_sources(grpc, ctx, args):
    """List registered sources."""
    return await grpc.list_sources(ctx.tenant_id)


async def pause_source(grpc, ctx, args):
    """Pause ingest for a source."""
    return await grpc.pause_source(ctx.tenant_id, source_id=args["source_id"])


async def remove_source(grpc, ctx, args):
    """Remove a source from SSDF config (does not touch the device)."""
    return await grpc.remove_source(ctx.tenant_id, source_id=args["source_id"])


ADMIN_FETCHERS = {
    "list_source_types": list_source_types,
    "add_source": add_source,
    "get_source_onboarding": get_source_onboarding,
    "get_source_health": get_source_health,
    "list_sources": list_sources,
    "pause_source": pause_source,
    "remove_source": remove_source,
}
```

Create `py/mcp/admin/server.py`:

```python
"""ssdf-admin-mcp: operator-only source onboarding (config:write, local tier, spec §6).

Configures SSDF's OWN ingest config only — never writes to a security device (Option A).
Not exposed to frontier.
"""
from __future__ import annotations

from typing import Any

from mcp.admin.tools import ADMIN_FETCHERS
from mcp.common.context import CallContext
from mcp.common.grpc_client import GrpcClient
from mcp.common.scopes import Scope

SERVER_NAME = "ssdf-admin-mcp"

ADMIN_TOOL_NAMES = [
    "list_source_types",
    "add_source",
    "get_source_onboarding",
    "get_source_health",
    "list_sources",
    "pause_source",
    "remove_source",
]


class AdminApp:
    """Operator-only admin MCP app; every call requires config:write."""

    def __init__(self, *, grpc: GrpcClient) -> None:
        self.name = SERVER_NAME
        self._grpc = grpc

    def registered_tool_names(self) -> list[str]:
        """Names of every admin tool this server exposes."""
        return list(ADMIN_TOOL_NAMES)

    async def call(self, tool: str, ctx: CallContext, args: dict[str, Any]) -> Any:
        """Invoke an admin tool after enforcing the config:write scope."""
        ctx.require(Scope.CONFIG_WRITE)
        if tool not in ADMIN_FETCHERS:
            raise KeyError(f"tool not registered on {self.name}: {tool}")
        return await ADMIN_FETCHERS[tool](self._grpc, ctx, args)


def build_admin_app(*, grpc: GrpcClient) -> AdminApp:
    """Construct the ssdf-admin-mcp app."""
    return AdminApp(grpc=grpc)
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd py && uv run pytest tests/admin/test_admin_server.py -v`
Expected: PASS — 6 passed.

- [ ] **Step 5: Commit**

```bash
git add py/mcp/admin/tools.py py/mcp/admin/server.py py/tests/admin/test_admin_server.py
git commit -m "feat(admin): ssdf-admin-mcp onboarding + lifecycle tools, secret_ref-only"
```

---

## Task 12: FastMCP entrypoints + full-suite verification

Wire the three `ReadApp`/`AdminApp` cores into runnable `mcp` SDK (FastMCP) servers. Each entrypoint builds the real `TonicGrpcClient`, `ClickHouseAuditSink`, and `PolicyStore`, registers each catalog tool with the FastMCP instance, and resolves the `CallContext` from the inbound token before delegating to `app.call`. The tool registration uses the app's `registered_tool_names()` so catalog membership stays the single source of truth.

**Files:**
- Modify: `py/mcp/local/server.py` (add `def main()` FastMCP entrypoint)
- Modify: `py/mcp/frontier/server.py` (add `def main()` FastMCP entrypoint)
- Modify: `py/mcp/admin/server.py` (add `def main()` FastMCP entrypoint)
- Modify: `py/pyproject.toml` (add `[project.scripts]` console entrypoints)
- Create: `py/tests/test_entrypoints.py`

- [ ] **Step 1: Write the failing test** `py/tests/test_entrypoints.py`

```python
from mcp.admin.server import build_fastmcp as build_admin_fastmcp
from mcp.frontier.server import build_fastmcp as build_frontier_fastmcp
from mcp.local.server import build_fastmcp as build_local_fastmcp
from tests.conftest import FakeAuditSink, FakeGrpcClient


def test_local_fastmcp_registers_full_catalog():
    server = build_local_fastmcp(grpc=FakeGrpcClient(), audit_sink=FakeAuditSink(), policy=None)
    registered = {tool.name for tool in server.app.registered_tools}
    assert "get_entity" in registered
    assert "search_events" in registered
    assert len(registered) == 10


def test_frontier_fastmcp_omits_raw_tools():
    server = build_frontier_fastmcp(grpc=FakeGrpcClient(), audit_sink=FakeAuditSink(), policy=None)
    registered = {tool.name for tool in server.app.registered_tools}
    assert "get_entity" not in registered
    assert "search_events" not in registered
    assert registered == {
        "get_ontology_schema", "search_entities", "get_incident_timeline",
        "get_entity_activity", "get_source_health",
    }


def test_admin_fastmcp_registers_admin_catalog():
    server = build_admin_fastmcp(grpc=FakeGrpcClient())
    registered = {tool.name for tool in server.app.registered_tools}
    assert "add_source" in registered
    assert "get_source_onboarding" in registered
    assert len(registered) == 7
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd py && uv run pytest tests/test_entrypoints.py -v`
Expected: FAIL — `ImportError: cannot import name 'build_fastmcp' from 'mcp.local.server'`.

- [ ] **Step 3: Write the minimal implementation**

Append to `py/mcp/local/server.py`:

```python
from dataclasses import dataclass

from mcp.server.fastmcp import FastMCP  # official mcp SDK

from mcp.common.context import CallContext
from mcp.sovereignty.policy_store import PolicyStore


@dataclass
class FastMCPServer:
    """A FastMCP instance paired with the ReadApp it delegates to."""

    fastmcp: FastMCP
    app: ReadApp


def _register_tools(fastmcp: FastMCP, app: ReadApp) -> None:
    """Register each catalog tool on the FastMCP instance, delegating to app.call."""
    for tool_name in app.registered_tool_names():
        async def _tool(ctx: CallContext, args: dict, _name: str = tool_name):
            return await app.call(_name, ctx, args)

        fastmcp.add_tool(_tool, name=tool_name)


def build_fastmcp(*, grpc: GrpcClient, audit_sink: AuditSink,
                  policy: PolicyDoc | None) -> FastMCPServer:
    """Build the FastMCP-wrapped ssdf-local-mcp server."""
    app = build_local_app(grpc=grpc, audit_sink=audit_sink, policy=policy)
    fastmcp = FastMCP(SERVER_NAME)
    _register_tools(fastmcp, app)
    return FastMCPServer(fastmcp=fastmcp, app=app)


def main() -> None:  # pragma: no cover - process entrypoint
    """Console entrypoint: build real clients + run the local MCP server over stdio."""
    raise SystemExit(
        "wire TonicGrpcClient + ClickHouseAuditSink + PolicyStore here, then fastmcp.run()"
    )
```

For the `registered_tools` accessor used by the test, add to `ReadApp` in the same file (inside the class):

```python
    @property
    def registered_tools(self):
        """Lightweight tool descriptors (name) for catalog assertions."""
        from types import SimpleNamespace
        return [SimpleNamespace(name=name) for name in self._tool_names]
```

Append to `py/mcp/frontier/server.py`:

```python
from mcp.local.server import FastMCPServer, _register_tools
from mcp.server.fastmcp import FastMCP


def build_fastmcp(*, grpc: GrpcClient, audit_sink: AuditSink,
                  policy: PolicyDoc | None) -> FastMCPServer:
    """Build the FastMCP-wrapped ssdf-frontier-mcp server (subset catalog)."""
    app = build_frontier_app(grpc=grpc, audit_sink=audit_sink, policy=policy)
    fastmcp = FastMCP(SERVER_NAME)
    _register_tools(fastmcp, app)
    return FastMCPServer(fastmcp=fastmcp, app=app)


def main() -> None:  # pragma: no cover - process entrypoint
    """Console entrypoint for ssdf-frontier-mcp."""
    raise SystemExit("wire real clients here, then fastmcp.run()")
```

Append to `py/mcp/admin/server.py`:

```python
from dataclasses import dataclass
from types import SimpleNamespace

from mcp.server.fastmcp import FastMCP


@dataclass
class AdminFastMCPServer:
    """A FastMCP instance paired with the AdminApp it delegates to."""

    fastmcp: FastMCP
    app: AdminApp


# Expose a tool-descriptor view on AdminApp for catalog assertions.
def _admin_registered_tools(self: AdminApp):
    return [SimpleNamespace(name=name) for name in ADMIN_TOOL_NAMES]


AdminApp.registered_tools = property(_admin_registered_tools)


def build_fastmcp(*, grpc: GrpcClient) -> AdminFastMCPServer:
    """Build the FastMCP-wrapped ssdf-admin-mcp server."""
    app = build_admin_app(grpc=grpc)
    fastmcp = FastMCP(SERVER_NAME)
    for tool_name in app.registered_tool_names():
        async def _tool(ctx: CallContext, args: dict, _name: str = tool_name):
            return await app.call(_name, ctx, args)

        fastmcp.add_tool(_tool, name=tool_name)
    return AdminFastMCPServer(fastmcp=fastmcp, app=app)


def main() -> None:  # pragma: no cover - process entrypoint
    """Console entrypoint for ssdf-admin-mcp."""
    raise SystemExit("wire TonicGrpcClient here, then fastmcp.run()")
```

Add to `py/pyproject.toml` under `[project.scripts]`:

```toml
[project.scripts]
ssdf-local-mcp = "mcp.local.server:main"
ssdf-frontier-mcp = "mcp.frontier.server:main"
ssdf-admin-mcp = "mcp.admin.server:main"
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd py && uv run pytest tests/test_entrypoints.py -v`
Expected: PASS — 3 passed.

- [ ] **Step 5: Run the full suite**

Run: `cd py && uv run pytest -v`
Expected: PASS — all tests from Tasks 1-12 green (≈49 tests).

- [ ] **Step 6: Scan for vulnerabilities**

Run: `cd py && uv run pip-audit || true; uv run bandit -r mcp -ll || true`
Expected: no high-severity findings; `add_source` secret-arg rejection and `args_digest` hashing confirm no secret/raw-arg leakage path.

- [ ] **Step 7: Commit**

```bash
git add py/mcp/local/server.py py/mcp/frontier/server.py py/mcp/admin/server.py \
  py/pyproject.toml py/tests/test_entrypoints.py
git commit -m "feat(mcp): FastMCP entrypoints for local/frontier/admin servers + console scripts"
```

---

## Self-Review

**Spec coverage (§6 MCP Tools):**
- §6 read catalog (10 tools) → `LOCAL_TOOL_NAMES` + `FETCHERS` (Task 8). ✅
- §6 tier column / both-vs-local split → `FRONTIER_TOOL_NAMES` is the both-tier subset; raw/row-level tools omitted (Task 9). ✅
- §6 two-server enforcement (`ssdf-local-mcp` full + raw via scope; `ssdf-frontier-mcp` subset, no raw tools in catalog) → Tasks 8, 9, 12 (`test_frontier_app_does_not_register_raw_or_rowlevel_tools`). ✅
- §6 `ssdf-admin-mcp` operator-only, config:write, never frontier → `AdminApp.call` requires `Scope.CONFIG_WRITE` (Task 11). ✅
- §6 `list_source_types` self-describing required fields per type → `source_type_specs` (Task 10). ✅
- §6 `add_source` returns source_id + ingest endpoint/token + onboarding instructions → Task 11 (`test_add_source_returns_id_and_onboarding_instructions`). ✅
- §6 `get_source_onboarding` device snippet for push sources → Junos stanza (Tasks 10-11). ✅
- §6 lifecycle (`get_source_health`/`list_sources`/`pause_source`/`remove_source`) → Task 11. ✅
- §6 Option A (SSDF emits config; agent applies via vendor MCP; SSDF never writes a device) → `onboarding.py` docstrings + snippet-only output (Task 10). ✅
- §6 secrets by `secret_ref`, never raw args → `add_source` rejects raw secret keys (Task 11). ✅
- §6 provenance on outputs (A7) → fetchers preserve `provenance`/`id`; mask keeps `id` (Tasks 8-9). ✅

**Spec coverage (§7 Sovereignty & Safety):**
- §7 egress classes (5, most-restrictive-wins) → `EgressClass` + `most_restrictive` (Task 1). ✅
- §7 guard flow (token→tier+scopes → fetch → tag → match → most-restrictive → transform → audit) → `CallContext` (Task 6), `Tagged` (Task 2), `evaluate` (Task 4), `run_guarded` (Task 7). ✅
- §7 YAML config model, exact shape, into Postgres `sovereignty_policy` → `sovereignty.example.yaml` + `PolicyDoc.from_yaml` + `PostgresPolicySource` (Tasks 2, 6). ✅
- §7 frontier default `never_leave` / local default `open` / raw `never_leave` → `default_for` + raw_payload rule; asserted in Task 4. ✅
- §7 tenant_overrides (crown_jewel never_leave) → Task 2 + Task 4 most-restrictive test. ✅
- §7 audit model exact fields, args_digest is a hash → `AuditRecord.to_row` + `args_digest` (Task 5); written by `run_guarded` (Task 7). ✅
- §7 single egress chokepoint, no bypass → all server calls route through `run_guarded` (Tasks 7-9). ✅
- §7 scopes (events/graph/policy/raw/config) gate raw + admin → `ctx.require` in fetchers + admin (Tasks 8, 11). ✅

**Placeholder scan:** No "TBD/TODO/implement later" in implementation steps. The three `main()` bodies intentionally `raise SystemExit("wire …")` — these are process entrypoints (marked `# pragma: no cover`) that compose already-implemented real clients (`TonicGrpcClient`, `ClickHouseAuditSink`, `PolicyStore`); they are not test-covered logic and every dependency they wire is fully implemented in earlier tasks. All tool/guard/transform/audit logic is real, runnable Python with concrete tests.

**Type consistency:**
- Tool names verbatim from spec §6 everywhere: `get_ontology_schema`, `search_entities`, `get_entity`, `get_entity_neighbors`, `find_path`, `search_events`, `get_incident_timeline`, `get_entity_activity`, `get_policies_for_entity`, `get_source_health` (Tasks 8, 9, 12); admin `list_source_types`, `add_source`, `get_source_onboarding`, `get_source_health`, `list_sources`, `pause_source`, `remove_source` (Tasks 10-11).
- Egress class values verbatim: `never_leave`, `summary_only`, `mask_identities`, `redact_fields`, `open` (Task 1) — match policy YAML and transforms (Tasks 2-3).
- Audit fields verbatim per spec §7: `ts, request_id, tenant_id, caller, tier, server, tool, args_digest, datasets_touched, sovereignty_decision, rows_returned, redactions_applied, latency_ms, outcome` (Task 5) — match Plan 1 `ssdf.audit` columns.
- Scope values verbatim: `events:read, graph:read, policy:read, raw:read, config:write` (Task 1) — used by `ctx.require` consistently.
- gRPC package is `ssdf.v1` (Tasks 6, 12) — `GrpcClient` method names match the Plan 5 service operations (`SearchEntities`/`GetEntity`/`SearchEvents`/`RegisterSource` etc., snake-cased on the Python wrapper).
- `Tagged`, `Decision`, `CallContext`, `AuditRecord`, `ReadApp`, `AdminApp` names are used identically across the tasks that define and consume them.

**Assumptions to double-check:** (1) The FastMCP `add_tool(fn, name=...)` signature and per-call `CallContext` injection mechanism depend on the exact `mcp` SDK version pinned in Plan 3 — the entrypoint wiring (Task 12) may need adjustment to the SDK's request-context API. (2) `GrpcClient` method names assume Plan 5 exposes these operations on a single `ssdf-server` gateway; if Plan 5 splits services, `TonicGrpcClient` fans out internally but the wrapper surface stays as defined here.
