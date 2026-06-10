# SSDF M7b — Public MCP Split Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a second, physically isolated **public-tier** mode to the `ssdf-mcp-query` server that exposes only `shareable`-classed tools backed by ClickHouse `SQL SECURITY DEFINER` views, enforced at the grant floor so the public process cannot read sovereign data.

**Architecture:** Reuse the existing `services/mcp-query` package. A pure classification helper computes the public tool set; `graphstore.py` gains a `schema` parameter so the public build reads `ssdf_public.*` views instead of `ssdf.*` base tables; `build_app(tier)` registers only the shareable tools (minus `run_sql`) and audits `tier="public"`. A new SQL migration creates the `ssdf_public` database, a least-privilege definer user, two definer views, and the `ssdf_public` reader user. Deployment is a new LXC (ct110, 198.51.100.154, port 30033) running the same package with `MCP_TIER=public`.

**Tech Stack:** Python 3.11 + FastMCP, ClickHouse 26.5 (`SQL SECURITY DEFINER` views), `uv`/`pytest`, systemd on Proxmox LXC (no Docker).

**Reference spec:** `docs/superpowers/specs/2026-06-09-ssdf-m7b-public-mcp-split-design.md`

**Working directory for all `uv run` / `pytest` commands:** `services/mcp-query`

---

## File Structure

| File | Responsibility | Action |
|---|---|---|
| `services/mcp-query/src/ssdf_mcp_query/classification.py` | Pure taxonomy + the new `PUBLIC_EXCLUDED_TOOLS`, `is_tool_shareable`, `public_tool_names` helpers | Modify |
| `services/mcp-query/src/ssdf_mcp_query/graphstore.py` | Graph read seam; add `schema` param so SQL targets `ssdf` or `ssdf_public` | Modify |
| `services/mcp-query/src/ssdf_mcp_query/server.py` | `build_app(tier)` registers the per-tier tool set, wires schema + audit tier; `main()` reads `MCP_TIER` | Modify |
| `infra/clickhouse/008_public_views.sql` | `ssdf_public` db, definer user, 2 definer views, `ssdf_public` reader user + grants | Create |
| `services/mcp-query/infra/ssdf-mcp-public.service` | systemd unit for the public-tier service (deploy artifact) | Create |
| `services/mcp-query/infra/classification.public.example.json` | Example classification flipping `topology`+`identity` to `shareable` | Create |
| `services/mcp-query/tests/test_classification.py` | Unit tests for the new public-tool-set helpers | Modify |
| `services/mcp-query/tests/test_graphstore.py` | Unit tests for the `schema` param | Modify |
| `services/mcp-query/tests/test_server_public.py` | Unit tests for `build_app(tier="public")` | Create |
| `services/mcp-query/tests/test_public_views_integration.py` | Live floor assertion + public-tier audit row | Create |
| `CLAUDE.md` | M7b commands subsection | Modify |

**Convention notes for the implementer:**
- `classes_for_tool(name)` is a module-level function in `classification.py` returning a `frozenset[str]` (empty for unknown tools). `Classification.label_for_class(cls)` returns `"sovereign"|"shareable"` and raises `ConfigError` on an unknown class.
- `load_classification(path=None)` reads `MCP_CLASSIFICATION_FILE` when `path` is `None`; missing keys default to `sovereign`; only `topology`/`identity` may be flipped.
- Tests patch ClickHouse so no live DB is needed (see existing `tests/test_server_audit.py` `_patch_ch`).
- The full sovereign tool set is exactly these 11 names: `query_flows, describe_schema, top_talkers, run_sql, get_entity, locate, neighbors, find_path, enforcement_points, topology_snapshot, explain_access`.

---

### Task 1: Public-tool-set helpers in `classification.py`

**Files:**
- Modify: `services/mcp-query/src/ssdf_mcp_query/classification.py`
- Test: `services/mcp-query/tests/test_classification.py`

- [ ] **Step 1: Write the failing tests**

Append to `services/mcp-query/tests/test_classification.py`:

```python
from ssdf_mcp_query.classification import (
    PUBLIC_EXCLUDED_TOOLS,
    is_tool_shareable,
    public_tool_names,
)

ALL_TOOLS = [
    "query_flows", "describe_schema", "top_talkers", "run_sql", "get_entity",
    "locate", "neighbors", "find_path", "enforcement_points",
    "topology_snapshot", "explain_access",
]


def _classification(**overrides):
    """Build a Classification with the given class->label overrides (rest sovereign)."""
    import json, tempfile, os
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as handle:
        json.dump(overrides, handle)
    try:
        return load_classification(path)
    finally:
        os.unlink(path)


def test_run_sql_is_excluded_from_public():
    assert "run_sql" in PUBLIC_EXCLUDED_TOOLS


def test_no_shareable_classes_yields_empty_public_set():
    classification = _classification()  # all sovereign
    assert public_tool_names(classification, ALL_TOOLS) == []


def test_topology_flip_exposes_four_topology_tools():
    classification = _classification(topology="shareable")
    assert public_tool_names(classification, ALL_TOOLS) == [
        "locate", "neighbors", "find_path", "topology_snapshot",
    ]


def test_identity_flip_exposes_get_entity_only():
    classification = _classification(identity="shareable")
    assert public_tool_names(classification, ALL_TOOLS) == ["get_entity"]


def test_both_flips_expose_five_tools_and_not_run_sql():
    classification = _classification(topology="shareable", identity="shareable")
    selected = public_tool_names(classification, ALL_TOOLS)
    assert selected == [
        "get_entity", "locate", "neighbors", "find_path", "topology_snapshot",
    ]
    assert "run_sql" not in selected
    # enforcement_points + explain_access carry locked classes -> never public
    assert "enforcement_points" not in selected
    assert "explain_access" not in selected


def test_is_tool_shareable_false_for_unknown_tool():
    classification = _classification(topology="shareable", identity="shareable")
    assert is_tool_shareable(classification, "made_up_tool") is False
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd services/mcp-query && uv run pytest tests/test_classification.py -k "public or shareable or run_sql" -v`
Expected: FAIL with `ImportError` / `cannot import name 'public_tool_names'`.

- [ ] **Step 3: Implement the helpers**

Append to `services/mcp-query/src/ssdf_mcp_query/classification.py` (after `load_classification`):

```python
# Tools structurally barred from the public server regardless of classification
# (defense in depth: arbitrary SQL must never live on the public process).
PUBLIC_EXCLUDED_TOOLS: frozenset[str] = frozenset({"run_sql"})


def is_tool_shareable(classification: "Classification", tool_name: str) -> bool:
    """True iff every class the tool returns is 'shareable' and it is not excluded.

    Unknown tools (no declared classes) and hard-excluded tools are never shareable.
    """
    if tool_name in PUBLIC_EXCLUDED_TOOLS:
        return False
    classes = classes_for_tool(tool_name)
    if not classes:
        return False
    return all(classification.label_for_class(cls) == "shareable" for cls in classes)


def public_tool_names(
    classification: "Classification", candidates: list[str]
) -> list[str]:
    """Return, in input order, the candidate tools exposable on the public server."""
    return [name for name in candidates if is_tool_shareable(classification, name)]
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd services/mcp-query && uv run pytest tests/test_classification.py -v`
Expected: PASS (all classification tests, including the pre-existing ones).

- [ ] **Step 5: Commit**

```bash
git add services/mcp-query/src/ssdf_mcp_query/classification.py services/mcp-query/tests/test_classification.py
git commit -m "feat(m7b): public-tool-set helpers (shareable-classes minus run_sql)"
```

---

### Task 2: `schema` parameter in `graphstore.py`

**Files:**
- Modify: `services/mcp-query/src/ssdf_mcp_query/graphstore.py`
- Test: `services/mcp-query/tests/test_graphstore.py`

- [ ] **Step 1: Write the failing tests**

Append to `services/mcp-query/tests/test_graphstore.py`:

```python
from ssdf_mcp_query.graphstore import build_nodes_by_id_sql


def test_builders_default_to_ssdf_schema():
    node_sql, _ = build_node_match_sql("10.64.0.5", tenant="t_main")
    edge_sql, _ = build_subgraph_sql(since_iso="2026-06-06T00:00:00+00:00", tenant="t_main")
    ids_sql, _ = build_nodes_by_id_sql(["n1"], tenant="t_main")
    assert "ssdf.graph_nodes FINAL" in node_sql
    assert "ssdf.graph_edges FINAL" in edge_sql
    assert "ssdf.graph_nodes FINAL" in ids_sql


def test_builders_honor_public_schema():
    node_sql, _ = build_node_match_sql("10.64.0.5", tenant="t_main", schema="ssdf_public")
    edge_sql, _ = build_subgraph_sql(
        since_iso="2026-06-06T00:00:00+00:00", tenant="t_main", schema="ssdf_public"
    )
    ids_sql, _ = build_nodes_by_id_sql(["n1"], tenant="t_main", schema="ssdf_public")
    assert "ssdf_public.graph_nodes FINAL" in node_sql
    assert "ssdf_public.graph_edges FINAL" in edge_sql
    assert "ssdf_public.graph_nodes FINAL" in ids_sql
    # base schema must NOT appear when the public schema is requested
    assert "ssdf.graph_nodes" not in node_sql
    assert "ssdf.graph_edges" not in edge_sql


def test_store_threads_schema_into_queries():
    fake = FakeCH()
    store = ClickHouseGraphStore(fake, tenant="t_main", schema="ssdf_public")
    store.find_node("10.64.0.5")
    assert any("ssdf_public.graph_nodes" in sql for sql, _ in fake.calls)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd services/mcp-query && uv run pytest tests/test_graphstore.py -k "schema" -v`
Expected: FAIL with `TypeError: build_node_match_sql() got an unexpected keyword argument 'schema'`.

- [ ] **Step 3: Implement the `schema` parameter**

Replace the three builder functions and the store `__init__`/methods in `services/mcp-query/src/ssdf_mcp_query/graphstore.py` with:

```python
def build_node_match_sql(value: str, tenant: str, schema: str = "ssdf") -> tuple[str, dict]:
    sql = (
        "SELECT node_id, kind, name, identifiers, toString(first_seen) AS first_seen, "
        f"toString(last_seen) AS last_seen, attrs FROM {schema}.graph_nodes FINAL "
        "WHERE tenant_id = {tenant:String} AND ("
        "node_id = {val:String} OR has(mapValues(identifiers), {val:String})) "
        "ORDER BY last_seen DESC LIMIT 1"
    )
    return sql, {"tenant": tenant, "val": _normalize_identifier(value)}


def build_subgraph_sql(
    since_iso: str, tenant: str, limit: int = 5000, schema: str = "ssdf"
) -> tuple[str, dict]:
    sql = (
        "SELECT edge_id, src_id, dst_id, edge_type, layer, "
        "toString(first_seen) AS first_seen, toString(last_seen) AS last_seen, "
        f"confidence, attrs FROM {schema}.graph_edges FINAL "
        "WHERE tenant_id = {tenant:String} AND last_seen >= {since:String} "
        f"ORDER BY last_seen DESC LIMIT {int(limit)}"
    )
    return sql, {"tenant": tenant, "since": since_iso}


def build_nodes_by_id_sql(
    node_ids: list[str], tenant: str, schema: str = "ssdf"
) -> tuple[str, dict]:
    sql = (
        "SELECT node_id, kind, name, identifiers, toString(first_seen) AS first_seen, "
        f"toString(last_seen) AS last_seen, attrs FROM {schema}.graph_nodes FINAL "
        "WHERE tenant_id = {tenant:String} AND node_id IN {ids:Array(String)}"
    )
    return sql, {"tenant": tenant, "ids": node_ids}
```

Then update the class:

```python
class ClickHouseGraphStore:
    """GraphStore backed by ClickHouse (the swappable storage seam)."""

    def __init__(self, ch_client, tenant: str = "t_main", schema: str = "ssdf"):
        self._ch = ch_client
        self._tenant = tenant
        self._schema = schema

    def find_node(self, identifier: str) -> dict | None:
        sql, params = build_node_match_sql(identifier, self._tenant, schema=self._schema)
        rows = self._ch.run(sql, params)["rows"]
        return rows[0] if rows else None

    def load_subgraph(self, since_iso: str, limit: int = 5000) -> tuple[list[dict], list[dict]]:
        edge_sql, edge_params = build_subgraph_sql(
            since_iso, self._tenant, limit, schema=self._schema
        )
        edges = self._ch.run(edge_sql, edge_params)["rows"]
        node_ids = sorted({e["src_id"] for e in edges} | {e["dst_id"] for e in edges})
        nodes: list[dict] = []
        if node_ids:
            node_sql, node_params = build_nodes_by_id_sql(
                node_ids, self._tenant, schema=self._schema
            )
            nodes = self._ch.run(node_sql, node_params)["rows"]
        return nodes, edges
```

> Note: `schema` is a fixed build-time constant (`"ssdf"` or `"ssdf_public"`), never user input, so f-string interpolation is safe here; `tenant`/`val`/`since`/`ids` remain bound query parameters.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd services/mcp-query && uv run pytest tests/test_graphstore.py -v`
Expected: PASS (new schema tests + all pre-existing graphstore tests, including the default-`ssdf` ones).

- [ ] **Step 5: Commit**

```bash
git add services/mcp-query/src/ssdf_mcp_query/graphstore.py services/mcp-query/tests/test_graphstore.py
git commit -m "feat(m7b): thread schema param through graphstore (ssdf vs ssdf_public)"
```

---

### Task 3: `build_app(tier)` public build path in `server.py`

**Files:**
- Modify: `services/mcp-query/src/ssdf_mcp_query/server.py`
- Test: `services/mcp-query/tests/test_server_public.py` (create)

- [ ] **Step 1: Write the failing tests**

Create `services/mcp-query/tests/test_server_public.py`:

```python
import asyncio
import json
import os

os.environ.setdefault("CH_PASSWORD", "x")
os.environ.setdefault("MCP_AUTH_TOKEN", "t")

SOVEREIGN_TOOLS = {
    "query_flows", "describe_schema", "top_talkers", "run_sql", "get_entity",
    "locate", "neighbors", "find_path", "enforcement_points",
    "topology_snapshot", "explain_access",
}


def _names(app):
    return {t.name for t in asyncio.run(app.list_tools())}


def _patch_ch(monkeypatch, server):
    class _Dummy:
        def __init__(self, *a, **k):
            pass

    monkeypatch.setattr(server, "ClickHouseClient", _Dummy)
    monkeypatch.setattr(server, "make_ch_auditor",
                        lambda config: server.Auditor(lambda row: None))


def _classification_file(tmp_path, **overrides):
    path = tmp_path / "classification.json"
    path.write_text(json.dumps(overrides))
    return str(path)


def test_public_build_both_classes_exposes_five_tools(monkeypatch, tmp_path):
    import ssdf_mcp_query.server as server
    _patch_ch(monkeypatch, server)
    monkeypatch.setenv("MCP_CLASSIFICATION_FILE",
                       _classification_file(tmp_path, topology="shareable", identity="shareable"))
    app = server.build_app(tier="public")
    assert _names(app) == {
        "get_entity", "locate", "neighbors", "find_path", "topology_snapshot",
    }


def test_public_build_topology_only(monkeypatch, tmp_path):
    import ssdf_mcp_query.server as server
    _patch_ch(monkeypatch, server)
    monkeypatch.setenv("MCP_CLASSIFICATION_FILE",
                       _classification_file(tmp_path, topology="shareable"))
    app = server.build_app(tier="public")
    assert _names(app) == {"locate", "neighbors", "find_path", "topology_snapshot"}
    assert "get_entity" not in _names(app)


def test_public_build_zero_tools_warns(monkeypatch, tmp_path, capsys):
    import ssdf_mcp_query.server as server
    _patch_ch(monkeypatch, server)
    # no MCP_CLASSIFICATION_FILE -> everything sovereign -> zero public tools
    monkeypatch.delenv("MCP_CLASSIFICATION_FILE", raising=False)
    app = server.build_app(tier="public")
    assert _names(app) == set()
    assert "no shareable classes" in capsys.readouterr().err


def test_public_build_never_exposes_run_sql_or_security_tools(monkeypatch, tmp_path):
    import ssdf_mcp_query.server as server
    _patch_ch(monkeypatch, server)
    monkeypatch.setenv("MCP_CLASSIFICATION_FILE",
                       _classification_file(tmp_path, topology="shareable", identity="shareable"))
    names = _names(server.build_app(tier="public"))
    for forbidden in ("run_sql", "query_flows", "describe_schema", "top_talkers",
                      "enforcement_points", "explain_access"):
        assert forbidden not in names


def test_sovereign_build_unchanged(monkeypatch):
    import ssdf_mcp_query.server as server
    _patch_ch(monkeypatch, server)
    app = server.build_app()  # default tier="sovereign"
    assert _names(app) == SOVEREIGN_TOOLS


def test_public_build_uses_public_schema(monkeypatch, tmp_path):
    import ssdf_mcp_query.server as server
    _patch_ch(monkeypatch, server)
    monkeypatch.setenv("MCP_CLASSIFICATION_FILE",
                       _classification_file(tmp_path, topology="shareable", identity="shareable"))
    captured = {}
    real_store = server.ClickHouseGraphStore

    def _spy(ch_client, tenant="t_main", schema="ssdf"):
        captured["schema"] = schema
        return real_store(ch_client, tenant=tenant, schema=schema)

    monkeypatch.setattr(server, "ClickHouseGraphStore", _spy)
    server.build_app(tier="public")
    assert captured["schema"] == "ssdf_public"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd services/mcp-query && uv run pytest tests/test_server_public.py -v`
Expected: FAIL — `build_app()` takes no `tier` argument (`TypeError`).

- [ ] **Step 3: Implement `build_app(tier)`**

Edit `services/mcp-query/src/ssdf_mcp_query/server.py`:

1. Add `import os` and `import sys` at the top (after `from __future__ import annotations`):

```python
import os
import sys
```

2. Update the classification import line to also import the helper:

```python
from .classification import load_classification, public_tool_names
```

3. Change the signature `def build_app() -> FastMCP:` to:

```python
def build_app(tier: str = "sovereign") -> FastMCP:
```

4. Inside `build_app`, replace the line `classification = load_classification()`-equivalent (currently `load_classification()  # fail closed on invalid classification config`) and the graph-store construction so the top of the function reads:

```python
    config = load_config()
    classification = load_classification()  # fail closed on invalid classification config
    auditor = make_ch_auditor(config)

    schema = "ssdf_public" if tier == "public" else "ssdf"
    client = ClickHouseClient(config)
    tools = Tools(client)
    graph_store = ClickHouseGraphStore(client, tenant="t_main", schema=schema)
    topo = TopoTools(graph_store)
    entity_store = ClickHouseEntityStore(client, tenant="t_main")
    access = AccessTools(entity_store, topo)
```

> The entity store / access tools are constructed unconditionally — construction does no I/O, and on the public host the CH user is `ssdf_public` (which cannot read the entity tables anyway), so this is security-neutral. The public tier simply never *registers* `explain_access`. This is a deliberate, minor simplification of the spec's "not constructed" wording, kept for code simplicity.

5. Replace the verifier-payload `tier` literal: change `"tier": "sovereign",` (inside the `payload` dict) to `"tier": tier,`.

6. Replace the registration block at the end of `build_app` (the `for name, fn in raw_tools.items(): mcp.tool(...)` loop) with:

```python
    if tier == "public":
        selected = public_tool_names(classification, list(raw_tools))
        if not selected:
            print("[public] no shareable classes configured; 0 tools exposed",
                  file=sys.stderr)
    else:
        selected = list(raw_tools)

    for name in selected:
        mcp.tool(name=name)(audited_tool(name, raw_tools[name], auditor, tier=tier))

    return mcp
```

7. Update `main()` to read the tier from the environment:

```python
def main() -> None:
    config = load_config()
    tier = os.environ.get("MCP_TIER", "sovereign")
    app = build_app(tier)
    app.run(transport="http", host=config.mcp_bind, port=config.mcp_port)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd services/mcp-query && uv run pytest tests/test_server_public.py tests/test_server_audit.py -v`
Expected: PASS (public build tests + the pre-existing sovereign `test_server_audit.py` still green).

- [ ] **Step 5: Run the full unit suite to confirm no regressions**

Run: `cd services/mcp-query && uv run pytest -m "not integration" -q`
Expected: PASS (all unit tests across the package).

- [ ] **Step 6: Commit**

```bash
git add services/mcp-query/src/ssdf_mcp_query/server.py services/mcp-query/tests/test_server_public.py
git commit -m "feat(m7b): build_app(tier) public path — shareable tools, ssdf_public schema, tier audit"
```

---

### Task 4: ClickHouse migration `008_public_views.sql`

**Files:**
- Create: `infra/clickhouse/008_public_views.sql`

- [ ] **Step 1: Write the migration**

Create `infra/clickhouse/008_public_views.sql`:

```sql
-- infra/clickhouse/008_public_views.sql
-- M7b: public-tier shareable views + least-privilege users.
--
-- ClickHouse does NOT expand {name:Type} params inside CREATE USER ... BY '...',
-- so inject the two passwords before applying (never commit real values):
--   DEFINER_PW="$CH_DEFINER_PASSWORD" PUBLIC_PW="$CH_PUBLIC_PASSWORD" \
--     envsubst < 008_public_views.sql \
--     | clickhouse-client --host <ct104> --multiquery
--
-- Enforcement model: ssdf_public is granted SELECT on the ssdf_public.* views
-- ONLY (no base-table grant). The views run with SQL SECURITY DEFINER as
-- ssdf_view_definer, which can read ONLY the two shareable base tables. So the
-- public process is structurally unable to name a sovereign table.

CREATE DATABASE IF NOT EXISTS ssdf_public;

-- Least-privilege definer: its readable surface == the shareable surface.
CREATE USER IF NOT EXISTS ssdf_view_definer IDENTIFIED WITH sha256_password BY '${DEFINER_PW}';
GRANT SELECT ON ssdf.graph_nodes TO ssdf_view_definer;
GRANT SELECT ON ssdf.graph_edges TO ssdf_view_definer;

-- Coarse v0 shareable views (full node/edge shape; tenant filtering stays in the
-- tool SQL exactly like the sovereign path).
CREATE OR REPLACE VIEW ssdf_public.graph_nodes
    DEFINER = ssdf_view_definer SQL SECURITY DEFINER
    AS SELECT * FROM ssdf.graph_nodes;

CREATE OR REPLACE VIEW ssdf_public.graph_edges
    DEFINER = ssdf_view_definer SQL SECURITY DEFINER
    AS SELECT * FROM ssdf.graph_edges;

-- Public reader: granted on the VIEWS ONLY. No base ssdf.* grant.
CREATE USER IF NOT EXISTS ssdf_public IDENTIFIED WITH sha256_password BY '${PUBLIC_PW}';
GRANT SELECT ON ssdf_public.graph_nodes TO ssdf_public;
GRANT SELECT ON ssdf_public.graph_edges TO ssdf_public;
```

- [ ] **Step 2: Sanity-check that the placeholders and statements are well-formed**

Run: `grep -c "CREATE OR REPLACE VIEW" infra/clickhouse/008_public_views.sql`
Expected: `2`

Run: `grep -c '\${DEFINER_PW}\|\${PUBLIC_PW}' infra/clickhouse/008_public_views.sql`
Expected: `2`

(The migration is exercised live in Task 6's integration test; there is no unit test for raw SQL.)

- [ ] **Step 3: Commit**

```bash
git add infra/clickhouse/008_public_views.sql
git commit -m "feat(m7b): 008_public_views.sql — ssdf_public definer views + grant floor"
```

---

### Task 5: Deployment artifacts (systemd unit + classification example)

**Files:**
- Create: `services/mcp-query/infra/ssdf-mcp-public.service`
- Create: `services/mcp-query/infra/classification.public.example.json`

- [ ] **Step 1: Write the systemd unit**

Create `services/mcp-query/infra/ssdf-mcp-public.service`:

```ini
[Unit]
Description=SSDF M7b public-tier MCP server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=MCP_TIER=public
Environment=CH_HOST=198.51.100.151
Environment=CH_PORT=8123
Environment=CH_USER=ssdf_public
Environment=CH_DATABASE=ssdf_public
Environment=MCP_BIND=0.0.0.0
Environment=MCP_PORT=30033
Environment=MCP_TOKEN_FILE=/etc/ssdf-mcp/token
Environment=MCP_CLASSIFICATION_FILE=/etc/ssdf-mcp/classification.json
Environment=CH_AUDIT_USER=ssdf_audit
EnvironmentFile=/etc/ssdf-mcp/secrets.env
ExecStart=/opt/ssdf-mcp/bin/python -m ssdf_mcp_query.server
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
```

> `secrets.env` (mode 600, created at deploy time) supplies `CH_PASSWORD` (= the `ssdf_public`
> password) and `CH_AUDIT_PASSWORD` (= the `ssdf_audit` password). `MCP_TOKEN_FILE` may be replaced
> by `MCP_TOKENS_FILE` if multiple public principals are wanted.

- [ ] **Step 2: Write the example classification file**

Create `services/mcp-query/infra/classification.public.example.json`:

```json
{
  "topology": "shareable",
  "identity": "shareable"
}
```

- [ ] **Step 3: Verify both files are valid**

Run: `python3 -c "import json; json.load(open('services/mcp-query/infra/classification.public.example.json'))" && echo OK`
Expected: `OK`

Run: `grep -c "MCP_TIER=public" services/mcp-query/infra/ssdf-mcp-public.service`
Expected: `1`

- [ ] **Step 4: Commit**

```bash
git add services/mcp-query/infra/ssdf-mcp-public.service services/mcp-query/infra/classification.public.example.json
git commit -m "feat(m7b): public-tier systemd unit + classification example"
```

---

### Task 6: Live integration tests (grant floor + public audit)

**Files:**
- Create: `services/mcp-query/tests/test_public_views_integration.py`

These run only with live ClickHouse (marked `integration`, skipped otherwise). They assume `008_public_views.sql` has been applied (see the run command below).

- [ ] **Step 1: Write the integration tests**

Create `services/mcp-query/tests/test_public_views_integration.py`:

```python
import os
import uuid
import pytest
import clickhouse_connect
from clickhouse_connect.driver.exceptions import DatabaseError

pytestmark = pytest.mark.integration

CH_HOST = os.environ.get("CH_HOST")
CH_PORT = int(os.environ.get("CH_PORT", "8123"))
PUBLIC_PW = os.environ.get("CH_PUBLIC_PASSWORD")
AUDIT_PW = os.environ.get("CH_AUDIT_PASSWORD")


def _public_client():
    return clickhouse_connect.get_client(
        host=CH_HOST, port=CH_PORT,
        username=os.environ.get("CH_PUBLIC_USER", "ssdf_public"),
        password=PUBLIC_PW, database="ssdf_public",
    )


@pytest.mark.skipif(not (CH_HOST and PUBLIC_PW), reason="needs live CH + ssdf_public pw")
def test_public_can_read_shareable_view():
    client = _public_client()
    # Must succeed (count may be zero, but the query must be authorized).
    client.query("SELECT count() FROM ssdf_public.graph_nodes")
    client.query("SELECT count() FROM ssdf_public.graph_edges")


@pytest.mark.skipif(not (CH_HOST and PUBLIC_PW), reason="needs live CH + ssdf_public pw")
def test_public_cannot_read_sovereign_base_tables():
    client = _public_client()
    with pytest.raises(DatabaseError):
        client.query("SELECT count() FROM ssdf.graph_nodes")
    with pytest.raises(DatabaseError):
        client.query("SELECT count() FROM ssdf.events")
    with pytest.raises(DatabaseError):
        client.query("SELECT count() FROM ssdf.entities")


@pytest.mark.skipif(not (CH_HOST and AUDIT_PW), reason="needs live CH + ssdf_audit pw")
def test_public_tier_audit_row_round_trips():
    """A public-tier audit row is written and tagged tier='public'."""
    from ssdf_mcp_query.audit import make_ch_auditor
    from ssdf_mcp_query.config import load_config

    principal = f"pub-itest-{uuid.uuid4().hex[:8]}"
    auditor = make_ch_auditor(load_config())
    auditor.record(
        principal=principal, tier="public", tool="topology_snapshot",
        args={"layer": "l2"}, data_classes=["topology"],
        decision="allow", row_count=0, error="",
    )
    admin_pw = os.environ.get("CH_ADMIN_PASSWORD")
    if not admin_pw:
        pytest.skip("set CH_ADMIN_PASSWORD to verify read-back")
    import time
    time.sleep(0.5)
    admin = clickhouse_connect.get_client(
        host=CH_HOST, port=CH_PORT,
        username=os.environ.get("CH_ADMIN_USER", "default"),
        password=admin_pw, database="ssdf",
    )
    rows = admin.query(
        "SELECT tier, tool FROM ssdf.audit WHERE principal = {p:String} "
        "ORDER BY ts DESC LIMIT 1",
        parameters={"p": principal},
    ).result_rows
    assert rows, "public audit row not found"
    tier, tool = rows[0]
    assert tier == "public"
    assert tool == "topology_snapshot"
```

- [ ] **Step 2: Verify the tests are skipped without live CH (CI-safe)**

Run: `cd services/mcp-query && uv run pytest tests/test_public_views_integration.py -v`
Expected: all tests SKIPPED (no `CH_HOST`/passwords set) — confirms they never run in a unit context.

- [ ] **Step 3: Commit**

```bash
git add services/mcp-query/tests/test_public_views_integration.py
git commit -m "test(m7b): live grant-floor + public-tier audit integration tests"
```

> **Live validation (run during deployment, not in this task):** after applying the migration on
> ct104 —
> ```bash
> # on the dev host, with services/mcp-query as CWD
> CH_HOST=198.51.100.151 \
> CH_PUBLIC_PASSWORD=<public_pw> CH_AUDIT_PASSWORD=<audit_pw> CH_PASSWORD=<public_pw> \
> CH_ADMIN_PASSWORD=<admin_pw> \
> uv run pytest tests/test_public_views_integration.py -m integration -v
> ```
> Expected: `test_public_can_read_shareable_view` PASS, `test_public_cannot_read_sovereign_base_tables`
> PASS (the hard-floor assertion), `test_public_tier_audit_row_round_trips` PASS.

---

### Task 7: Document M7b commands in `CLAUDE.md`

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Add the M7b commands subsection**

In `CLAUDE.md`, immediately after the `### M7a (classification + multi-principal auth + audit — ssdf-mcp-query hardening)` block (before the closing `Future Rust/Python components…` line), insert:

```markdown
### M7b (public MCP split — ssdf-mcp-public tier)
- Unit tests: `cd services/mcp-query && uv run pytest -m "not integration"` (adds `test_server_public` + classification/graphstore public-schema suites).
- Live floor/audit integration: `cd services/mcp-query && CH_HOST=<ip> CH_PUBLIC_PASSWORD=<pub_pw> CH_AUDIT_PASSWORD=<audit_pw> CH_PASSWORD=<pub_pw> [CH_ADMIN_PASSWORD=<pw>] uv run pytest tests/test_public_views_integration.py -m integration`.
- Apply public views + users: `DEFINER_PW="$CH_DEFINER_PASSWORD" PUBLIC_PW="$CH_PUBLIC_PASSWORD" envsubst < infra/clickhouse/008_public_views.sql | clickhouse-client --host <ct104> --multiquery` (creates `ssdf_public` db, `ssdf_view_definer`, two `SQL SECURITY DEFINER` views, and the `ssdf_public` reader granted on views only).
- **Tier select:** the SAME `ssdf_mcp_query.server` runs public when `MCP_TIER=public` (default `sovereign`). Public build registers only tools whose data classes are ALL `shareable` (per `MCP_CLASSIFICATION_FILE`), **minus `run_sql`** (hard-excluded). No shareable class ⇒ 0 tools + a stderr warning (secure default). Public stores read the `ssdf_public` schema (`graphstore` `schema` param); audit rows are tagged `tier="public"`.
- **Hard floor:** `ssdf_public` has SELECT on `ssdf_public.graph_nodes`/`graph_edges` ONLY; the definer views read base `ssdf.*` as `ssdf_view_definer`. `ssdf_public` selecting any base `ssdf.*` table ⇒ `ACCESS_DENIED` (proven by `test_public_cannot_read_sovereign_base_tables`).
- **Deploy:** new LXC **ct110** (`ssdf-mcp-public`, 198.51.100.154, port 30033). Unit `services/mcp-query/infra/ssdf-mcp-public.service`; `/etc/ssdf-mcp/secrets.env` (mode 600) holds `CH_PASSWORD`=ssdf_public pw + `CH_AUDIT_PASSWORD`; `/etc/ssdf-mcp/classification.json` flips `topology`/`identity` to `shareable` (see `infra/classification.public.example.json`). A public LLM connects as an MCP client to `http://198.51.100.154:30033/mcp` with a public-tier token — MCP is the only interface; no API/egress to configure.
```

- [ ] **Step 2: Verify the section was added**

Run: `grep -c "M7b (public MCP split" CLAUDE.md`
Expected: `1`

- [ ] **Step 3: Commit**

```bash
git add CLAUDE.md
git commit -m "docs(m7b): commands + tier/floor/deploy notes for public MCP split"
```

---

## Deployment (run after all tasks merge; not part of TDD)

1. Create LXC **ct110** `ssdf-mcp-public` (198.51.100.154) on pve3; install the `ssdf-mcp-query` package into `/opt/ssdf-mcp` (mirror ct106's install style — record editable vs regular in CLAUDE.md afterward).
2. Apply `infra/clickhouse/008_public_views.sql` on ct104 via `envsubst` with fresh `DEFINER_PW`/`PUBLIC_PW` (mode-600 temp file, shred after).
3. Write ct110 `/etc/ssdf-mcp/secrets.env` (mode 600): `CH_PASSWORD=<ssdf_public pw>`, `CH_AUDIT_PASSWORD=<ssdf_audit pw>`; `/etc/ssdf-mcp/classification.json` (from the example); `/etc/ssdf-mcp/token` (a public-tier bearer token).
4. Install `ssdf-mcp-public.service`, `systemctl enable --now`, confirm clean boot + the expected tool list (`topology_snapshot`, `locate`, `neighbors`, `find_path`, `get_entity`).
5. Run the Task 6 live-validation command; confirm the base-table denial + a `tier="public"` audit row.
6. Update STATUS.md (M7b row) + memory once live-proven.

---

## Notes for the implementer

- Run the full unit suite (`uv run pytest -m "not integration"`) after Task 3 and again after Task 7; it must stay green throughout.
- Do **not** modify the sovereign path's observable behavior: `build_app()` with no argument must still register all 11 tools with `schema="ssdf"` and `tier="sovereign"` (guarded by `test_sovereign_build_unchanged` and the pre-existing `test_server_audit.py`).
- The integration tests must remain SKIPPED without live-CH env vars so the unit run is unaffected.
