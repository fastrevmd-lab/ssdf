# Pair-aware entity resolution in explain_access — design

**Date:** 2026-06-15
**Status:** approved (read-path-only approach)
**Scope:** `services/mcp-query` only — no schema, no resolver, no data migration.

## Problem

`explain_access(client, server)` resolves each identifier to a **single** entity, then
queries `communicated_with` edges between that exact pair. The resolver (`find_entity` →
`build_entity_match_sql`) orders `confidence DESC, last_seen DESC LIMIT 1`, returning the
globally-top entity for an identifier irrespective of which counterpart it is connected to.

When an IP has **multiple entity twins**, the globally-top pick may not be the twin that
actually has an edge with the counterpart, so `explain_access` finds no edge →
`sessions:0` and the (correctly-stamped) provenance never surfaces. Two live sub-cases:

1. **Per-segment external-IP twins.** A shared external destination (e.g. `8.8.8.8`) seen
   by two firewalls becomes two ip_only twins, one per observing segment. The SRX endpoint's
   edge points to the SRX-side twin, but `find_entity("8.8.8.8")` returns whichever twin has
   the most-recent `last_seen` (the busier panosvm-side twin) — which has no edge with the
   SRX client.
2. **MAC-vs-ip_only competition.** A LAN host (e.g. `198.51.100.1`) is a MAC-bound asset
   (confidence 1.0) *and* a per-segment ip_only twin (confidence 0.5). `find_entity` returns
   the MAC asset, but the SRX-side flow edge points to the ip_only twin.

This is the M6a IP-vs-MAC/segment identity split, documented as the M6c-B provenance caveat
in CLAUDE.md. The data layer is correct — each edge carries the right `observer_hosts`
(`vSRX-Production`, `panosvm.example.com`); only the read-path *resolution* mispicks the twin.

**Live evidence (2026-06-15):** `8.8.8.8` has two ip_only twins — `37ad…` (edge from the
panosvm endpoint, `observer_hosts=panosvm.example.com`, newer `last_seen`) and `43cd…` (edge
from the SRX endpoint `081c90fe9302a540`, `observer_hosts=vSRX-Production`). `explain_access`
resolves `8.8.8.8` to `37ad…` → no edge with the SRX client → `sessions:0`. The PAN-OS path
surfaces correctly only because its client (ct199) is MAC-bound and its server twin happens
to be the most-recent.

## Goal

`explain_access(<SRX endpoint>, 8.8.8.8)` and `(<SRX endpoint>, 198.51.100.1)` surface the
existing SRX provenance: `firewall_basis:provenance`, `firewalls:[vSRX-Production]`,
`sessions>0` — matching the PAN-OS path. Do this **without** changing the resolver, the
entity graph, or the schema.

## Approach (read-path only)

Resolve each side to **all** candidate twins, then select the client/server pair that
actually has `communicated_with` edges between them. Selection is by real edge presence, so
it fixes both sub-cases. Honesty is preserved: when no candidate pair has an edge, fall back
to today's confidence-first single pick with `sessions:0`.

### Component 1 — `entitystore.py`

The existing `find_entity` / `communicated_edges` / `build_entity_match_sql` /
`build_comm_edges_sql` remain unchanged (other code and tests depend on them). Add:

- `build_entities_match_sql(value, tenant) -> (sql, params)`: identical to
  `build_entity_match_sql` **without** the `LIMIT 1`. Keeps `ORDER BY confidence DESC,
  entities.last_seen DESC` so row 0 is the same entity `find_entity` returns today.
- `build_comm_edges_multi_sql(a_ids, b_ids, since_iso, tenant) -> (sql, params)`: same shape
  as `build_comm_edges_sql` but with `src_id IN {a:Array(String)}` / `dst_id IN
  {b:Array(String)}` on both directions:
  `(src_id IN A AND dst_id IN B) OR (src_id IN B AND dst_id IN A)`. Retains the
  `entity_edges.last_seen >= {since}` qualified-column guard (alias-shadowing note).
- `ClickHouseEntityStore.find_entities(identifier) -> list[dict]`: runs
  `build_entities_match_sql`, returns all rows (`[]` if none).
- `ClickHouseEntityStore.communicated_edges_multi(a_ids, b_ids, since_iso) -> list[dict]`:
  runs `build_comm_edges_multi_sql`; returns `[]` when either id list is empty (no query).
- `EntityStore` Protocol gains `find_entities` and `communicated_edges_multi`.

### Component 2 — `access_tools.py` `explain_access`

Replace the two `find_entity` calls + single `communicated_edges` call with:

1. `client_cands = self._store.find_entities(client)`;
   `server_cands = self._store.find_entities(server)`.
   If either is empty → `{"error":"not_found", "detail": f"no entity matches '{missing}'"}`
   (unchanged; `missing` = the empty side's raw identifier).
2. `client_ids = [c["entity_id"] for c in client_cands]`; `server_ids` likewise.
3. `edges = self._store.communicated_edges_multi(client_ids, server_ids, _since(window))`.
4. Group edges by their resolved `(client_id, server_id)` pair. For each edge, the client
   side is whichever of `{src_id, dst_id}` is in `client_ids`, the server side is the other
   (an edge from the multi-query always has exactly one end in each set by construction; if
   an edge's ends both fall in the same set — only possible when the two identifiers resolve
   to overlapping candidate sets — skip it).
5. **Select** the pair with the greatest summed `sessions`; tiebreak by greatest edge
   `last_seen`, then lexicographic `(client_id, server_id)` for determinism. Set
   `client_entity` / `server_entity` to the candidates with those ids and `comm_edges` to
   that pair's edge list.
6. **Fallback:** if no pair has edges, `client_entity = client_cands[0]`,
   `server_entity = server_cands[0]`, `comm_edges = []` (⇒ `sessions:0`, today's behavior).

Everything after this point is unchanged: `sessions`/`bytes`/`ports`/`providers` summation,
`observer_hosts` → `firewalls`/`firewall_basis`, observed `controls`, `configured_controls`,
`detections`, `topology_path`, `coverage`. `topology_path`/`enforcement_points` still take
the raw `client`/`server` strings; `alert_ips` still draws from the chosen entities'
identifiers (now the edge-bearing twins, which is strictly better).

### Selection helper

A small pure function keeps `explain_access` readable and unit-testable in isolation:

```python
def _select_pair(edges, client_ids, server_ids):
    """Return (client_id, server_id, edges_for_pair) for the pair with the most sessions,
    or None when no edge maps cleanly onto one client id + one server id."""
```

`client_ids`/`server_ids` passed as sets for O(1) membership. Returns `None` ⇒ caller uses
the fallback.

## Data flow

```
explain_access(client, server)
  ├─ find_entities(client)  ─┐
  ├─ find_entities(server) ─┤  candidate twin sets (tiny: 1–4 each)
  ├─ communicated_edges_multi(client_ids, server_ids, since)
  ├─ _select_pair(...)  ── chosen (client_entity, server_entity, comm_edges)
  │         └─ none? → confidence-first fallback (sessions:0)
  └─ [unchanged] provenance → firewalls; controls; configured; detections; coverage
```

## Error handling

No new failure modes. `not_found` is unchanged. Candidate sets are bounded by how many
twins an IP has (a handful), so the extra rows and the single multi-edge query are cheap.
The CH client's `result_overflow_mode="throw"` / row caps are unaffected (IN-lists are tiny).

## Testing

**Unit — `tests/test_access_tools.py`** (fake store returning scripted candidates/edges):
- `server_two_twins_picks_edge_bearing`: client → 1 entity; server → 2 twins, only twin B has
  an edge with the client → result uses twin B, `sessions>0`, `firewall_basis:provenance`,
  `firewalls:[vSRX-Production]`.
- `mac_vs_iponly_picks_edge_bearing`: server → MAC entity (conf 1.0, no edge) + ip_only twin
  (conf 0.5, edge) → picks the ip_only twin; provenance surfaces.
- `no_edge_falls_back_confidence_first`: no candidate pair has an edge → `client_cands[0]` /
  `server_cands[0]`, `sessions:0`, `firewall_basis:no_path_firewall` (today's behavior).
- `single_twin_each_side_unchanged`: 1 entity per side with an edge (panosvm-style) → same
  result as the pre-change path (regression guard).
- `_select_pair` direct unit tests: most-sessions wins; last_seen tiebreak; empty → `None`.

**Unit — `tests/test_entitystore.py`**:
- `build_entities_match_sql` omits `LIMIT 1`, keeps the `confidence DESC, last_seen DESC`
  order and the `has(mapValues(identifiers), …)` match.
- `find_entities` returns all rows (not just the first); `[]` when none.
- `build_comm_edges_multi_sql` emits `IN {a:Array(String)}` / `IN {b:Array(String)}` on both
  directions and the qualified `entity_edges.last_seen` guard.
- `communicated_edges_multi` returns `[]` (no query) when either id list is empty.

Update the two existing fake `EntityStore`s in the test files to implement the two new
Protocol methods.

**Live proof (post-deploy, ct106):**
- `explain_access("10.74.12.20", "8.8.8.8")` → `firewall_basis:provenance`,
  `firewalls:["vSRX-Production"]`, `sessions>0`, deny edge present.
- `explain_access("10.74.12.20", "198.51.100.1")` → `firewall_basis:provenance`,
  `firewalls:["vSRX-Production"]`, `sessions>0`.
- Regression: `explain_access("10.74.11.20", "198.51.100.1")` (panosvm) still
  `firewall_basis:provenance`, `firewalls:["panosvm"]`, `coverage.configured:7`.

## Files

- Modify `services/mcp-query/src/ssdf_mcp_query/entitystore.py` (2 builders + 2 store methods
  + Protocol).
- Modify `services/mcp-query/src/ssdf_mcp_query/access_tools.py` (pair-aware resolution +
  `_select_pair` helper).
- Modify `services/mcp-query/tests/test_entitystore.py`, `tests/test_access_tools.py`.

## Deploy

ct106 is an editable install at `/opt/src/mcp-query/src`: sync the two source files +
`systemctl restart ssdf-mcp-query.service`. No migration, no infra change. The ct113 public
tier does not construct `AccessTools`/`ClickHouseEntityStore`, so it is unaffected.

## Out of scope

- Resolver identity changes / twin merging (Approach B) — deliberately deferred; this is a
  read-path-only fix that surfaces the already-correct edges.
- Aggregating across multiple server twins for one identifier — a directed
  `client→server` query has at most one edge-bearing server twin for a given client, so
  single-pair selection is sufficient.
