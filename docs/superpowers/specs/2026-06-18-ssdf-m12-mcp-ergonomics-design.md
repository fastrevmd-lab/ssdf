# M12 — MCP ergonomics & agent-routing

**Status:** design (approved in brainstorming, pending spec review)
**Date:** 2026-06-18
**Author:** SSDF / Claude Code
**Predecessors:** M8 (eval harness + corpus), M6b (configured policy), M6c-B (provenance attribution)

## Problem

The 2026-06-15 sovereign eval (claude-sonnet-4-6) scored 15/22. Mining the 7 misses
shows the failures are **not** missing data or a missing derived-findings layer (M10):
the fabric already holds the right answers. They split into two buckets:

1. **Tool-routing / answer-shape misses (agent-side, probabilistic):** the model
   reached for `query_flows` (raw events) when the question wanted firewall *attribution*
   (`reach-rule-trust-untrust`, `reach-firewall-attribution`, `topo-locate-labgen`). The
   data was reachable; the model picked a tool whose output is shaped for a different
   question, then answered with a vendor string (`paloalto`) instead of a device name
   (`panosvm`). `explain_access` already normalizes to device names via `_short_host`, so
   this is purely a routing problem — the tool surface does not draw crisp enough
   ownership lines for the agent to route correctly.

2. **Genuine ergonomics gaps + eval-design defects (SSDF-side, fixable):**
   - `reach-configured-policy-count-panosvm` (4 vs 7): no first-class way to ask "how many
     configured policies does firewall X have"; the count also hits a ReplacingMergeTree
     duplicate-version trap that only `count(DISTINCT entity_id)` avoids.
   - `topo-firewall-inventory` (25 lab vSRX names vs expected `[panosvm, vSRX-test10]`):
     `topology_snapshot` cannot filter to firewall-role nodes, AND the corpus expectation is
     stale (lab now carries many real firewall nodes incl. vSRX-Production).
   - `topo-locate-labgen`: asks "which firewall observes traffic from IP X" — an **L3
     provenance** question (the firewall that *logged* the flow), which `locate` (L2
     attachment only) structurally cannot answer. There is no tool that owns this question.

`honesty-device-metrics` (didn't refuse CPU-utilization) is an agent-prompt-discipline miss,
out of scope for a tool-surface milestone.

## Goal

A **targeted ergonomics pass** on the MCP tool surface so that the questions whose answers
already live in the fabric are routable to a tool that owns them and returns a clean,
device-named answer — plus the corpus fixes for the two eval-design defects. No new ingest,
no schema migration, no resolver work, no derived-findings layer.

## Non-goals

- No cross-tool response-shape convention / envelope refactor (the heavier "Approach 2").
- No relaxation of `required_tools` to accept SQL shortcuts — the eval mandate stays strict;
  we fix the *tool surface* so the strict mandate is satisfiable, not the bar.
- No NAT-aware flow correlation or multi-hop path stitching — that is its own milestone (M13)
  needing ingest + schema + resolver work (SRX NAT is not even captured today).
- M10 (derived findings) stays deferred — the eval misses do not justify it.

## Approach

Five additive components. Nothing changes the shape of an existing tool's response except
by adding optional parameters with backwards-compatible defaults.

### Component A — description sharpening + output audit

Rewrite the docstrings (which ARE the MCP tool descriptions FastMCP exposes to agents) in
`services/mcp-query/src/ssdf_mcp_query/server.py` to draw crisp ownership lines:

- **`explain_access`** owns *"which rule / which firewall governs or observed this pair"*.
  Note in the description that its `firewalls` are **device names** (not vendor strings).
- **`locate` / `neighbors`** own *"where is this attached / what is L2-adjacent"* — explicitly
  **not** firewall-observation.
- **`query_flows`** explicitly states it returns **raw events**; its provider/vendor field is
  a vendor string (`paloalto`), **not** a firewall identity — point the agent to
  `explain_access` / `observed_by` when the question is about *which firewall*.

Audit `locate`, `get_entity`, `topology_snapshot` outputs for vendor-string leakage where a
device name is the right answer. This is the lever for misses #1/#2/#5 **under strict
`required_tools`** — it is probabilistic (we cannot force a model's tool choice), so it is a
nudge, not a guarantee. The deterministic fixes are B/C/E.

### Component B — `configured_policies(firewall)` tool

A new **sovereign-only** tool (registered only when `access is not None`, mirroring
`explain_access`'s guard) that wraps the existing, correctness-proven
`ClickHouseEntityStore.configured_policies_for_firewalls`. Response:

```json
{"firewalls": [{"firewall": "panosvm",
                "rules": [{"rule": "...", "action": "...", "from_zone": "...",
                           "to_zone": "...", "position": "...", "enabled": true,
                           "source": "configured"}],
                "count": 7}]}
```

`count` is the **deduplicated** policy count (`count(DISTINCT entity_id)` semantics — the
store already keys per `provider:device_name:rule_name`, so de-dup the projected rows by
entity), which is exactly the `reach-configured-policy-count-panosvm` answer (fixes #3, the
ReplacingMergeTree trap). Reuse the `configured_controls` projection already in
`explain_access` so the row shape matches. Accepts one firewall name or a list.

Classification: **`firewall_config`** — add to `TOOL_DATA_CLASSES` in `classification.py`.
`firewall_config` is secure-by-default (not configurable to shareable), so the tool is
auto-excluded from the public tier. Correct: configured rules are sovereign-only.

### Component C — `topology_snapshot` role filter

Add an optional `role` (and/or `kind`) parameter to `topology_snapshot` in `topo_tools.py`,
applied as a **post-fetch filter** on `attrs.role` / `kind`. Default `None` ⇒ current
behavior unchanged (purely additive). `topology_snapshot(role="firewall")` returns only
firewall-role nodes — the product half of the `topo-firewall-inventory` fix (#6).

### Component D — corpus fixes (`services/evals/golden/core.yaml`)

- **Refresh the `topo-firewall-inventory` expectation:** verify live which nodes carry
  `attrs.role=firewall` and update `expected.firewalls` to the real set (lab now includes
  vSRX-Production and others — the old `[panosvm, vSRX-test10]` predates Phase 2). This is
  the eval-design half of #6.
- **`required_tools` consistency audit:** keep mandates strict; only correct a mandate where
  it is genuinely wrong (e.g. a question that should mandate the new `observed_by`/
  `configured_policies` tool, or a `locate` mandate that the question cannot satisfy). Do not
  relax mandates to accept SQL shortcuts.

Corpus lint (unit-tested: unique ids, public questions restricted to public tools,
SELECT-only SQL) must stay green.

### Component E — `observed_by(identifier, since_hours)` tool (NEW)

A dedicated **sovereign** tool that answers the L3 provenance question *"which firewall(s)
have observed traffic for this IP/asset"* — the question `locate` (L2) structurally cannot
own. Response:

```json
{"entity": {"entity_id": "...", "name": "..."},
 "firewalls": ["panosvm", "vSRX-Production"]}
```

Built from the same L3 flow provenance `explain_access` uses: resolve the identifier to its
entity, read the `observer_hosts` set from its `COMMUNICATED_WITH` edges (or query
`observer_hostname` over the window), normalize each to its device name via `_short_host`.
**Multi-firewall-aware for free** — a flow that transits several firewalls returns all of
them (the real-world several-FW-traversal case the operator called out). Becomes the mandated
tool for the `topo-locate-labgen` question (#5).

Classification: **`security_log`** — add to `TOOL_DATA_CLASSES`. Secure-by-default, so
auto-excluded from public. Correct: flow provenance is sovereign-only.

## Components → eval misses

| Miss | Fixed by | Determinism |
|---|---|---|
| reach-rule-trust-untrust (#1) | A (routing nudge) | probabilistic |
| reach-firewall-attribution (#2) | A (routing nudge) | probabilistic |
| reach-configured-policy-count-panosvm (#3) | B | deterministic |
| topo-firewall-inventory (#6) | C (product) + D (corpus) | deterministic |
| topo-locate-labgen (#5) | E (new tool) + D (mandate) | deterministic |
| flows-paloalto-actions-7d | — (data-completeness, out of scope) | n/a |
| honesty-device-metrics | — (agent prompt discipline, out of scope) | n/a |

## Testing

- **Unit:** `configured_policies` response shaping + sovereign-only registration;
  `topology_snapshot` role filter (additive, default unchanged); `observed_by` shaping +
  sovereign-only registration; `classification.py` map entries for both new tools.
- **Corpus lint** stays green (unit-tested in `services/evals`).
- **Live integration:** `configured_policies("panosvm")` → count 7;
  `topology_snapshot(role="firewall")` → the live firewall set; `observed_by("10.74.11.20")`
  → surfaces the observing firewall(s).
- **End-to-end:** re-run the claude sovereign eval after deploy. Expect #3/#6/#5 to flip
  green deterministically; #1/#2 remain probabilistic (description nudge only). Commit the new
  scorecard under `services/evals/results/` (git history is the eval database).

## Deployment

Both new sovereign tools live on ct106 (`ssdf-mcp-query`, the editable install at
`/opt/src/mcp-query/src`) — sync source + `systemctl restart ssdf-mcp-query.service`. No new
LXC, no schema migration, no resolver change. Public tier (ct113) is unaffected: both new
tools are secure-by-default classed and never register on public.

## Risks

- **A is probabilistic.** Sharper descriptions improve routing but cannot force a model's
  tool choice; #1/#2 may still miss on some runs. Accepted — B/C/E carry the deterministic
  load.
- **Corpus expectation drift (D).** The firewall-inventory expectation is live-data-derived;
  if the lab firewall set changes again it will need another refresh. This is inherent to a
  live-data eval (static answers rot) and accepted by the M8 design.
