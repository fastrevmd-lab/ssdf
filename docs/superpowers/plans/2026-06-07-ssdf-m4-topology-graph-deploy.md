# SSDF M4 — Phase 6: Deployment, integration, acceptance

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development or superpowers:executing-plans. Prerequisite: Phases 0–5 complete (CH tables exist, `services/topo` package builds and unit-tests pass, topology tools registered in `ssdf-mcp-query`).

**Goal:** Ship M4 — package the `services/topo` collectors+resolver behind config, deploy them to a new Proxmox LXC **ct107** on a systemd timer (collect → resolve, 5-min interval), prove the end-to-end fused chain (host → switch-port → firewall → rule) against the live lab, and reconcile the project docs.

**The read-only boundary holds by construction:** collectors call only `show`/GET MCP tools; the only writer is the `ssdf_topo` CH user (INSERT+SELECT on topo tables + SELECT on events), created in Phase 0. `ssdf_ro` (the read MCP) is untouched.

---

## Task 6.1: Service env template (`ENV.example`)

**Files:**
- Create: `services/topo/infra/ENV.example`

> The as-built file is `services/topo/infra/ENV.local`, which is **gitignored** by the existing `*.local` rule in `.gitignore` (line 18). Only `ENV.example` (placeholders) is committed. Mirrors M2's `services/mcp-query/.env.example`.

- [ ] **Step 1: Write the template**

`services/topo/infra/ENV.example`:
```sh
# SSDF M4 topo service — copy to ENV.local and fill in (ENV.local is gitignored).

# ClickHouse target (ct104). ssdf_topo = writer (INSERT+SELECT topo, SELECT events).
CH_HOST=198.51.100.151
CH_PORT=8123
CH_USER=ssdf_topo
CH_PASSWORD=__set_in_ENV.local__
CH_DATABASE=ssdf

# Resolver scope
TOPO_TENANT=t_main
TOPO_WINDOW_HOURS=24

# Which collectors run this cycle (comma-separated subset of: junos,unifi,panos,proxmox)
TOPO_COLLECTORS=junos,unifi,panos,proxmox

# Per-source read-only MCP endpoints + bearer tokens.
# URL is required for an enabled collector; token may be empty if the MCP needs none.
JUNOS_MCP_URL=http://198.51.100.194:30031/mcp
JUNOS_MCP_TOKEN=__set_in_ENV.local__
UNIFI_MCP_URL=http://__unifi_mcp_host__:PORT/mcp
UNIFI_MCP_TOKEN=__set_in_ENV.local__
PANOS_MCP_URL=http://__panos_mcp_host__:PORT/mcp
PANOS_MCP_TOKEN=__set_in_ENV.local__
PROXMOX_MCP_URL=http://__proxmox_mcp_host__:PORT/mcp
PROXMOX_MCP_TOKEN=__set_in_ENV.local__
```

- [ ] **Step 2: Verify the keys match `load_config` / `mcp_endpoint`**

These env names are exactly what `services/topo/src/ssdf_topo/config.py` reads:
`CH_HOST/CH_PORT/CH_USER/CH_PASSWORD/CH_DATABASE`, `TOPO_TENANT`, `TOPO_WINDOW_HOURS`,
`TOPO_COLLECTORS`, and `<PREFIX>_MCP_URL` / `<PREFIX>_MCP_TOKEN` for each collector
(`JUNOS`, `UNIFI`, `PANOS`, `PROXMOX`). No code change — this is a read-only check.

- [ ] **Step 3: Commit**

```bash
git add services/topo/infra/ENV.example
git commit -m "chore(m4): topo service env template (ENV.local is gitignored)"
```

## Task 6.2: systemd units (oneshot collect→resolve, on a timer)

**Files:**
- Create: `services/topo/infra/ssdf-topo.service`
- Create: `services/topo/infra/ssdf-topo.timer`

> One-shot, idempotent run: collectors append observations, then the resolver rebuilds the
> graph. No always-on daemon. The timer drives it (default 5 min). `ExecStartPre` runs the
> collectors so a collector failure (logged + skipped inside `run_collectors`) never blocks the
> resolver; `ExecStart` runs the resolver pass.

- [ ] **Step 1: Write the service unit**

`services/topo/infra/ssdf-topo.service`:
```ini
[Unit]
Description=SSDF M4 topo collect+resolve (one-shot)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
EnvironmentFile=/etc/ssdf-topo/ENV.local
ExecStartPre=/opt/ssdf-topo/bin/python -m ssdf_topo.collect_all
ExecStart=/opt/ssdf-topo/bin/python -m ssdf_topo.resolve_main
# A collector failure is logged+skipped in run_collectors; do not fail the whole unit on it.
SuccessExitStatus=0
```

- [ ] **Step 2: Write the timer unit**

`services/topo/infra/ssdf-topo.timer`:
```ini
[Unit]
Description=Run SSDF M4 topo collect+resolve every 5 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
AccuracySec=30s
Persistent=true

[Install]
WantedBy=timers.target
```

- [ ] **Step 3: Lint the unit files locally (syntax only)**

Run: `systemd-analyze verify services/topo/infra/ssdf-topo.service services/topo/infra/ssdf-topo.timer 2>&1 || true`
Expected: no fatal parse errors (warnings about missing ExecStart paths on this host are fine — the binary lives on ct107). If `systemd-analyze` is unavailable locally, skip; the real check is Task 6.5 Step 7.

- [ ] **Step 4: Commit**

```bash
git add services/topo/infra/ssdf-topo.service services/topo/infra/ssdf-topo.timer
git commit -m "feat(m4): systemd oneshot unit + 5-min timer for topo collect/resolve"
```

## Task 6.3: Integration test (live MCPs + live ClickHouse)

**Files:**
- Create: `services/topo/tests/test_integration.py`

> Marked `integration` so it is excluded from the default unit run. It exercises the real
> path: run collectors against the live MCPs (writing real observations), run the resolver, and
> assert the graph tables get populated. Uses the same env the service uses.

- [ ] **Step 1: Write the integration test**

```python
# tests/test_integration.py
"""Live end-to-end: collect against real MCPs, resolve, assert graph populated.

Run: cd services/topo && CH_HOST=<ct104> CH_PASSWORD=<pw> \
     JUNOS_MCP_URL=... JUNOS_MCP_TOKEN=... [other *_MCP_URL/_TOKEN] \
     uv run pytest -m integration -v
"""
import os
import pytest

from ssdf_topo.chwriter import ClickHouseWriter
from ssdf_topo.config import load_config
from ssdf_topo.collect_all import run_collectors, _build_collector, _now
from ssdf_topo.mcp_client import McpToolClient
from ssdf_topo.resolve_main import run_resolver

pytestmark = pytest.mark.integration

requires_ch = pytest.mark.skipif(
    not os.environ.get("CH_PASSWORD"), reason="CH_PASSWORD not set"
)


@requires_ch
def test_collect_then_resolve_populates_graph():
    config = load_config()
    writer = ClickHouseWriter(config)

    inserted = run_collectors(
        enabled=config.enabled_collectors,
        client_factory=lambda name: McpToolClient(config.mcp_endpoint(name)),
        collector_factory=_build_collector,
        writer=writer,
        now=_now(),
    )
    assert inserted > 0, "no observations collected from any live MCP"

    n_nodes, n_edges = run_resolver(
        writer, tenant=config.tenant_id, window_hours=config.window_hours
    )
    assert n_nodes > 0 and n_edges > 0

    # Graph tables actually hold rows for this tenant (FINAL to dedup the upserts).
    rows = writer.query(
        "SELECT count() AS c FROM ssdf.graph_nodes FINAL "
        "WHERE tenant_id = {t:String}",
        {"t": config.tenant_id},
    )
    assert int(rows[0]["c"]) >= n_nodes
```

- [ ] **Step 2: Confirm it is collected but skipped without creds**

Run: `cd services/topo && uv run pytest -m "not integration" -q`
Expected: PASS — the integration test is NOT run (marker excluded), unit suite still green.

Run: `cd services/topo && uv run pytest -m integration -q`
Expected: SKIPPED (no `CH_PASSWORD`) — confirms the gate works without a live DB.

- [ ] **Step 3: Commit**

```bash
git add services/topo/tests/test_integration.py
git commit -m "test(m4): live integration — collect+resolve populates graph tables"
```

## Task 6.4: Acceptance / exit-criteria test (the fused chain)

**Files:**
- Create: `services/topo/tests/test_acceptance.py`

> This encodes the M4 exit criteria from the spec (§8): a real endpoint resolves to **one**
> canonical node carrying MAC+IP+hostname; `locate` finds its switch/port/VLAN; `find_path`
> reaches the firewall; `enforcement_points` names the governing zone+rule; and both vendors
> appear in one graph. It calls the topology MCP tools on **ct106** over MCP (the same surface
> an LLM uses), so it validates the product contract, not just the DB.

- [ ] **Step 1: Write the acceptance test**

```python
# tests/test_acceptance.py
"""M4 exit criteria, exercised through the live ssdf-mcp-query topology tools (ct106).

Run: cd services/topo && SSDF_MCP_URL=http://<ct106>:30032/mcp \
     SSDF_MCP_TOKEN=<bearer> uv run pytest -m integration tests/test_acceptance.py -v
"""
import json
import os
import pytest

from ssdf_topo.mcp_client import McpToolClient
from ssdf_topo.config import McpEndpoint

pytestmark = pytest.mark.integration

requires_mcp = pytest.mark.skipif(
    not os.environ.get("SSDF_MCP_URL"), reason="SSDF_MCP_URL not set"
)


def _client() -> McpToolClient:
    return McpToolClient(
        McpEndpoint(
            url=os.environ["SSDF_MCP_URL"],
            token=os.environ.get("SSDF_MCP_TOKEN", ""),
        )
    )


def _call(client, tool, **args):
    # call_tool returns the tool's text payload (JSON) directly.
    return json.loads(client.call_tool(tool, args))


@requires_mcp
def test_fused_chain_host_to_switchport_to_firewall_rule():
    client = _client()

    # A snapshot must exist with nodes from BOTH vendors (juniper + paloalto).
    snap = _call(client, "topology_snapshot")
    providers = {n.get("source_provider") or n.get("provider") for n in snap["nodes"]}
    assert {"juniper", "paloalto"} & providers, "expected at least one vendor in graph"
    assert snap["node_count"] > 0 and snap["edge_count"] > 0

    # Pick a resolved host that carries a MAC (the identity anchor) + an IP.
    hosts = [
        n for n in snap["nodes"]
        if n["kind"] == "host"
        and any(k.startswith("mac:") for k in n.get("identifiers", {}))
        and any(k.startswith("ip:") for k in n.get("identifiers", {}))
    ]
    assert hosts, "no fully-resolved host (MAC+IP) in the graph"
    host = hosts[0]

    # get_entity returns the single canonical node for that host.
    entity = _call(client, "get_entity", node_id=host["node_id"])
    assert entity["node"]["node_id"] == host["node_id"]

    # locate: physical position (switch / port / vlan) — at least a switch-port neighbor.
    loc = _call(client, "locate", node_id=host["node_id"])
    assert loc["located"] is True
    assert loc.get("switch") or loc.get("port") or loc.get("vlan")

    # enforcement_points: the governing zone + rule for this host's traffic.
    enf = _call(client, "enforcement_points", node_id=host["node_id"])
    assert enf["points"], "expected at least one enforcement point (zone/rule)"
    assert any(p.get("rule") or p.get("zone") for p in enf["points"])
```

- [ ] **Step 2: Reconcile field names with the implemented tools**

Before running live, confirm the JSON keys asserted here (`node_count`, `edge_count`,
`identifiers`, `located`, `switch`/`port`/`vlan`, `points`, `rule`/`zone`,
`source_provider`) match what `topo_tools.py` actually returns (Phase 5, Task 5.3). If a
tool names a field differently, fix the assertion here — do not change the tool to satisfy
the test. Record any rename in this task before committing.

- [ ] **Step 3: Confirm skip-without-creds**

Run: `cd services/topo && uv run pytest -m integration tests/test_acceptance.py -q`
Expected: SKIPPED (no `SSDF_MCP_URL`).

- [ ] **Step 4: Commit**

```bash
git add services/topo/tests/test_acceptance.py
git commit -m "test(m4): acceptance — fused host->switchport->firewall->rule via MCP tools"
```

## Task 6.5: Provision LXC ct107 + deploy [LIVE checkpoint]

> **LIVE checkpoint — pause for operator confirmation before creating infrastructure.**
> Present the VMID (**ct107**) and chosen IP and get a "go" before `pct create`. ct107 is the
> reserved M4 VMID; do not reuse the protected VMIDs in `~/.claude/CLAUDE.md` (500, 600,
> 601–604, 100/301, 900) or the SSDF infra ct102/ct104/ct106.

**Files:** (none new — uses the units from Task 6.2 and the package from Phases 1–5)

- [ ] **Step 1: Confirm the ssdf_topo CH user exists (created in Phase 0)**

```bash
ssh root@pve3.example.com "pct exec 104 -- clickhouse-client --user ssdf_topo --password '<CH_TOPO_PASSWORD>' \
  --query 'SELECT count() FROM ssdf.events'"                    # SELECT on events works
ssh root@pve3.example.com "pct exec 104 -- clickhouse-client --user ssdf_topo --password '<CH_TOPO_PASSWORD>' \
  --query \"INSERT INTO ssdf.topo_observations (collector,source_device,layer,observation_type,subj_kind,subj_id) VALUES ('selftest','x','l3','arp_entry','host','ip:0.0.0.0')\""
```
Expected: SELECT returns a count; INSERT into `topo_observations` succeeds. If the user is
missing, re-run the Phase 0 user/grant SQL (main plan Task 0.1).

- [ ] **Step 2: Pick an unused IP and confirm ct107 is free**

```bash
ssh root@pve3.example.com "pct status 107" 2>&1            # expect: does not exist / free
ssh root@pve3.example.com "ping -c1 -W1 198.51.100.153" 2>&1 || echo "candidate IP free"
```
Record the chosen IP (e.g. **198.51.100.153**).

- [ ] **Step 3: Create and start the LXC (Debian, like M1/M2)**

```bash
ssh root@pve3.example.com "pct create 107 <template> \
  --hostname ssdf-topo --cores 1 --memory 512 --swap 256 \
  --net0 name=eth0,bridge=vmbr0,ip=<IP>/24,gw=198.51.100.1 \
  --rootfs local-lvm:4 --unprivileged 1 --start 1"
```
Use the same Debian template M2 used (discover with `pct config 106` / `pveam list local`).
Expected: container starts; `pct exec 107 -- ip a` shows `<IP>`.

- [ ] **Step 4: Install Python + the package into the LXC**

```bash
ssh root@pve3.example.com "pct exec 107 -- bash -lc 'apt-get update && apt-get install -y python3 python3-venv python3-pip'"
# Copy the package source (tar + pct push, the reliable mechanism M1/M2 used):
tar czf /tmp/ssdf-topo.tgz -C services topo
scp /tmp/ssdf-topo.tgz root@pve3.example.com:/tmp/
ssh root@pve3.example.com "pct push 107 /tmp/ssdf-topo.tgz /tmp/ssdf-topo.tgz && \
  pct exec 107 -- bash -lc 'mkdir -p /opt/src && tar xzf /tmp/ssdf-topo.tgz -C /opt/src'"
ssh root@pve3.example.com "pct exec 107 -- bash -lc 'cd /opt && python3 -m venv ssdf-topo && \
  /opt/ssdf-topo/bin/pip install /opt/src/topo'"
ssh root@pve3.example.com "pct exec 107 -- /opt/ssdf-topo/bin/python -c 'import ssdf_topo; print(\"ok\")'"
```
Expected: install succeeds; import prints `ok`. (`networkx` is only needed on ct106 for the
tools, not on ct107 — the resolver does not import it.)

- [ ] **Step 5: Push the env file (ENV.local) — secrets, not committed**

```bash
ssh root@pve3.example.com "pct exec 107 -- mkdir -p /etc/ssdf-topo"
# Fill a local copy from ENV.example with real CH_PASSWORD + MCP URLs/tokens, then push it:
scp services/topo/infra/ENV.local root@pve3.example.com:/tmp/ENV.local
ssh root@pve3.example.com "pct push 107 /tmp/ENV.local /etc/ssdf-topo/ENV.local && \
  pct exec 107 -- chmod 600 /etc/ssdf-topo/ENV.local && rm -f /tmp/ENV.local"
ssh root@pve3.example.com "rm -f /tmp/ENV.local"
```
Expected: `/etc/ssdf-topo/ENV.local` exists, mode 600.

- [ ] **Step 6: Install the systemd units and enable the timer**

```bash
for f in ssdf-topo.service ssdf-topo.timer; do
  scp services/topo/infra/$f root@pve3.example.com:/tmp/$f
  ssh root@pve3.example.com "pct push 107 /tmp/$f /etc/systemd/system/$f && rm -f /tmp/$f"
done
ssh root@pve3.example.com "pct exec 107 -- systemctl daemon-reload && \
  pct exec 107 -- systemctl enable --now ssdf-topo.timer"
```
Expected: timer enabled and active.

- [ ] **Step 7: Trigger one cycle and verify the graph fills**

```bash
ssh root@pve3.example.com "pct exec 107 -- systemctl start ssdf-topo.service"
ssh root@pve3.example.com "pct exec 107 -- journalctl -u ssdf-topo.service --no-pager -n 40"
# Confirm graph rows landed (run as the topo user against ct104):
ssh root@pve3.example.com "pct exec 104 -- clickhouse-client --user ssdf_topo --password '<CH_TOPO_PASSWORD>' \
  --query 'SELECT count() FROM ssdf.graph_nodes FINAL' "
ssh root@pve3.example.com "pct exec 104 -- clickhouse-client --user ssdf_topo --password '<CH_TOPO_PASSWORD>' \
  --query 'SELECT count() FROM ssdf.graph_edges FINAL' "
```
Expected: the journal shows `collect-all complete: N observations` and `resolver: X nodes, Y
edges upserted`; node/edge counts are > 0.

- [ ] **Step 8: Record the as-built coordinates (gitignored)**

Write the live VMID/IP, CH_TOPO_PASSWORD location, and per-MCP endpoints into
`services/topo/infra/ENV.local` (already gitignored via `*.local`). Do NOT commit secrets.

## Task 6.6: Update project docs — CLAUDE.md commands

**Files:**
- Modify: `CLAUDE.md` (the `## Commands` section)

- [ ] **Step 1: Add an M4 commands subsection after the M3 block**

Insert under `## Commands` (after the M2/M3 entries):
```markdown
### M4 (topology graph — services/topo + topology MCP tools)
- Unit tests: `cd services/topo && uv run pytest -m "not integration"`
- Live integration: `cd services/topo && CH_HOST=<ip> CH_PASSWORD=<pw> JUNOS_MCP_URL=… JUNOS_MCP_TOKEN=… uv run pytest -m integration`
- One collection cycle: `cd services/topo && uv run python -m ssdf_topo.collect_all`
- One resolver pass: `cd services/topo && uv run python -m ssdf_topo.resolve_main`
- Apply topology schema: `CH_HOST=<ip> ./scripts/apply_topology_schema.sh`
- Deployed: collectors+resolver on Proxmox LXC ct107 (`ssdf-topo`, no Docker) on a 5-min
  systemd timer; writes CH ct104 as `ssdf_topo`. Topology MCP tools (`get_entity`, `locate`,
  `neighbors`, `find_path`, `enforcement_points`, `topology_snapshot`) live on the existing
  `ssdf-mcp-query` (ct106). As-built coords in gitignored `services/topo/infra/ENV.local`.
```

- [ ] **Step 2: Commit**

```bash
git add CLAUDE.md
git commit -m "docs(m4): record topology graph commands + deployment in CLAUDE.md"
```

## Task 6.7: Update STATUS.md — reconcile M4 as built

**Files:**
- Modify: `docs/superpowers/STATUS.md`

- [ ] **Step 1: Mark M4 done in the forward roadmap**

In the forward roadmap, change the M4 bullet from a *proposed* entry to a *built* one. Replace
the `**M4 — dynamic connectivity graph.**` bullet with:
```markdown
- **M4 — dynamic connectivity / topology graph.** ✅ Built 2026-06-07. Collectors (junos,
  unifi, panos, proxmox) reuse the deployed read-only MCPs to gather LLDP/MAC/ARP/interface +
  VM-NIC facts into `ssdf.topo_observations`; a resolver fuses them with L3 flow rollups into
  `ssdf.graph_nodes`/`graph_edges` (MAC-anchored identity, IP-never-identity-alone). Six
  read-only topology tools added to `ssdf-mcp-query`. Deployed on LXC ct107 (5-min timer);
  graph tools on ct106. Spec: `specs/2026-06-07-ssdf-m4-topology-graph-design.md`; plan:
  `plans/2026-06-07-ssdf-m4-topology-graph*.md`.
```
> Note: this supersedes the earlier proposed M4 ("dynamic connectivity rollups into
> `ssdf.connectivity_edges_hourly`"). The shipped M4 is the richer topology-graph design.

- [ ] **Step 2: Add ct107 to the protected-infra list**

In `## Protected lab infra (do not reclaim)`, update the SSDF LXC line to include ct107:
```markdown
SSDF LXCs on Proxmox pve3.example.com: **ct102** (Vector), **ct104** (ClickHouse), **ct106**
(MCP query server), **ct107** (topo collectors+resolver). Plus the cluster-wide protected
VMIDs in `~/.claude/CLAUDE.md`.
```

- [ ] **Step 3: Commit**

```bash
git add docs/superpowers/STATUS.md
git commit -m "docs(m4): reconcile STATUS.md — M4 topology graph built, ct107 protected"
```

---

**Phase 6 done — M4 complete.** The full plan set:
`...-topology-graph.md` (Phases 0–2) → `...-collectors.md` (3) → `...-resolver.md` (4) →
`...-mcp-tools.md` (5) → `...-deploy.md` (6).
