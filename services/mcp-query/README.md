# ssdf-mcp-query (SSDF M2)

Read-only MCP server exposing `ssdf.events` to LLM agents.

## Develop
- Install: `uv sync --extra dev`
- Unit tests: `uv run pytest -m "not integration"`
- All tests (needs live ClickHouse): `uv run pytest`
- Run locally: `uv run python -m ssdf_mcp_query.server`

## Tools
`query_flows`, `describe_schema`, `top_talkers`, `run_sql` (guarded SELECT-only).

Config via env (see `.env.example`). Deployed as a systemd service on a Proxmox LXC.
