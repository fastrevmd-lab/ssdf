# ssdf-common

Shared utilities for SSDF services — eliminates byte-identical duplication across topo, entity, policy, health, public-metrics, evals, and mcp-query.

## Modules

- **`config.py`**: `ConfigError`, `McpEndpoint`, `env_bool`, `load_mcp_endpoint`
- **`clickhouse.py`**: `client_kwargs`, `get_client`, `client_kwargs_from_config` — the unified TLS-aware ClickHouse connection builder
- **`mcp_client.py`**: `extract_text`, `McpToolClient` — synchronous MCP tool caller for collectors
- **`collectors.py`**: `REGISTRY`, `register`, `get_collector`, `run_collectors` — fault-isolated collector orchestration

## Usage

Add as a path dependency in a service:

```toml
[project]
dependencies = [
    "ssdf-common",
    # ...
]

[tool.uv.sources]
ssdf-common = { path = "../common", editable = true }
```

Then import:

```python
from ssdf_common.config import ConfigError, load_mcp_endpoint
from ssdf_common.clickhouse import client_kwargs, get_client
from ssdf_common.mcp_client import McpToolClient, extract_text
from ssdf_common.collectors import register, run_collectors
```
