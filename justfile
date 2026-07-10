set dotenv-load := false
set export := false

setup:
    for service in services/*; do if [ -f "$service/pyproject.toml" ]; then (cd "$service" && uv sync --all-extras --locked); fi; done
    pre-commit install

dev:
    @echo "Choose a service; for example: cd services/mcp-query && uv run python -m ssdf_mcp_query.server"

fmt:
    git diff --check

lint:
    ruff check services

test:
    for service in services/*; do if [ -f "$service/pyproject.toml" ]; then echo "==> $service"; (cd "$service" && uv run pytest -m "not integration" -q); fi; done

guard: lint test

integration:
    @if [ "${CONFIRM_LAB_INTEGRATION:-}" != "yes" ]; then echo "Set CONFIRM_LAB_INTEGRATION=yes after reviewing ClickHouse/MCP targets and write behavior."; exit 2; fi
    for service in services/*; do if [ -f "$service/pyproject.toml" ]; then echo "==> $service"; (cd "$service" && uv run pytest -m integration -q); fi; done

e2e:
    @echo "No browser end-to-end suite is defined for SSDF."

security:
    trivy fs --scanners vuln,misconfig,secret --exit-code 1 .

release-check: fmt lint test security
