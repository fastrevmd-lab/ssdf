"""Live-CH integration: every corpus reference_sql executes; audit join works.

Run:
  cd services/evals && CH_HOST=<ip> CH_PORT=8443 CH_SECURE=1 \
    CH_CA_FILE=../../infra/tls-local/ssdf-ca.crt \
    CH_PASSWORD=<ro_pw> CH_AUDIT_VERIFY_PASSWORD=<av_pw> \
    [CH_AUDIT_PASSWORD=<audit_pw>] uv run pytest -m integration -v
"""

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif("CH_HOST" not in os.environ, reason="needs live ClickHouse (CH_HOST)"),
]

GOLDEN = Path(__file__).resolve().parents[1] / "golden" / "core.yaml"


@pytest.fixture(scope="module")
def config():
    from ssdf_evals.config import load_config

    return load_config()


@pytest.fixture(scope="module")
def query_client(config):
    import clickhouse_connect
    from ssdf_evals.config import client_kwargs

    return clickhouse_connect.get_client(**client_kwargs(config))


@pytest.fixture(scope="module")
def audit_client(config):
    import clickhouse_connect
    from ssdf_evals.config import client_kwargs

    return clickhouse_connect.get_client(
        **client_kwargs(config, username="ssdf_audit_verify", password=config.audit_verify_password)
    )


def test_every_reference_sql_executes(query_client):
    """Corpus SQL is live-valid: executes as ssdf_ro and returns rows-shaped data.

    Empty results are allowed (windows move); errors are corpus bugs.
    """
    from ssdf_evals.corpus import load_corpus

    failures = []
    checked = 0
    for question in load_corpus(GOLDEN):
        if question.predicate["type"] != "reference_sql":
            continue
        checked += 1
        try:
            rows = query_client.query(question.predicate["sql"]).result_rows
            assert isinstance(rows, list)
        except Exception as exc:  # collect all, report together
            failures.append(f"{question.id}: {exc}")
    assert checked > 0, "no reference_sql questions found in corpus — vacuous pass"
    assert not failures, "corpus SQL errors:\n" + "\n".join(failures)


def test_audit_verify_can_read_audit(audit_client):
    rows = audit_client.query("SELECT count() FROM ssdf.audit").result_rows
    assert rows[0][0] >= 0


@pytest.mark.skipif(
    "CH_AUDIT_PASSWORD" not in os.environ, reason="needs ssdf_audit writer (CH_AUDIT_PASSWORD)"
)
def test_audit_join_roundtrip(config, audit_client):
    """Insert a synthetic audit row as ssdf_audit; fetch_tools must see it."""
    import clickhouse_connect
    from ssdf_evals.auditcheck import fetch_tools
    from ssdf_evals.config import client_kwargs

    writer = clickhouse_connect.get_client(
        **client_kwargs(config, username="ssdf_audit", password=os.environ["CH_AUDIT_PASSWORD"])
    )
    now = datetime.now(timezone.utc)
    principal = f"eval-inttest-{now.strftime('%H%M%S')}"
    writer.insert(
        "ssdf.audit",
        [[now, principal, "eval-test", "locate", "{}", ["topology"], "allow", 1, ""]],
        column_names=[
            "ts",
            "principal",
            "tier",
            "tool",
            "args",
            "data_classes",
            "decision",
            "row_count",
            "error",
        ],
    )

    tools = fetch_tools(
        audit_client,
        principal,
        now - timedelta(seconds=2),
        now + timedelta(seconds=2),
        slop_secs=config.audit_slop_secs,
    )
    assert tools == ["locate"]
