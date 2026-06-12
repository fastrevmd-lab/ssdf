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

# TLS (edge-hardening L1a): same envs the services use.
_TLS_KWARGS = (
    {"interface": "https", "ca_cert": os.environ.get("CH_CA_FILE")}
    if os.environ.get("CH_SECURE") == "1"
    else {}
)


def _public_client():
    return clickhouse_connect.get_client(
        host=CH_HOST, port=CH_PORT,
        username=os.environ.get("CH_PUBLIC_USER", "ssdf_public"),
        password=PUBLIC_PW, database="ssdf_public",
        **_TLS_KWARGS,
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
        **_TLS_KWARGS,
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
