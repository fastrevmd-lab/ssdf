import os
import time
import uuid
import pytest
import clickhouse_connect

pytestmark = pytest.mark.integration

CH_HOST = os.environ.get("CH_HOST")
AUDIT_PW = os.environ.get("CH_AUDIT_PASSWORD")
RO_PW = os.environ.get("CH_PASSWORD")


def _audit_client():
    return clickhouse_connect.get_client(
        host=CH_HOST, port=int(os.environ.get("CH_PORT", "8123")),
        username=os.environ.get("CH_AUDIT_USER", "ssdf_audit"),
        password=AUDIT_PW, database="ssdf",
    )


@pytest.mark.skipif(not (CH_HOST and AUDIT_PW), reason="needs live CH + ssdf_audit pw")
def test_audit_row_inserts_and_round_trips():
    from ssdf_mcp_query.audit import make_ch_auditor
    from ssdf_mcp_query.config import load_config

    principal = f"itest-{uuid.uuid4().hex[:8]}"
    auditor = make_ch_auditor(load_config())
    auditor.record(
        principal=principal, tier="sovereign", tool="query_flows",
        args={"dst_port": 443}, data_classes=["security_log"],
        decision="allow", row_count=3, error="",
    )
    time.sleep(0.5)
    # Read back as an admin/ro path that CAN select (ssdf_ro has no audit grant,
    # so use a privileged client via CH_ADMIN_* if provided; else skip read-back).
    admin_pw = os.environ.get("CH_ADMIN_PASSWORD")
    if not admin_pw:
        pytest.skip("set CH_ADMIN_PASSWORD to verify read-back")
    admin = clickhouse_connect.get_client(
        host=CH_HOST, port=int(os.environ.get("CH_PORT", "8123")),
        username=os.environ.get("CH_ADMIN_USER", "default"),
        password=admin_pw, database="ssdf",
    )
    rows = admin.query(
        "SELECT tool, decision, row_count, data_classes FROM ssdf.audit "
        "WHERE principal = {p:String} ORDER BY ts DESC LIMIT 1",
        parameters={"p": principal},
    ).result_rows
    assert rows, "audit row not found"
    tool, decision, row_count, data_classes = rows[0]
    assert tool == "query_flows"
    assert decision == "allow"
    assert row_count == 3
    assert list(data_classes) == ["security_log"]


@pytest.mark.skipif(not (CH_HOST and AUDIT_PW), reason="needs live CH + ssdf_audit pw")
def test_ssdf_audit_cannot_select():
    from clickhouse_connect.driver.exceptions import DatabaseError

    client = _audit_client()
    with pytest.raises(DatabaseError):
        client.query("SELECT count() FROM ssdf.audit")
