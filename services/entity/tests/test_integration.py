import os
import pytest

pytestmark = pytest.mark.integration

from ssdf_entity.chwriter import ClickHouseEntityWriter
from ssdf_entity.config import load_config
from ssdf_entity.resolve_main import run_resolver


@pytest.fixture
def writer():
    if not os.environ.get("CH_PASSWORD"):
        pytest.skip("CH_PASSWORD not set; live integration skipped")
    return ClickHouseEntityWriter(load_config())


def test_resolver_writes_entities_against_live_ch(writer):
    n_entities, n_edges = run_resolver(writer, tenant="t_main", window_hours=720)
    assert n_entities >= 0  # may be 0 if no flows in window; assert the call path works
    rows = writer.query(
        "SELECT count() AS c FROM ssdf.entities FINAL WHERE tenant_id = {t:String}", {"t": "t_main"}
    )
    assert rows[0]["c"] >= n_entities
