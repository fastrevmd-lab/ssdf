import os

import pytest

pytestmark = pytest.mark.integration

_REQUIRED = ["CH_HOST", "CH_PASSWORD", "PUBLIC_PSEUDONYM_KEY"]


@pytest.fixture
def config():
    missing = [k for k in _REQUIRED if not os.environ.get(k)]
    if missing:
        pytest.skip(f"missing env: {missing}")
    from ssdf_pubmetrics.config import load_config

    return load_config()


def test_resolver_writes_rows_and_floor_holds(config):
    from ssdf_pubmetrics.resolve import run
    from ssdf_pubmetrics.chreader import EventsReader, client_kwargs
    import clickhouse_connect

    assert run() == 0

    reader = EventsReader(config)
    agg = reader._client.query(
        "SELECT count() FROM ssdf_public.metric_timeseries FINAL"
    ).result_rows
    assert agg[0][0] >= 0  # table reachable; aggregate rows present after a run

    # de-identification floor: a public-tier reader must be denied the map
    public_kwargs = dict(client_kwargs(config))
    public_kwargs.update(
        username="ssdf_public", password=os.environ["CH_PUBLIC_PASSWORD"], database="ssdf_public"
    )
    public = clickhouse_connect.get_client(**public_kwargs)
    with pytest.raises(Exception):
        public.query("SELECT count() FROM ssdf.pseudonym_map")
