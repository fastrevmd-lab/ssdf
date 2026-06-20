from datetime import datetime, timezone

from ssdf_health.config import Config
from ssdf_health.chwriter import client_kwargs, health_rows, HEALTH_COLUMNS
from ssdf_health.gauge import Gauge


def _config(**over):
    base = dict(
        ch_host="h", ch_port=8443, ch_user="ssdf_health", ch_password="p",
        ch_database="ssdf", tenant_id="t_main", enabled_collectors=("proxmox",),
        junos_devices=[], panos_device="panosvm", unifi_macs=[], unifi_site_id="default",
    )
    base.update(over)
    return Config(**base)


def test_client_kwargs_adds_tls_when_secure():
    kwargs = client_kwargs(_config(ch_secure=True, ch_ca_file="/ca.crt"))
    assert kwargs["interface"] == "https"
    assert kwargs["ca_cert"] == "/ca.crt"


def test_client_kwargs_plain_when_not_secure():
    kwargs = client_kwargs(_config())
    assert "interface" not in kwargs


def test_health_rows_maps_gauge_fields_in_column_order():
    now = datetime(2026, 6, 20, tzinfo=timezone.utc)
    gauge = Gauge("juniper", "vSRX-test10", "device", "cpu", "",
                  "cpu_util_pct", 5.0, "percent", "Idle 95 percent")
    rows = health_rows([gauge], now, "t_main")
    assert len(rows) == 1
    row = dict(zip(HEALTH_COLUMNS, rows[0]))
    assert row["timestamp"] == now
    assert row["tenant_id"] == "t_main"
    assert row["provider"] == "juniper"
    assert row["device"] == "vSRX-test10"
    assert row["scope"] == "device"
    assert row["metric_class"] == "cpu"
    assert row["sensor"] == ""
    assert row["metric_name"] == "cpu_util_pct"
    assert row["metric_value"] == 5.0
    assert row["unit"] == "percent"
    assert row["raw"] == "Idle 95 percent"


def test_health_rows_empty():
    assert health_rows([], datetime.now(timezone.utc), "t_main") == []
