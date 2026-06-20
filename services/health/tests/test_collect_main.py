from datetime import datetime, timezone

from ssdf_health import collect_main
from ssdf_health.config import Config
from ssdf_health.gauge import Gauge


def _config(**over):
    base = dict(
        ch_host="h", ch_port=8443, ch_user="ssdf_health", ch_password="p",
        ch_database="ssdf", tenant_id="t_main",
        enabled_collectors=("junos", "panos", "unifi", "proxmox"),
        junos_devices=["vSRX-test10"], panos_device="panosvm",
        unifi_macs=["aa:bb:cc:dd:ee:ff"], unifi_site_id="default",
    )
    base.update(over)
    return Config(**base)


def test_build_collector_passes_device_config():
    config = _config()
    junos = collect_main.build_collector("junos", config)
    assert junos.devices == ["vSRX-test10"]
    panos = collect_main.build_collector("panos", config)
    assert panos.device == "panosvm"
    unifi = collect_main.build_collector("unifi", config)
    assert unifi.macs == ["aa:bb:cc:dd:ee:ff"]
    assert unifi.site_id == "default"
    proxmox = collect_main.build_collector("proxmox", config)
    assert proxmox.name == "proxmox"


def test_run_with_fakes_writes_all_gauges():
    config = _config(enabled_collectors=("fake",))

    class _Fake:
        name = "fake"
        def collect(self, client, now):
            return [Gauge("p", "d", "device", "cpu", "", "cpu_util_pct",
                          1.0, "percent", "")]

    captured = []

    class _Writer:
        def insert_gauges(self, gauges, now):
            captured.extend(gauges)
            return len(gauges)

    total = collect_main.run(
        config,
        client_factory=lambda name: None,
        collector_factory=lambda name: _Fake(),
        writer=_Writer(),
        now=datetime(2026, 6, 20, tzinfo=timezone.utc),
    )
    assert total == 1
    assert captured[0].metric_name == "cpu_util_pct"
