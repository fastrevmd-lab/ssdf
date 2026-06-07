# tests/test_collect_all.py
"""Tests for the collect_all entrypoint (multi-collector orchestration)."""

from ssdf_topo.collect_all import run_collectors
from ssdf_topo.collectors.base import REGISTRY, register
from ssdf_topo.models import Observation

NOW = "2026-06-07T00:00:00+00:00"


class FakeClient:
    def call_tool(self, name: str, args: dict | None = None) -> str:
        return "[]"


class RecordingWriter:
    def __init__(self):
        self.inserted: list[Observation] = []

    def insert_observations(self, obs: list[Observation]) -> int:
        self.inserted.extend(obs)
        return len(obs)


# Throwaway collectors registered only for this test module
@register("_ok_test")
class _OkCollector:
    name = "_ok_test"

    def collect(self, client, now: str) -> list[Observation]:
        return [
            Observation(
                observed_at=now,
                collector="_ok_test",
                source_device="fake",
                layer="l2",
                observation_type="test_obs",
                subj_kind="host",
                subj_id="mac:aa:bb:cc:dd:ee:ff",
            )
        ]


@register("_boom_test")
class _BoomCollector:
    name = "_boom_test"

    def collect(self, client, now: str) -> list[Observation]:
        raise RuntimeError("simulated failure")


def test_run_collectors_skips_failing_and_inserts():
    writer = RecordingWriter()
    total = run_collectors(
        enabled=("_ok_test", "_boom_test"),
        client_factory=lambda name: FakeClient(),
        collector_factory=lambda name: REGISTRY[name](),
        writer=writer,
        now=NOW,
    )
    assert total == 1
    assert len(writer.inserted) == 1
    assert writer.inserted[0].collector == "_ok_test"
