"""Declared liveness subjects: what proves each source and resolver is alive.

A set derived from observations cannot miss a thing that was never observed —
UniFi produced zero events for 30+ days and nothing noticed, because nothing was
present to go stale. Sources and resolvers are therefore DECLARED here rather
than derived. The device fleet stays derived; that is ``ingest_status``.

Each entry names the observable that proves liveness, which is not always
``ssdf.events``: UniFi IPS detections are rare by design, so the collector poll
is the honest signal for "is the integration alive".
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Subject:
    """One thing whose liveness is asserted, and the signal that proves it."""

    name: str
    kind: str  # "source" | "resolver"
    table: str
    ts_column: str
    filter_column: str | None
    filter_value: str | None
    budget_hours: float
    note: str


# INVARIANT: ts_column must be a WRITE-time column, never a data-time column.
# ssdf_public.metric_timeseries.bucket_start lags ~0.5h by design and would
# report a healthy resolver stale; inserted_at is the write time. Verify this
# when adding a subject — a table offering only data time is not a valid signal.
MANIFEST: tuple[Subject, ...] = (
    Subject(
        name="juniper",
        kind="source",
        table="ssdf.events",
        ts_column="timestamp",
        filter_column="event_provider",
        filter_value="juniper",
        budget_hours=1.0,
        note="Continuous SRX security stream; quiet for an hour means something broke.",
    ),
    Subject(
        name="paloalto",
        kind="source",
        table="ssdf.events",
        ts_column="timestamp",
        filter_column="event_provider",
        filter_value="paloalto",
        budget_hours=1.0,
        note="Continuous PAN-OS traffic stream.",
    ),
    Subject(
        name="proxmox",
        kind="source",
        table="ssdf.events",
        ts_column="timestamp",
        filter_column="event_provider",
        filter_value="proxmox",
        budget_hours=24.0,
        note="Event-driven: auth and task events only on activity. Idle overnight is correct.",
    ),
    Subject(
        name="unifi",
        kind="source",
        table="ssdf.health_metrics",
        ts_column="timestamp",
        filter_column="provider",
        filter_value="unifi",
        budget_hours=0.5,
        note=(
            "Checked against the 5-minute collector poll, NOT ssdf.events: IPS "
            "detections are rare by design, so event silence is not a fault while "
            "a dead integration is."
        ),
    ),
    Subject(
        name="ssdf-topo",
        kind="resolver",
        table="ssdf.topo_observations",
        ts_column="observed_at",
        filter_column=None,
        filter_value=None,
        budget_hours=0.25,
        note="5-minute timer; 0.25h allows three missed runs.",
    ),
    Subject(
        name="ssdf-entity",
        kind="resolver",
        table="ssdf.entity_edges",
        ts_column="last_seen",
        filter_column=None,
        filter_value=None,
        budget_hours=0.25,
        note=(
            "5-minute timer. last_seen reads event-derived but is stamped by the "
            "resolver at write time — verified live while flow events were ~0."
        ),
    ),
    Subject(
        name="ssdf-policy",
        kind="resolver",
        table="ssdf.entities",
        ts_column="last_seen",
        filter_column="source",
        filter_value="configured",
        budget_hours=2.0,
        note=(
            "Hourly timer. This is the signal that was flat for four days while the "
            "resolver ran, exited 0 and logged '0 entities upserted'."
        ),
    ),
    Subject(
        name="ssdf-health",
        kind="resolver",
        table="ssdf.health_metrics",
        ts_column="timestamp",
        filter_column=None,
        filter_value=None,
        budget_hours=0.25,
        note="5-minute timer.",
    ),
    Subject(
        name="ssdf-public-metrics",
        kind="resolver",
        table="ssdf_public.metric_timeseries",
        ts_column="inserted_at",
        filter_column=None,
        filter_value=None,
        budget_hours=0.25,
        note="5-minute timer. inserted_at, not bucket_start, which lags by design.",
    ),
)


def signal_label(subject: Subject) -> str:
    """Human-readable description of what is being probed."""
    if subject.filter_column is not None:
        return f"{subject.table}({subject.filter_column}={subject.filter_value})"
    return f"{subject.table}.{subject.ts_column}"


def build_subject_sql(subject: Subject) -> tuple[str, dict]:
    """Build the freshness probe for one subject.

    Table, timestamp and filter column come only from the frozen MANIFEST and are
    never caller-supplied; the filter VALUE is bound as a parameter. ``count()``
    lets the caller distinguish "never observed" from "observed long ago".
    """
    params: dict = {}
    where = ""
    if subject.filter_column is not None:
        where = f" WHERE {subject.filter_column} = {{fval:String}}"
        params["fval"] = subject.filter_value
    sql = (
        f"SELECT count() AS n, max({subject.ts_column}) AS last_seen, "
        f"dateDiff('second', max({subject.ts_column}), now()) / 3600.0 AS hours_since "
        f"FROM {subject.table}{where}"
    )
    return sql, params
