from ssdf_mcp_query.fabric_manifest import (
    MANIFEST,
    Subject,
    build_subject_sql,
    signal_label,
)

EXPECTED_SOURCES = {"juniper", "paloalto", "proxmox", "unifi"}
EXPECTED_RESOLVERS = {
    "ssdf-topo",
    "ssdf-entity",
    "ssdf-policy",
    "ssdf-health",
    "ssdf-public-metrics",
}


def test_sql_binds_the_filter_value_as_a_parameter():
    """Filter values must never be interpolated into SQL text."""
    subject = Subject(
        name="juniper",
        kind="source",
        table="ssdf.events",
        ts_column="timestamp",
        filter_column="event_provider",
        filter_value="juniper",
        budget_hours=1.0,
        note="continuous flow/security stream",
    )
    sql, params = build_subject_sql(subject)

    assert "{fval:String}" in sql
    assert params == {"fval": "juniper"}
    assert "'juniper'" not in sql
    assert "FROM ssdf.events" in sql
    assert "max(timestamp)" in sql
    # hours_since computed in SQL: tz-aware datetimes break Python subtraction.
    assert "dateDiff" in sql
    # count() lets the caller tell "never observed" from "observed long ago".
    assert "count()" in sql


def test_sql_omits_the_where_clause_when_there_is_no_filter():
    subject = Subject(
        name="ssdf-topo",
        kind="resolver",
        table="ssdf.topo_observations",
        ts_column="observed_at",
        filter_column=None,
        filter_value=None,
        budget_hours=0.25,
        note="5-minute timer",
    )
    sql, params = build_subject_sql(subject)

    assert "WHERE" not in sql
    assert params == {}


def test_signal_label_is_human_readable():
    with_filter = Subject(
        name="unifi",
        kind="source",
        table="ssdf.health_metrics",
        ts_column="timestamp",
        filter_column="provider",
        filter_value="unifi",
        budget_hours=0.5,
        note="n",
    )
    without = Subject(
        name="ssdf-topo",
        kind="resolver",
        table="ssdf.topo_observations",
        ts_column="observed_at",
        filter_column=None,
        filter_value=None,
        budget_hours=0.25,
        note="n",
    )
    assert signal_label(with_filter) == "ssdf.health_metrics(provider=unifi)"
    assert signal_label(without) == "ssdf.topo_observations.observed_at"


def test_manifest_covers_every_source_and_resolver():
    """Tripwire: adding an ingest source or resolver without declaring it here
    fails CI. Update EXPECTED_* deliberately, never to make the test pass."""
    by_kind: dict[str, set[str]] = {"source": set(), "resolver": set()}
    for subject in MANIFEST:
        by_kind[subject.kind].add(subject.name)

    assert by_kind["source"] == EXPECTED_SOURCES
    assert by_kind["resolver"] == EXPECTED_RESOLVERS


def test_manifest_entries_are_well_formed():
    names = [s.name for s in MANIFEST]
    assert len(names) == len(set(names)), "subject names must be unique"
    for subject in MANIFEST:
        assert subject.kind in {"source", "resolver"}
        assert subject.budget_hours > 0
        # note is required, not decorative: budgets are judgement calls and an
        # undocumented one cannot be reviewed later.
        assert subject.note.strip(), f"{subject.name} has no note"
        # A filter needs both halves or neither.
        assert (subject.filter_column is None) == (subject.filter_value is None)


def test_public_metrics_uses_write_time_not_bucket_time():
    """bucket_start lags ~0.5h by design and would read stale against a 0.25h
    budget while the resolver is healthy. Measured on the live fabric."""
    subject = next(s for s in MANIFEST if s.name == "ssdf-public-metrics")
    assert subject.ts_column == "inserted_at"


def test_sql_max_alias_cannot_shadow_ts_column():
    """Regression: when ts_column is 'last_seen', aliasing max(last_seen) AS
    last_seen makes the second max(last_seen) in dateDiff reference the alias
    (an aggregate), which ClickHouse rejects as ILLEGAL_AGGREGATION. The alias
    must not collide with any ts_column name."""
    for subject in MANIFEST:
        sql, _ = build_subject_sql(subject)
        # The SQL must contain max(ts_column) AS <something>, where <something> != ts_column
        assert f"max({subject.ts_column})" in sql, (
            f"{subject.name}: missing max({subject.ts_column})"
        )
        # The alias must be probe_max_ts, not the ts_column name
        assert f"AS {subject.ts_column}" not in sql, (
            f"{subject.name}: max() aliased as {subject.ts_column} shadows the source column"
        )
        # Confirm the probe_max_ts alias is present (not just asserting absence)
        assert "AS probe_max_ts" in sql, f"{subject.name}: missing probe_max_ts alias"
