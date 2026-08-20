"""ingest_status: per-firewall ingest liveness tool."""

from __future__ import annotations

import datetime as _dt


def _since(hours: int) -> str:
    return (_dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(hours=hours)).isoformat(
        timespec="milliseconds"
    )


def _short_host(name: str) -> str:
    """First DNS label of a hostname, case preserved. Reused from access_tools."""
    try:
        import ipaddress

        ipaddress.ip_address(name)
        return name
    except ValueError:
        return name.split(".", 1)[0]


def build_recent_observer_hostnames_sql(since_iso: str, tenant: str) -> tuple[str, dict]:
    """Distinct non-empty observer_hostname values per provider in-window.

    Returns rows {observer_hostname, provider, max_timestamp, hours_since} where
    observer_hostname != '' and timestamp >= since. Computes hours_since in SQL
    (dateDiff('second', max(timestamp), now())/3600.0) to avoid Python tz-aware/naive
    datetime subtraction errors. The short-host normalization (first DNS label) happens
    in Python, not SQL, so this query returns the full FQDN for downstream _short_host
    processing.
    """
    sql = (
        "SELECT observer_hostname, event_provider AS provider, "
        "max(timestamp) AS max_timestamp, "
        "dateDiff('second', max(timestamp), now()) / 3600.0 AS hours_since "
        "FROM ssdf.events "
        "WHERE tenant_id = {tenant:String} AND observer_hostname != '' "
        "AND timestamp >= parseDateTimeBestEffort({since:String}) "
        "GROUP BY observer_hostname, provider"
    )
    return sql, {"tenant": tenant, "since": since_iso}


class LivenessTools:
    """Stateless liveness tools bound to a GraphStore + EntityStore."""

    def __init__(self, graph_store, entity_store, default_staleness_hours: int = 2):
        self._graph = graph_store
        self._entity = entity_store
        self._staleness = default_staleness_hours

    def ingest_status(self, staleness_hours: int | None = None) -> dict:
        """Per-firewall ingest liveness: which devices are logging, how stale.

        Combines the expected set (topology firewall nodes + recent observer_hostname
        values over 7d) with actual per-device last-event times. A device that
        STOPPED sending entirely (e.g. vSRX-twin went silent) is caught by including
        topology firewalls regardless of their last_seen.

        Args:
            staleness_hours: threshold for marking a firewall stale (default 2)

        Returns:
            {
              "firewalls": [
                {
                  "name": str,
                  "provider": str | null,
                  "last_event": ISO-8601 | null,
                  "hours_since": float | null,
                  "stale": bool
                }
              ],
              "summary": {"total": int, "stale": int, "fresh": int}
            }
        """
        staleness = staleness_hours if staleness_hours is not None else self._staleness

        # Expected set part 1: topology firewall nodes (kind='device', attrs['role']='firewall')
        topo_firewalls = self._graph.nodes_by_attr(role="firewall", kind="device")
        topo_by_name: dict[str, dict] = {}
        for node in topo_firewalls:
            name = node.get("name", "")
            if name:
                # Topology nodes may not have a provider in identifiers; leave it null
                provider = node.get("identifiers", {}).get("provider")
                topo_by_name[name] = {
                    "name": name,
                    "provider": provider,
                    "last_event": None,
                    "hours_since": None,
                    "stale": True,
                }  # assume stale until proven fresh

        # Expected set part 2: distinct observer_hostname over last 7d (per-provider max)
        seven_days_ago = _since(24 * 7)
        sql, params = build_recent_observer_hostnames_sql(seven_days_ago, "t_main")
        rows = self._entity._ch.run(sql, params)["rows"]

        event_by_name: dict[str, dict] = {}
        for row in rows:
            full_name = row.get("observer_hostname", "")
            if not full_name:
                continue
            short_name = _short_host(full_name)
            provider = row.get("provider", "")
            max_ts_str = row.get("max_timestamp", "")
            hours_since = row.get("hours_since")
            if not max_ts_str or hours_since is None:
                continue
            # hours_since is computed in SQL; staleness check uses it directly
            is_stale = hours_since > staleness

            # If we already have this name, keep the most recent event (smallest hours_since)
            if short_name in event_by_name:
                existing = event_by_name[short_name]
                if hours_since < existing["hours_since"]:
                    event_by_name[short_name] = {
                        "name": short_name,
                        "provider": provider,
                        "last_event": max_ts_str,
                        "hours_since": hours_since,
                        "stale": is_stale,
                    }
            else:
                event_by_name[short_name] = {
                    "name": short_name,
                    "provider": provider,
                    "last_event": max_ts_str,
                    "hours_since": hours_since,
                    "stale": is_stale,
                }

        # Merge: topology firewalls get their event data stamped if present
        for name in topo_by_name:
            if name in event_by_name:
                topo_by_name[name].update(event_by_name[name])

        # Any event-only device (not in topology) is also part of the expected set
        for name, event_data in event_by_name.items():
            if name not in topo_by_name:
                topo_by_name[name] = event_data

        # Build result: sort stale-first, then by name
        firewalls = sorted(topo_by_name.values(), key=lambda fw: (not fw["stale"], fw["name"]))

        total = len(firewalls)
        stale = sum(1 for fw in firewalls if fw["stale"])
        fresh = total - stale

        return {"firewalls": firewalls, "summary": {"total": total, "stale": stale, "fresh": fresh}}
