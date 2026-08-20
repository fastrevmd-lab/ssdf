"""fabric_status: is every ingest source and resolver still producing?

Answers the question nobody could ask on 2026-08-19, when three collectors had
been dead for four days, the policy resolver had produced nothing while exiting
0, and UniFi had been silent for a month — none of it visible without
hand-querying ClickHouse.
"""

from __future__ import annotations

import datetime as _dt

from .fabric_manifest import MANIFEST, build_subject_sql, signal_label


class FabricTools:
    """Runs the declared liveness probes. Stateless apart from its stores."""

    def __init__(self, ch_client, liveness=None, manifest=MANIFEST):
        self._ch = ch_client
        self._liveness = liveness
        self._manifest = manifest

    def _probe(self, subject) -> dict:
        """Probe one subject. A query failure becomes a reported error, never a
        silent omission."""
        base = {
            "name": subject.name,
            "kind": subject.kind,
            "signal": signal_label(subject),
            "budget_hours": subject.budget_hours,
            "note": subject.note,
        }
        sql, params = build_subject_sql(subject)
        try:
            rows = self._ch.run(sql, params)["rows"]
        except Exception as exc:  # surfaced in the payload, not just logged
            return {
                **base,
                "last_seen": None,
                "hours_since": None,
                "stale": True,
                "error": str(exc),
            }

        row = rows[0] if rows else {}
        count = row.get("n") or 0
        hours_since = row.get("hours_since")
        if not count or hours_since is None:
            # Never observed. Absence is the signal, not a missing row.
            return {**base, "last_seen": None, "hours_since": None, "stale": True}

        last_seen = row.get("last_seen")
        return {
            **base,
            "last_seen": str(last_seen) if last_seen is not None else None,
            "hours_since": hours_since,
            "stale": hours_since > subject.budget_hours,
        }

    def fabric_status(self) -> dict:
        """Report freshness for every declared source and resolver.

        Returns {healthy, checked_at, subjects[], devices, summary}. ``healthy``
        is true only when nothing is stale and nothing errored.
        """
        subjects = [self._probe(s) for s in self._manifest]
        subjects.sort(key=lambda s: (not s["stale"], s["name"]))

        stale = sum(1 for s in subjects if s["stale"])
        errored = sum(1 for s in subjects if "error" in s)

        result = {
            "healthy": stale == 0 and errored == 0,
            "checked_at": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="milliseconds"),
            "subjects": subjects,
            "devices": None,
            "summary": {
                "total": len(subjects),
                "stale": stale,
                "fresh": len(subjects) - stale,
                "errored": errored,
            },
        }

        if self._liveness is not None:
            try:
                result["devices"] = self._liveness.ingest_status()["summary"]
            except Exception as exc:
                result["devices_error"] = str(exc)
                result["healthy"] = False

        return result
