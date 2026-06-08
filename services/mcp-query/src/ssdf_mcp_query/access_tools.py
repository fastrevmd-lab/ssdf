"""explain_access: end-to-end flow + observed security controls for a client→server pair."""

from __future__ import annotations

import datetime as _dt

DEFAULT_WINDOW_HOURS = 24


def _since(hours: int) -> str:
    return (_dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(hours=hours)).isoformat(
        timespec="milliseconds")


def _csv_list(value: str) -> list[str]:
    return [item for item in value.split(",") if item]


class AccessTools:
    """Stateless access-explanation tool bound to an EntityStore + M4 TopoTools."""

    def __init__(self, entity_store, topo_tools, default_window_hours: int = DEFAULT_WINDOW_HOURS):
        self._store = entity_store
        self._topo = topo_tools
        self._window = default_window_hours

    def explain_access(self, client: str, server: str, since_hours: int | None = None) -> dict:
        client_entity = self._store.find_entity(client)
        server_entity = self._store.find_entity(server)
        if not client_entity or not server_entity:
            missing = client if not client_entity else server
            return {"error": "not_found", "detail": f"no entity matches '{missing}'"}

        window = since_hours or self._window
        comm_edges = self._store.communicated_edges(
            client_entity["entity_id"], server_entity["entity_id"], _since(window))

        sessions = bytes_total = 0
        ports: set[str] = set()
        providers: set[str] = set()
        for edge in comm_edges:
            attrs = edge.get("attrs", {})
            sessions += int(attrs.get("sessions", "0") or 0)
            bytes_total += int(attrs.get("bytes", "0") or 0)
            ports.update(_csv_list(attrs.get("ports", "")))
            providers.update(_csv_list(attrs.get("providers", "")))

        # Firewall attribution comes from topology, NOT the event stream (see spec §3).
        enforcement = self._topo.enforcement_points(client, server)
        firewalls = enforcement.get("firewalls", [])
        attributed_fw = firewalls[0] if len(firewalls) == 1 else None

        controls = []
        if comm_edges:
            for item in self._store.governed_policies([e["edge_id"] for e in comm_edges]):
                policy = item["policy"]
                controls.append({
                    "firewall": attributed_fw,
                    "vendor": policy["identifiers"].get("provider", ""),
                    "rule": policy.get("name", ""),
                    "source": policy.get("source", "observed"),
                    "firewall_basis": "topology",
                })

        return {
            "client": {"entity_id": client_entity["entity_id"],
                       "name": client_entity.get("name", ""),
                       "identity_basis": client_entity.get("identity_basis", "")},
            "server": {"entity_id": server_entity["entity_id"],
                       "name": server_entity.get("name", ""),
                       "identity_basis": server_entity.get("identity_basis", "")},
            "observed_flows": {"sessions": sessions, "bytes": bytes_total,
                               "ports": sorted(int(p) for p in ports),
                               "providers": sorted(providers), "window_hours": window},
            "controls": controls,
            "firewalls": firewalls,
            "topology_path": self._topo.find_path(client, server),
            "coverage": {"observed": sessions > 0, "configured": "pending_m6b"},
        }
