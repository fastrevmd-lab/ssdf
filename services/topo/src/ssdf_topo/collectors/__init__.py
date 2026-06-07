# src/ssdf_topo/collectors/__init__.py
"""Collector implementations register themselves on import."""
from . import base, junos, panos, proxmox, unifi  # noqa: F401
