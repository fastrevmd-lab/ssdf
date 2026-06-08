"""Importing this package registers all collectors via their @register decorators."""

from . import panos  # noqa: F401

try:
    from . import junos  # noqa: F401
except ImportError:
    pass
