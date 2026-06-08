"""Importing this package registers all collectors via their @register decorators."""

try:
    from . import panos  # noqa: F401
except ImportError:
    pass
from . import junos  # noqa: F401
