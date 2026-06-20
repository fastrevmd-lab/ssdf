"""Importing this package registers every collector via @register decorators."""

from . import proxmox  # noqa: F401
from . import junos    # noqa: F401
from . import panos    # noqa: F401
from . import unifi    # noqa: F401
