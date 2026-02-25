from __future__ import annotations

import os
from collections import namedtuple

_VMem = namedtuple("svmem", ["total", "available", "percent"])


def virtual_memory():
    return _VMem(total=0, available=0, percent=0.0)


def cpu_percent(interval=None):  # noqa: ARG001
    return 0.0


def cpu_count():
    return os.cpu_count() or 1
