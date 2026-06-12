"""Per-scan file logging with optional console echo (thread-local)."""

import datetime
import os
import threading
from contextlib import contextmanager
from typing import Iterator, Optional

from .files import open_unique

_local = threading.local()


@contextmanager
def scan_log_session(log_path: str, *, echo: bool = True) -> Iterator[str]:
    """Open a per-scan log file for the current thread.

    Yields the actual log path, which may carry a ``_N`` suffix when
    concurrent scans computed the same timestamped name.
    """
    os.makedirs(os.path.dirname(log_path) or ".", exist_ok=True)
    handle, log_path = open_unique(log_path)
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    handle.write(f"TPCRM Findings Scanner log started {started}\n")
    handle.flush()

    previous_handle = getattr(_local, "handle", None)
    previous_echo = getattr(_local, "echo", True)
    _local.handle = handle
    _local.echo = echo
    try:
        yield log_path
    finally:
        finished = datetime.datetime.now(datetime.timezone.utc).isoformat()
        handle.write(f"TPCRM Findings Scanner log finished {finished}\n")
        handle.flush()
        handle.close()
        _local.handle = previous_handle
        _local.echo = previous_echo


def scan_log(message: str, *, also_print: Optional[bool] = None) -> None:
    """Write a scan message to the active log file and optionally stdout."""
    echo = getattr(_local, "echo", True) if also_print is None else also_print
    if echo:
        print(message)

    handle = getattr(_local, "handle", None)
    if not handle:
        return

    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    handle.write(f"{timestamp} {message}\n")
    handle.flush()


def active_scan_log_path() -> Optional[str]:
    """Return the active per-scan log path for the current thread, if any."""
    handle = getattr(_local, "handle", None)
    if not handle:
        return None
    return getattr(handle, "name", None)