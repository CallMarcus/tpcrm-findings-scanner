"""Filesystem helpers shared by reporters and scan logging."""

import os
from typing import Optional, TextIO, Tuple


def open_unique(path: str, encoding: str = "utf-8", newline: Optional[str] = None) -> Tuple[TextIO, str]:
    """Open path for writing without clobbering an existing file.

    Uses O_CREAT|O_EXCL so concurrent batch threads that compute the same
    timestamped filename cannot overwrite each other; collisions get an
    incrementing ``_N`` suffix before the extension. Returns the open text
    handle and the actual path used.
    """
    base, ext = os.path.splitext(path)
    candidate = path
    counter = 0
    while True:
        try:
            fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
            return os.fdopen(fd, "w", encoding=encoding, newline=newline), candidate
        except FileExistsError:
            counter += 1
            candidate = f"{base}_{counter}{ext}"
