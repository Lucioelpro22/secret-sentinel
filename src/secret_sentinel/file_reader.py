"""Bounded reads anchored to a directory, with symlinks rejected at every component."""

import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


class FileLimitExceeded(OSError):
    """A regular input cannot fit within the permitted byte budget."""

    def __init__(self, message: str, consumed: int = 0) -> None:
        super().__init__(message)
        self.consumed = consumed


@contextmanager
def open_scan_root(root: Path) -> Iterator[int]:
    """Pin a canonical root while rejecting symlinks in its absolute path."""
    if os.open not in os.supports_dir_fd or not hasattr(os, "O_NOFOLLOW"):
        raise OSError("safe scan file reads are unavailable on this platform")
    canonical = root.absolute()
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open(canonical.anchor, flags)
    try:
        for component in canonical.parts[1:]:
            next_fd = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_fd
        yield descriptor
    finally:
        os.close(descriptor)


def read_scan_file(root: Path | int, relative: Path, limit: int) -> bytes:
    """Read a bounded regular file beneath an already pinned root descriptor."""
    if isinstance(root, Path):
        with open_scan_root(root) as descriptor:
            return read_scan_file(descriptor, relative, limit)
    if (
        relative.is_absolute()
        or not relative.parts
        or ".." in relative.parts
        or limit < 0
    ):
        raise OSError("invalid scan file read")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    directory_fd = os.dup(root)
    try:
        for component in relative.parts[:-1]:
            next_fd = os.open(component, directory_flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        file_fd = os.open(
            relative.name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=directory_fd,
        )
        with os.fdopen(file_fd, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                raise OSError("scan file is not regular")
            if metadata.st_size > limit:
                raise FileLimitExceeded("scan file exceeds the read limit")
            data = stream.read(limit + 1)
            if len(data) > limit:
                raise FileLimitExceeded("scan file exceeds the read limit", len(data))
            return data
    finally:
        os.close(directory_fd)
