"""Bounded, process-local caches for immutable artifact snapshots.

Files are re-statted on every lookup. Rebuilds/replacements invalidate entries;
artifacts must not be edited concurrently with a classification. Cached parsed
objects are read-only to consumers. These caches never store proof verdicts.
"""

from collections import OrderedDict
from functools import lru_cache, wraps
import hashlib
import os
from pathlib import Path


def file_identity(path: str | Path) -> tuple:
    name = os.path.normcase(os.path.abspath(path))
    try:
        status = os.stat(name)
    except FileNotFoundError:
        return (name, None)
    return (name, status.st_dev, status.st_ino, status.st_size,
            status.st_mtime_ns, status.st_ctime_ns)


@lru_cache(maxsize=32)
def _file_sha256(identity: tuple) -> str:
    digest = hashlib.sha256()
    with open(identity[0], "rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    if file_identity(identity[0]) != identity:
        raise RuntimeError(f"artifact changed while hashing: {identity[0]}")
    return digest.hexdigest()


def file_sha256(path: str | Path) -> str:
    return _file_sha256(file_identity(path))


class _Identity:
    """Retain an object: using bare id() would allow reuse after eviction."""

    def __init__(self, value):
        self.value = value

    def __hash__(self):
        return id(self.value)

    def __eq__(self, other):
        return isinstance(other, _Identity) and self.value is other.value


def _key(value):
    if isinstance(value, Path):
        # A build-directory mtime changes when a disk cache is created. Its
        # input files are separate arguments (or explicit dependencies).
        return ("directory", str(value.resolve())) if value.is_dir() else file_identity(value)
    if isinstance(value, (str, int, bool, float, bytes, type(None))):
        return (type(value), value)
    if isinstance(value, tuple):
        return tuple(_key(item) for item in value)
    return _Identity(value)


def artifact_memoize(maxsize=8, *, dependencies=None):
    """Memoize file-backed readers; an explicit refresh clears prior entries."""
    def decorate(function):
        entries = OrderedDict()

        @wraps(function)
        def cached(*args, **kwargs):
            refresh = kwargs.get("refresh", False) or (args and args[-1] is True)
            if refresh:
                entries.clear()
                return function(*args, **kwargs)
            key = (_key(args), tuple((name, _key(value)) for name, value in sorted(kwargs.items())),
                   dependencies(*args, **kwargs) if dependencies else None)
            if key in entries:
                entries.move_to_end(key)
                return entries[key]
            value = function(*args, **kwargs)
            entries[key] = value
            if len(entries) > maxsize:
                entries.popitem(last=False)
            return value

        cached.cache_clear = entries.clear
        return cached
    return decorate
