"""Fail-closed interprocess serialization for the small response control plane."""

from contextlib import contextmanager
import os


@contextmanager
def response_lock(path):
    with open(path, "a+b") as handle:
        os.chmod(path, 0o600)
        try:
            if os.name == "posix":
                import fcntl

                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            else:
                import msvcrt

                if handle.tell() == 0:
                    handle.write(b"0")
                    handle.flush()
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            raise ValueError("Another response operation is active; retry after verification") from None
        try:
            yield
        finally:
            if os.name == "posix":
                fcntl.flock(handle, fcntl.LOCK_UN)
            else:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
