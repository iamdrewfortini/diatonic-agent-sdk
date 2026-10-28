"""Read native systemd credentials without relaxing private-file semantics.

systemd may expose root-owned0440 credential files with service-specific ACLs.
Only its read-only /run/credentials namespace qualifies for this separate port.
"""
from contextlib import contextmanager
import os
from pathlib import Path
import re
import stat

from pydantic import SecretStr


def _manager_path(path):
    p = Path(path)
    return p.is_absolute() and p.parent == Path("/run/credentials") and not p.is_symlink()


@contextmanager
def descriptor(name):
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", name) or name in {".", ".."}:
        raise ValueError("Invalid systemd credential name")
    directory = os.environ.get("CREDENTIALS_DIRECTORY", "")
    if not _manager_path(directory):
        raise ValueError("Native systemd credential directory unavailable")
    parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    fd = None
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid not in {0, os.geteuid()}
                or info.st_gid not in {0, os.getegid()} or stat.S_IMODE(info.st_mode) not in {0o400,0o440}
                or not 0 < info.st_size <= 16384 or not os.fstatvfs(fd).f_flag & os.ST_RDONLY):
            raise ValueError("Systemd credential is not a bounded protected read-only file")
        yield fd
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def available(name):
    try:
        with descriptor(name):
            return True
    except (OSError, ValueError):
        return False


def read(name):
    with descriptor(name) as fd:
        value = os.read(fd, 16385).decode()
    if value.endswith("\n"):
        value = value[:-1]
    if not value or len(value.encode()) > 16384 or any(c in value for c in "\r\n"):
        raise ValueError("Systemd credential value unavailable")
    return SecretStr(value)
