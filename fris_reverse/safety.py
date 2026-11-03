"""Resource policies and portable path validation, not an OS sandbox."""
from __future__ import annotations
import hashlib
import os
from pathlib import Path, PurePosixPath
import shutil
import signal
import stat
import subprocess
import tarfile
import tempfile
import time
import zipfile

MAX_ENTRIES = 30000
MAX_EXPANDED = 1073741824

class Failure(Exception):
    def __init__(self, code, message, hint=""):
        super().__init__(message)
        self.code, self.hint = code, hint

    def as_dict(self):
        return {"code": self.code, "message": str(self), "hint": self.hint}

def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1048576), b""):
            digest.update(chunk)
    return digest.hexdigest()

def confined(root, value, must_exist=True):
    root = Path(root).resolve()
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        target = candidate.resolve(strict=must_exist)
        target.relative_to(root)
    except (ValueError, OSError, RuntimeError) as exc:
        raise Failure("PATH_POLICY", "Missing path or path outside workspace") from exc
    return target

def member_path(root, name):
    if not isinstance(name, str) or not name or chr(92) in name or chr(0) in name or ":" in name:
        raise Failure("UNSAFE_ARCHIVE", "Invalid archive member name")
    member = PurePosixPath(name)
    if member.is_absolute() or ".." in member.parts:
        raise Failure("UNSAFE_ARCHIVE", "Archive traversal refused")
    reserved = {"CON", "PRN", "AUX", "NUL", *("COM" + str(i) for i in range(1, 10)), *("LPT" + str(i) for i in range(1, 10))}
    for part in member.parts:
        if part.endswith((".", " ")) or part.split(".")[0].upper() in reserved or any(ord(c) < 32 for c in part):
            raise Failure("UNSAFE_ARCHIVE", "Non-portable archive member refused")
    return confined(root, str(member), False)

def checked_zip(path, max_bytes=MAX_EXPANDED):
    try:
        with zipfile.ZipFile(path) as archive:
            members = archive.infolist()
            if len(members) > MAX_ENTRIES or sum(x.file_size for x in members) > max_bytes:
                raise Failure("ARCHIVE_LIMIT", "Archive expansion budget exceeded")
            names = set()
            for item in members:
                # orig_filename precedes ZipInfo OS normalization and NUL trimming.
                raw_name = getattr(item, "orig_filename", item.filename)
                member_path(Path.cwd(), raw_name)
                member_path(Path.cwd(), item.filename)
                canonical = PurePosixPath(item.filename).as_posix().casefold()
                if canonical in names:
                    raise Failure("UNSAFE_ARCHIVE", "Duplicate or case-colliding member")
                names.add(canonical)
                if stat.S_ISLNK(item.external_attr >> 16) or item.flag_bits & 1:
                    raise Failure("UNSAFE_ARCHIVE", "Symlink or encrypted member refused")
            return members
    except zipfile.BadZipFile as exc:
        raise Failure("BAD_ZIP", "Invalid ZIP container") from exc

def extract_archive(path, destination):
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    if zipfile.is_zipfile(path):
        members = checked_zip(path)
        with zipfile.ZipFile(path) as archive:
            for item in members:
                target = member_path(destination, item.filename)
                if item.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with archive.open(item) as src, target.open("xb") as dst:
                        shutil.copyfileobj(src, dst)
                    target.chmod(0o755 if (item.external_attr >> 16) & 0o111 else 0o644)
        return
    with tarfile.open(path, "r:*") as archive:
        seen, links, total, count = set(), [], 0, 0
        for item in archive:
            count, total = count + 1, total + item.size
            if count > MAX_ENTRIES or total > MAX_EXPANDED:
                raise Failure("ARCHIVE_LIMIT", "TAR expansion budget exceeded")
            target = member_path(destination, item.name)
            key = PurePosixPath(item.name).as_posix().casefold()
            if key in seen:
                raise Failure("UNSAFE_ARCHIVE", "Duplicate TAR member")
            seen.add(key)
            if item.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif item.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(item) as src, target.open("xb") as dst:
                    shutil.copyfileobj(src, dst)
                target.chmod(0o755 if item.mode & 0o111 else 0o644)
            elif item.issym() or item.islnk():
                if Path(item.linkname).is_absolute() or chr(92) in item.linkname or ":" in item.linkname:
                    raise Failure("UNSAFE_ARCHIVE", "Unsafe TAR link")
                base = target.parent if item.issym() else destination
                source = confined(destination, base / item.linkname, False)
                links.append((target, source))
            else:
                raise Failure("UNSAFE_ARCHIVE", "Special TAR member refused")
        for _ in range(len(links) + 1):
            pending = []
            for target, source in links:
                if source.is_file():
                    if target.exists():
                        raise Failure("UNSAFE_ARCHIVE", "Link overwrite refused")
                    total += source.stat().st_size
                    if total > MAX_EXPANDED:
                        raise Failure("ARCHIVE_LIMIT", "Materialized link budget exceeded")
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(source, target)
                else:
                    pending.append((target, source))
            if not pending:
                break
            if len(pending) == len(links):
                raise Failure("UNSAFE_ARCHIVE", "Unresolved or directory TAR link")
            links = pending

def run_process(argv, cwd, timeout=120):
    allow = {"PATH", "HOME", "USERPROFILE", "SystemRoot", "SYSTEMROOT", "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL", "JAVA_HOME", "APPDATA", "LOCALAPPDATA"}
    env = {k: v for k, v in os.environ.items() if k in allow}
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        try:
            proc = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=out, stderr=err, shell=False, start_new_session=os.name != "nt")
        except OSError as exc:
            raise Failure("PROCESS_START", "Cannot start tool", str(exc)) from exc
        start, reason = time.monotonic(), None
        while proc.poll() is None:
            if time.monotonic() - start > timeout:
                reason = "TIMEOUT"
            if os.fstat(out.fileno()).st_size + os.fstat(err.fileno()).st_size > 131072:
                reason = "OUTPUT_LIMIT"
            if reason:
                try:
                    proc.kill() if os.name == "nt" else os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                break
            time.sleep(0.05)
        proc.wait()
        size = os.fstat(out.fileno()).st_size + os.fstat(err.fileno()).st_size
        if size > 131072:
            reason = reason or "OUTPUT_LIMIT"
        out.seek(0)
        err.seek(0)
        result = {"exit_code": proc.returncode, "stdout": out.read(4096).decode("utf-8", "replace"), "stderr": err.read(4096).decode("utf-8", "replace"), "logs_truncated": size > 8192}
        if reason:
            raise Failure(reason, "Analysis interrupted by resource policy")
        return result
