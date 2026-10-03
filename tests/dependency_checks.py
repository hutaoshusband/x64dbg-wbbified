import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import tarfile
import zipfile

from wi_driver import McpError, file_identity


def verify_archive_sources(archive, expected_sha256, source):
    archive, source = Path(archive), Path(source)
    before = file_identity(archive)
    if before["sha256"] != expected_sha256:
        raise McpError("Dependency archive differs from its pin")
    if source.is_symlink() or source.is_junction() or not source.is_dir():
        raise McpError("Dependency source must be an existing ordinary directory")
    prefix = None
    files = {}
    total = 0
    entries = 0

    def compare(name, directory, stream, size):
        nonlocal prefix, total, entries
        entries += 1
        parts = PurePosixPath(name).parts
        if entries > 150000 or not parts or len(name) > 1024 or name.startswith("/") or "\\" in name or any(p in (".", "..") or ":" in p for p in parts):
            raise McpError("Dependency archive has an unsafe or excessive entry")
        if prefix is None:
            prefix = parts[0]
        if parts[0] != prefix:
            raise McpError("Dependency archive must have one source root")
        if len(parts) == 1:
            if not directory:
                raise McpError("Dependency archive root must be a directory")
            return
        relative = PurePosixPath(*parts[1:]).as_posix()
        path = source.joinpath(*parts[1:])
        if directory:
            if not path.is_dir() or path.is_symlink() or path.is_junction():
                raise McpError("Dependency source directory differs from its archive")
            return
        key = relative.casefold()
        total += size
        if key in files or size < 0 or total > 16 * 1024**3:
            raise McpError("Dependency archive has duplicate or excessive files")
        if path.is_symlink() or path.is_junction():
            raise McpError("Dependency source contains a reparse object")
        digest = hashlib.sha256()
        with path.open("rb") as actual:
            initial = os.fstat(actual.fileno())
            if not stat.S_ISREG(initial.st_mode) or initial.st_size != size:
                raise McpError("Dependency source size differs from its archive")
            remaining = size
            while remaining:
                count = min(remaining, 1024 * 1024)
                expected = stream.read(count)
                received = actual.read(count)
                if len(expected) != count or expected != received:
                    raise McpError("Dependency source bytes differ from its archive")
                digest.update(received)
                remaining -= count
            final = os.fstat(actual.fileno())
            if actual.read(1) or (initial.st_size, initial.st_mtime_ns, initial.st_ino) != (final.st_size, final.st_mtime_ns, final.st_ino):
                raise McpError("Dependency source changed during verification")
        files[key] = (relative, size, digest.hexdigest())

    if zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as container:
            for member in container.infolist():
                mode = member.external_attr >> 16
                if stat.S_ISLNK(mode):
                    raise McpError("Dependency archive links are unsupported")
                with container.open(member) as stream:
                    compare(member.filename, member.is_dir(), stream, member.file_size)
    else:
        with tarfile.open(archive, mode="r|*") as container:
            for member in container:
                if not member.isfile() and not member.isdir():
                    raise McpError("Dependency archive links or special objects are unsupported")
                stream = container.extractfile(member) if member.isfile() else None
                try:
                    compare(member.name, member.isdir(), stream, member.size)
                finally:
                    if stream is not None:
                        stream.close()
    actual_files = set()
    pending = [source]
    while pending:
        with os.scandir(pending.pop()) as children:
            for child in children:
                attributes = child.stat(follow_symlinks=False)
                if attributes.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                    raise McpError("Dependency source contains a reparse object")
                if child.is_dir(follow_symlinks=False):
                    pending.append(Path(child.path))
                else:
                    relative = Path(child.path).relative_to(source).as_posix().casefold()
                    if relative in actual_files:
                        raise McpError("Dependency source has duplicate files")
                    actual_files.add(relative)
    if not files or actual_files != set(files) or file_identity(archive) != before:
        raise McpError("Dependency source file set or archive changed")
    closure = hashlib.sha256()
    for item in sorted(files.values()):
        closure.update((json.dumps(item, ensure_ascii=False, separators=(",", ":")) + "\n").encode())
    return {"archive": before, "sourceDirectory": str(source), "sourceFiles": len(files), "sourceBytes": total, "sourceTreeSha256": closure.hexdigest()}


def check_dependency_source_reuse(output):
    output = Path(output) / "dependency-source-controls"
    output.mkdir()
    source = output / "Hu Tao ❤ source"
    source.mkdir()
    (source / "reference.h").write_bytes(b"native reference 42\n")
    archive = output / "source.tar"

    def write_archive(name="package/reference.h", link=False):
        with tarfile.open(archive, "w") as container:
            member = tarfile.TarInfo(name)
            member.size = 20
            if link:
                member.type = tarfile.SYMTYPE
                member.linkname = "reference.h"
                member.size = 0
            container.addfile(member, None if link else io.BytesIO(b"native reference 42\n"))

    write_archive()
    pin = file_identity(archive)["sha256"]
    accepted = verify_archive_sources(archive, pin, source)
    refusals = []

    def refused(name, digest=pin):
        try:
            verify_archive_sources(archive, digest, source)
        except (McpError, OSError) as error:
            refusals.append({"case": name, "error": str(error)})
        else:
            raise AssertionError("Altered dependency source was admitted")

    refused("wrong-archive-pin", "0" * 64)
    (source / "reference.h").write_bytes(b"native reference 43\n")
    refused("changed-source-bytes")
    (source / "reference.h").write_bytes(b"native reference 42\n")
    (source / "extra.h").write_bytes(b"extra")
    refused("extra-source-file")
    (source / "extra.h").unlink()
    (source / "reference.h").unlink()
    refused("missing-source-file")
    (source / "reference.h").write_bytes(b"native reference 42\n")
    write_archive("package/../escape.h")
    refused("archive-traversal", file_identity(archive)["sha256"])
    write_archive(link=True)
    refused("archive-link", file_identity(archive)["sha256"])
    write_archive()
    assert verify_archive_sources(archive, pin, source) == accepted
    zip_archive = output / "source.zip"
    with zipfile.ZipFile(zip_archive, "w") as container:
        container.writestr("package/reference.h", b"native reference 42\n")
    zip_pin = file_identity(zip_archive)["sha256"]
    zip_original = zip_archive.read_bytes()
    zip_accepted = verify_archive_sources(zip_archive, zip_pin, source)
    assert zip_accepted["sourceTreeSha256"] == accepted["sourceTreeSha256"]
    for name, linked in (("zip-traversal", False), ("zip-link", True)):
        with zipfile.ZipFile(zip_archive, "w") as container:
            member = zipfile.ZipInfo("package/reference.h" if linked else "package/../escape.h")
            if linked:
                member.external_attr = (stat.S_IFLNK | 0o777) << 16
            container.writestr(member, b"reference.h" if linked else b"native reference 42\n")
        try:
            verify_archive_sources(zip_archive, file_identity(zip_archive)["sha256"], source)
        except McpError as error:
            refusals.append({"case": name, "error": str(error)})
        else:
            raise AssertionError("Altered ZIP dependency archive was admitted")
    zip_archive.write_bytes(zip_original)
    assert verify_archive_sources(zip_archive, zip_pin, source) == zip_accepted
    return {"sourceReuseAccepted": accepted, "zipSourceReuseAccepted": zip_accepted, "actualSourceRefusals": refusals, "sourceRestored": True}
