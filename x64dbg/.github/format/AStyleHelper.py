#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = [
#   "astyle==3.6.9",
# ]
# ///

from __future__ import annotations

import importlib.metadata
import re
import shutil
import subprocess
import sys
import sysconfig
from pathlib import Path

PATTERNS = ("*.c", "*.h", "*.cpp", "*.hpp")
OPTIONS = (
    "style=allman, convert-tabs, align-pointer=type, align-reference=middle, "
    "indent=spaces, indent-namespaces, indent-col1-comments, "
    "unpad-paren, keep-one-line-blocks, close-templates"
)
IGNORE_PATTERNS = (
    r"src/cross/vendor",
    r"src/gui/Src/ThirdPartyLibs/md4c",
)
LICENSE_TEXT = ""

EXIT_OK = 0
EXIT_CHANGES = 1
EXIT_ERROR = 2


def stderr(message: str) -> None:
    print(message, file=sys.stderr)


def usage() -> int:
    stderr(
        "Usage: AStyleHelper.py [Silent|Check] [filter_epoch]\n"
        "\n"
        "Formats the git repository containing the current working directory.\n"
        "If the current working directory is not inside a git repository, it formats that directory.\n"
        "\n"
        "Modes:\n"
        "  <no mode>  Format files and print each file as it is processed.\n"
        "  Silent     Format files without progress output.\n"
        "  Check      Check formatting without modifying files.\n"
        "\n"
        "Examples:\n"
        "  uv run --script .github/format/AStyleHelper.py\n"
        "  uv run --script .github/format/AStyleHelper.py Silent\n"
        "  uv run --script .github/format/AStyleHelper.py Check\n"
    )
    return EXIT_ERROR


def parse_filter_epoch(args: list[str]) -> tuple[int, int]:
    if not args:
        return 0, EXIT_OK
    try:
        return int(args[0]), EXIT_OK
    except ValueError:
        stderr(f"Invalid epoch time provided: {args[0]}")
        return 0, EXIT_ERROR


def option_flags() -> list[str]:
    return [f"--{option.strip()}" for option in OPTIONS.split(",") if option.strip()]


def find_astyle_executable() -> Path:
    candidate_names = ("astyle.exe", "AStyle.exe", "astyle", "AStyle")

    try:
        dist = importlib.metadata.distribution("astyle")
        preferred = []
        fallback = []
        for file in dist.files or []:
            path = Path(file)
            if path.name not in candidate_names:
                continue
            located = Path(dist.locate_file(file))
            if not located.is_file():
                continue
            if "data" in path.parts:
                preferred.append(located)
            else:
                fallback.append(located)
        if preferred:
            return preferred[0]
        if fallback:
            return fallback[0]
    except importlib.metadata.PackageNotFoundError:
        pass

    candidate_dirs = []
    scripts_dir = sysconfig.get_path("scripts")
    if scripts_dir:
        candidate_dirs.append(Path(scripts_dir))
    candidate_dirs.append(Path(sys.executable).resolve().parent)

    for directory in candidate_dirs:
        for name in candidate_names:
            candidate = directory / name
            if candidate.is_file():
                return candidate

    for name in candidate_names:
        resolved = shutil.which(name)
        if resolved:
            return Path(resolved)

    raise FileNotFoundError(
        "Could not locate the 'astyle' executable from the astyle wheel."
    )


def get_git_root(start_dir: Path) -> Path:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=start_dir,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        if result.returncode == 0:
            git_root = result.stdout.strip()
            if git_root:
                return Path(git_root).resolve()
    except OSError:
        pass
    return start_dir.resolve()


def filter_git_ignored(root: Path, files: list[Path]) -> list[Path]:
    if not files:
        return files

    try:
        relative_paths = [file.as_posix() for file in files]
        result = subprocess.run(
            ["git", "check-ignore", "--no-index", "--stdin"],
            cwd=root,
            input="\n".join(relative_paths) + "\n",
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        if result.returncode not in (0, 1):
            return files
        ignored = {
            line.strip().replace("\\", "/")
            for line in result.stdout.splitlines()
            if line.strip()
        }
        return [file for file in files if file.as_posix() not in ignored]
    except OSError:
        return files


def git_ls_files(root: Path) -> list[Path]:
    try:
        result = subprocess.run(
            [
                "git",
                "ls-files",
                "--cached",
                "--others",
                "--exclude-standard",
                "--",
                *PATTERNS,
            ],
            cwd=root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        if result.returncode == 0:
            seen: set[str] = set()
            files: list[Path] = []
            for line in result.stdout.splitlines():
                line = line.strip()
                if not line or line in seen:
                    continue
                seen.add(line)
                files.append(Path(line))
            return filter_git_ignored(root, files)
    except OSError:
        pass

    seen: set[str] = set()
    files: list[Path] = []
    for pattern in PATTERNS:
        for path in root.rglob(pattern):
            if not path.is_file():
                continue
            relative = path.relative_to(root)
            key = relative.as_posix()
            if key in seen:
                continue
            seen.add(key)
            files.append(relative)
    files.sort(key=lambda path: path.as_posix())
    return files


def should_ignore(path: Path) -> bool:
    normalized = path.as_posix()
    return any(re.search(pattern, normalized) for pattern in IGNORE_PATTERNS)


def should_process(root: Path, relative_path: Path, filter_epoch: int) -> bool:
    if should_ignore(relative_path):
        return False
    if filter_epoch <= 0:
        return True
    try:
        return int((root / relative_path).stat().st_mtime) >= filter_epoch
    except OSError:
        return False


def read_utf8(path: Path) -> str | None:
    try:
        return path.read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def normalize_output(text: str) -> str:
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = text.replace("\n", "\r\n")
    text = text.strip("\uFEFF\u200B")
    if LICENSE_TEXT and not text.startswith(LICENSE_TEXT):
        text = LICENSE_TEXT + text
    return text


def chunk_paths(paths: list[Path], max_command_chars: int = 24000) -> list[list[Path]]:
    chunks: list[list[Path]] = []
    current: list[Path] = []
    current_chars = 0

    for path in paths:
        path_chars = len(str(path)) + 3
        if current and current_chars + path_chars > max_command_chars:
            chunks.append(current)
            current = []
            current_chars = 0
        current.append(path)
        current_chars += path_chars

    if current:
        chunks.append(current)
    return chunks


def run_astyle(astyle_exe: Path, file_paths: list[Path], dry_run: bool) -> subprocess.CompletedProcess[str]:
    command = [
        str(astyle_exe),
        *option_flags(),
        "--options=none",
        "--project=none",
        "--formatted",
    ]
    if dry_run:
        command.append("--dry-run")
    else:
        command.append("--suffix=none")
    command.extend(str(file_path) for file_path in file_paths)
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )


def parse_changed_paths(output: str, root: Path) -> list[str]:
    changed_files: list[str] = []
    root_resolved = root.resolve()

    for line in output.splitlines():
        line = line.strip()
        if not line or not line.startswith("Formatted"):
            continue
        path_text = line[len("Formatted"):].strip()
        try:
            relative = Path(path_text).resolve().relative_to(root_resolved).as_posix()
        except (OSError, ValueError):
            relative = path_text.replace("\\", "/")
        changed_files.append(relative)

    return changed_files


def format_directory(root: Path, write_changes: bool, filter_epoch: int, show_progress: bool = False) -> tuple[list[str], list[str]]:
    changed_files: set[str] = set()
    errors: list[str] = []
    astyle_exe = find_astyle_executable()
    file_records: list[tuple[Path, str]] = []

    for relative_path in git_ls_files(root):
        if not should_process(root, relative_path, filter_epoch):
            continue

        original_text = read_utf8(root / relative_path)
        if original_text is None:
            continue
        file_records.append((relative_path, original_text))

    if show_progress:
        for relative_path, _ in file_records:
            print(relative_path.as_posix(), flush=True)

    absolute_paths = [root / relative_path for relative_path, _ in file_records]
    for batch in chunk_paths(absolute_paths):
        result = run_astyle(astyle_exe, batch, dry_run=not write_changes)
        if result.returncode != 0:
            batch_set = {path.resolve() for path in batch}
            for relative_path, _ in file_records:
                if (root / relative_path).resolve() in batch_set:
                    errors.append(f"Cannot format {relative_path.as_posix()}")
            continue
        changed_files.update(parse_changed_paths(result.stdout, root))

    for relative_path, original_text in file_records:
        display_path = relative_path.as_posix()
        if write_changes:
            formatted_text = read_utf8(root / relative_path)
            if formatted_text is None:
                errors.append(f"Cannot format {display_path}")
                continue
            normalized_text = normalize_output(formatted_text)
            if formatted_text != normalized_text:
                try:
                    (root / relative_path).write_bytes(normalized_text.encode("utf-8"))
                except OSError:
                    errors.append(f"Cannot format {display_path}")
                    continue
            if original_text != normalized_text:
                changed_files.add(display_path)
        elif original_text != normalize_output(original_text):
            changed_files.add(display_path)

    return sorted(changed_files), errors


def run_format(root: Path, filter_epoch: int, show_progress: bool) -> int:
    changed_files, errors = format_directory(
        root,
        write_changes=True,
        filter_epoch=filter_epoch,
        show_progress=show_progress,
    )
    for error in errors:
        stderr(error)
    if errors and not changed_files:
        return EXIT_ERROR
    return EXIT_CHANGES if changed_files else EXIT_OK


def run_silent(root: Path, filter_epoch: int) -> int:
    return run_format(root, filter_epoch, show_progress=False)


def run_check(root: Path, filter_epoch: int) -> int:
    changed_files, errors = format_directory(root, write_changes=False, filter_epoch=filter_epoch)
    for error in errors:
        stderr(error)
    if changed_files:
        stderr("Nonconforming files:")
        for path in changed_files:
            stderr(path)
        return EXIT_CHANGES
    if errors:
        return EXIT_ERROR
    print("Formatting fully conforming!")
    return EXIT_OK


def main(argv: list[str]) -> int:
    root = get_git_root(Path.cwd())

    if not argv:
        try:
            return run_format(root, 0, show_progress=True)
        except FileNotFoundError as exc:
            stderr(str(exc))
            return EXIT_ERROR
        except OSError as exc:
            stderr(str(exc))
            return EXIT_ERROR

    filter_epoch, status = parse_filter_epoch(argv[1:])
    if status != EXIT_OK:
        return status

    command = argv[0].lower()

    try:
        if command == "silent":
            return run_silent(root, filter_epoch)
        if command == "check":
            return run_check(root, filter_epoch)
        stderr(f"Invalid argument: {argv[0]}")
        return usage()
    except FileNotFoundError as exc:
        stderr(str(exc))
        return EXIT_ERROR
    except OSError as exc:
        stderr(str(exc))
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
