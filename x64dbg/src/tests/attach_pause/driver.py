from __future__ import annotations

import argparse
import configparser
import json
import ctypes
import os
import queue
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[4] / "tests"))
from thread_checks import native_process_state, wait_for_blocked_thread
from wi_driver import McpError, file_identity, loaded_modules, process_identity

WM_QUIT = 0x0012
WM_APP = 0x8000


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Drive the attach + pause regression test.")
    parser.add_argument("--headless", required=True)
    parser.add_argument("--debuggee", required=True)
    parser.add_argument("--script", required=True)
    parser.add_argument("--runtime-dir", required=True)
    parser.add_argument("--userdir", required=True)
    parser.add_argument("--log", required=True)
    parser.add_argument("--artifacts-dir", required=True)
    parser.add_argument("--engine", required=True)
    parser.add_argument("--timeout", type=int, required=True)
    parser.add_argument("--no-console-window", action="store_true")
    return parser.parse_args()


def path_arg(path: Path, cwd: Path) -> str:
    try:
        return os.path.relpath(path, cwd)
    except ValueError:
        return str(path)


def append_log(log_path: Path, text: str) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8", errors="replace") as log_file:
        log_file.write(text)
        if not text.endswith("\n"):
            log_file.write("\n")


def wait_for_ready(process: subprocess.Popen[str], timeout: float) -> str | None:
    assert process.stdout is not None
    lines: queue.Queue[str] = queue.Queue(maxsize=1)
    threading.Thread(target=lambda: lines.put(process.stdout.readline()), daemon=True).start()
    try:
        line = lines.get(timeout=timeout)
    except queue.Empty:
        return None
    return line.strip() if line else None


class Headless:
    def __init__(self, command: list[str], cwd: Path, creationflags: int) -> None:
        self.process = subprocess.Popen(
            command,
            cwd=cwd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=creationflags,
        )
        self.identity = process_identity(self.process)
        self.lines: list[str] = []
        self.lock = threading.Lock()
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self) -> None:
        assert self.process.stdout is not None
        for line in self.process.stdout:
            with self.lock:
                self.lines.append(line.rstrip())

    def send(self, command: str) -> None:
        assert self.process.stdin is not None
        self.process.stdin.write(command + "\n")
        self.process.stdin.flush()

    def mark(self) -> int:
        with self.lock:
            return len(self.lines)

    def wait_for_line(self, predicate, timeout: float, after: int = 0) -> str | None:
        deadline = time.monotonic() + timeout
        seen = after
        while time.monotonic() < deadline:
            with self.lock:
                new_lines = self.lines[seen:]
                seen = len(self.lines)
            for line in new_lines:
                if predicate(line):
                    return line
            if self.process.poll() is not None:
                return None
            time.sleep(0.1)
        return None

    def wait_for_quiescence(self, idle: float, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self.lock:
                count = len(self.lines)
            time.sleep(idle)
            with self.lock:
                if len(self.lines) == count:
                    return

    def dump(self, path: Path) -> None:
        with self.lock:
            path.write_text("\n".join(self.lines) + "\n", encoding="utf-8", errors="replace")


def main() -> int:
    args = parse_args()
    headless_path = Path(args.headless).resolve()
    debuggee = Path(args.debuggee).resolve()
    userdir = Path(args.userdir).resolve()
    log_path = Path(args.log).resolve()
    artifacts_dir = Path(args.artifacts_dir).resolve()
    headless_dir = headless_path.parent
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    # The log is written after headless shuts down, because RedirectLog keeps
    # the file locked while headless is running.
    def fail(reason: str, message: str) -> int:
        shutdown_headless()
        append_log(log_path, f'[x64dbg-test] ASSERT FAIL source=driver message="{message}"')
        append_log(log_path, f"[x64dbg-test] FINAL status=fail asserts=1 reason={reason}")
        return 1

    def shutdown_headless() -> bool:
        if headless is None:
            return False
        if headless.process.poll() is not None:
            return headless.process.returncode == 0
        try:
            cursor = headless.mark()
            headless.send("detach")
            if headless.wait_for_line(lambda line: line == "[STATE] stopped", 10, cursor) is None:
                raise RuntimeError("The detach did not produce a new stopped event")
            headless.send("exit")
            headless.process.wait(timeout=10)
            observations["debuggerExit"] = headless.process.returncode
            return headless.process.returncode == 0
        except Exception:
            headless.process.kill()
            try:
                headless.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
            return False

    # test.txt drives the base test, test.breakin.txt the break-in fallback.
    script_name = Path(args.script).name
    breakin_mode = script_name == "test.breakin.txt"
    hidden_mode = script_name == "test.hidden.txt"
    hide_debugger = breakin_mode or hidden_mode
    configuration = configparser.ConfigParser()
    configuration.optionxform = str
    configuration.read(userdir / "headless.ini", encoding="utf-8")
    if not configuration.has_section("Engine"):
        raise RuntimeError("The isolated headless profile has no Engine section")
    configuration.set("Engine", "HideDebugger", str(int(hide_debugger)))
    if hidden_mode:
        if not configuration.has_section("Events"):
            configuration.add_section("Events")
        configuration.set("Events", "TlsCallbacks", "0")
        configuration.set("Events", "TlsCallbacksSystem", "0")
    with (userdir / "headless.ini").open("w", encoding="utf-8") as output:
        configuration.write(output)
    observations = {"hidden": hide_debugger, "mode": "breakin" if breakin_mode else "hidden" if hidden_mode else "debug-string",
                    "isolatedSettings": {section: dict(configuration[section]) for section in ("Engine", "Events") if configuration.has_section(section)}}

    def observe(label):
        cursor = headless.mark()
        headless.send(f"attachobserve {label}")
        line = headless.wait_for_line(lambda value: value.startswith(f"ATTACH_OBSERVE label={label} "), 10, cursor)
        if line is None:
            raise RuntimeError("The native SDK context observation did not complete")
        pairs = [part.split("=", 1) for part in line.split()[1:]]
        values = dict(pairs)
        if len(values) != len(pairs) or set(values) != {"label", "pid", "tid", "creation", "running", "sdk", "native", "ip", "nativeIp"}:
            raise RuntimeError("The native SDK context observation has invalid fields")
        return values

    def observe_status_boundary():
        cursor = headless.mark()
        headless.send("attachobserve boundary")
        emitted = headless.wait_for_line(lambda line: line == "ATTACH_BOUNDARY emitted=1", 10, cursor)
        with headless.lock:
            records = headless.lines[cursor:]
        observations["statusBoundary"] = {"acknowledged": emitted is not None, "records": records}
        try:
            prefix_index = records.index("ATTACH_STATE_PREFIX")
            state_index = records.index("[STATE] paused", prefix_index + 1)
            emitted_index = records.index("ATTACH_BOUNDARY emitted=1", state_index + 1)
        except ValueError:
            return False
        return emitted is not None and prefix_index < state_index < emitted_index

    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if args.no_console_window else 0
    target = subprocess.Popen(
        [str(debuggee)] + (["block"] if breakin_mode else []),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        creationflags=creationflags,
    )

    headless: Headless | None = None
    main_tid = 0
    target_lines = []
    try:
        ready_line = wait_for_ready(target, timeout=10)
        if not ready_line or not ready_line.startswith("ready "):
            return fail("target_not_ready", f"target did not print a ready line: {ready_line!r}")
        target_lines.append(ready_line)
        _, pid, main_tid, main_creation = ready_line.split()
        pid, main_tid, main_creation = int(pid), int(main_tid), int(main_creation)
        if pid != target.pid:
            return fail("wrong_target", "the ready PID does not match the owned process")
        observations["beforeAttach"] = native_process_state(target)
        observations["targetBinary"] = file_identity(debuggee)
        if observations["beforeAttach"]["debugPortPresent"]:
            return fail("already_debugged", "the owned target already has a debug port")

        command = [
            str(headless_path),
            "-userdir",
            str(userdir),
            "-c",
            f'RedirectLog "{log_path}"',
        ]
        suffix = ".dp32" if any(peb["kind"] == "wow64" for peb in observations["beforeAttach"]["pebs"]) else ".dp64"
        provider = Path(args.runtime_dir).resolve() / ("attach_pause" + suffix)
        if not provider.is_file():
            return fail("missing_provider", "the native attach observer is missing")
        command.extend(["-plugin", path_arg(provider, headless_dir)])
        observations["observerBinary"] = file_identity(provider)
        print("[attach-pause-driver] " + " ".join(command), flush=True)
        headless = Headless(command, headless_dir, creationflags)
        observations["debuggerIdentity"] = headless.identity

        # Attach through the interactive command handler (DbgCmdExec), which is
        # the same code path as the GUI attach dialog. This does not pause.
        cursor = headless.mark()
        headless.send(f"attach .{pid}")
        if headless.wait_for_line(lambda line: "Attached to process!" in line, 30, cursor) is None:
            return fail("attach_failed", "attach command did not report success")

        # Let the attach event storm and symbol loading settle.
        headless.wait_for_quiescence(idle=2, timeout=30)
        observations["debuggerModules"] = loaded_modules(headless.process)
        if not any(module["sha256"] == observations["observerBinary"]["sha256"] and module["path"] == observations["observerBinary"]["path"] for module in observations["debuggerModules"]):
            return fail("observer_not_loaded", "the exact source-built native observer is not loaded")
        observations["attached"] = native_process_state(target)
        attached = observations["attached"]
        if attached["identity"] != observations["beforeAttach"]["identity"] or not attached["debugPortPresent"] or any(peb["beingDebugged"] != int(not hide_debugger) for peb in attached["pebs"]):
            return fail("wrong_attach_state", "the actual owned debug port/PEB state does not match the isolated profile")

        if breakin_mode:
            # Every thread of the target blocks forever, so the first pause
            # request cannot interrupt anything.
            cursor = headless.mark()
            headless.send("pause")
            if headless.wait_for_line(lambda line: line == "[STATE] paused", 4, cursor) is not None:
                return fail("unexpected_pause", "first pause request should not break a fully blocked debuggee")

            # A repeated pause request after a few seconds must fall back to a
            # break-in thread and interrupt the debuggee.
            cursor = headless.mark()
            headless.send("pause")
            if headless.wait_for_line(lambda line: line == "[STATE] paused", 10, cursor) is None:
                return fail("breakin_no_effect", "repeated pause request did not break in")

            if not observe_status_boundary():
                return fail("state_record_boundary", "native paused status merged with an unterminated log fragment")
            if not shutdown_headless():
                return fail("detach_failed", "the blocked-target debugger did not detach and exit normally")
            append_log(log_path, '[x64dbg-test] ASSERT PASS source=driver message="first pause request did not pause the blocked debuggee"')
            append_log(log_path, '[x64dbg-test] ASSERT PASS source=driver message="repeated pause request paused via break-in thread"')
            append_log(log_path, "[x64dbg-test] FINAL status=pass asserts=2")
            return 0

        # Make a worker thread produce a debug event (OutputDebugString) and
        # then block forever, so the debugger's active thread is a thread that
        # never executes again.
        posted = ctypes.windll.user32.PostThreadMessageW(main_tid, WM_APP + int(hidden_mode), 0, 0)
        if not posted:
            return fail("signal_failed", "the owned main thread could not be signaled")
        if not hidden_mode and headless.wait_for_line(lambda line: "attach_pause: parking" in line, 10) is None:
            return fail("no_park_marker", "the unhidden debug-string event was not observed")
        parked_line = wait_for_ready(target, timeout=10)
        if not parked_line or not parked_line.startswith("parked "):
            return fail("no_native_park_marker", "the target did not identify its parked worker")
        target_lines.append(parked_line)
        _, parked_pid, parked_tid, parked_creation, wake_count = parked_line.split()
        parked_tid, parked_creation = int(parked_tid), int(parked_creation)
        if int(parked_pid) != pid or parked_tid == main_tid or int(wake_count) != 0:
            return fail("wrong_park_identity", "the target parked marker has the wrong process/thread or prior wake count")
        observations["blockedThread"] = wait_for_blocked_thread(target, parked_tid, parked_creation)
        if hidden_mode and headless.wait_for_line(lambda line: line.startswith(f"Thread {parked_tid} created,"), 10) is None:
            return fail("no_native_create_event", "the owned parked worker's real create-thread event was not observed")
        before = observe("before")
        observations["selectedBeforePause"] = before
        if before["pid"] != str(pid) or before["tid"] != str(parked_tid) or before["creation"] != str(parked_creation) or before["running"] != "1":
            return fail("wrong_selected_worker", "the running debugger did not select the actual blocked worker")

        # The pause command must interrupt the debuggee even though the active
        # thread is a parked worker thread that never executes.
        cursor = headless.mark()
        headless.send("pause")
        if headless.wait_for_line(lambda line: line == "[STATE] paused", 10, cursor) is None:
            return fail("pause_no_effect", "debugger did not pause after the pause command")

        paused = observe("paused")
        observations["selectedAtPause"] = paused
        if paused["pid"] != str(pid) or paused["tid"] != str(main_tid) or paused["creation"] != str(main_creation) or paused["running"] != "0" or paused["sdk"] != "1" or paused["native"] != "1" or int(paused["ip"], 16) == 0 or paused["ip"] != paused["nativeIp"]:
            return fail("wrong_pause_context", "the native OS/main-thread stop does not match the debugger context")
        if not observe_status_boundary():
            return fail("state_record_boundary", "native paused status merged with an unterminated log fragment")
        if not shutdown_headless():
            return fail("detach_failed", "the owned debugger did not detach and exit normally")
        observations["detached"] = native_process_state(target)
        if observations["detached"]["identity"] != observations["beforeAttach"]["identity"] or observations["detached"]["debugPortPresent"] or any(peb["beingDebugged"] for peb in observations["detached"]["pebs"]):
            return fail("port_retained", "the owned target still has a debug port after detach")
        if not ctypes.windll.user32.PostThreadMessageW(main_tid, WM_QUIT, 0, 0):
            return fail("quit_failed", "the owned main thread could not be asked to finish")
        completed_line = wait_for_ready(target, timeout=10)
        if not completed_line or not completed_line.startswith("completed "):
            return fail("no_completion", "the target did not report its independent wake/completion outcome")
        target_lines.append(completed_line)
        _, completed_pid, completed_wakes, port_read, port_present = completed_line.split()
        target.wait(timeout=10)
        if int(completed_pid) != pid or int(completed_wakes) != 1 or port_read != "1" or port_present != "0" or target.returncode != 0:
            return fail("wrong_completion", "the target did not execute exactly one pause wake and finish detached")
        observations["targetExit"] = target.returncode
        observations["completion"] = completed_line
        append_log(log_path, '[x64dbg-test] ASSERT PASS source=driver message="pause interrupted the attached debuggee"')
        append_log(log_path, "[x64dbg-test] FINAL status=pass asserts=1")
        return 0
    except (McpError, RuntimeError, ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
        observations["error"] = str(error)
        return fail("native_oracle_failed", str(error))
    finally:
        (artifacts_dir / "attach-observations.json").write_text(json.dumps(observations, indent=2) + "\n", encoding="utf-8")
        (artifacts_dir / "target.stdout.txt").write_text("\n".join(target_lines) + "\n", encoding="utf-8")
        if headless is not None:
            headless.dump(artifacts_dir / "headless.stdout.txt")
            if headless.process.poll() is None:
                headless.process.kill()
                headless.process.wait(timeout=5)
        if target.poll() is None:
            if main_tid:
                ctypes.windll.user32.PostThreadMessageW(main_tid, WM_QUIT, 0, 0)
            try:
                target.wait(timeout=5)
            except subprocess.TimeoutExpired:
                target.kill()
                target.wait(timeout=5)


if __name__ == "__main__":
    raise SystemExit(main())
