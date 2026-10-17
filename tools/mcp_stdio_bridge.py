"""x64dbg-wbbified agentic MCP bridge (Checkpoint 1).

Exposes the legacy x64dbg MCP HTTP endpoint as a newline-delimited JSON-RPC
server on stdio, which is the transport most AI-agent MCP clients speak.

The bridge owns one isolated debugger lifetime per process, started lazily
(the GUI only runs while the agent is actively calling tools):

1. Stage a private copy of ``WinTools/<arch>`` outside the repository.
2. Launch ``wininspect.exe`` with a fresh profile, random port and random
   bearer token, bound to an owned Windows job object.
3. Verify the HTTP listener belongs to the owned debugger PID, then run the
   MCP ``initialize`` handshake against the backend.
4. Forward stdio JSON-RPC to the backend session while the agent is active
   (``initialize``, ``ping``, ``BridgeInfo`` and cached ``tools/list``
   are answered with no debugger running; the first real ``tools/call``
   launches the visible GUI).
5. Stop the owned debugger after ``--idle-timeout`` seconds without a
   backend-backed call, and shut everything down on stdin EOF and exit.
   Pass ``--eager`` to launch the debugger at bridge startup instead.

Nothing is written to the repository or to ``WinTools``. The bearer token is
random per run and never written to stdout or the log in clear text.

Usage (from the repository root)::

    python tools/mcp_stdio_bridge.py --arch x64
    python tools/mcp_stdio_bridge.py --smoke-test --arch x64
    python tools/mcp_stdio_bridge.py --self-test
    python tools/mcp_stdio_bridge.py --print-config cursor

Only the standard library is used so agent hosts need no extra install.
"""

import argparse
import collections
import ctypes
import hashlib
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from ctypes import wintypes
from pathlib import Path

BRIDGE_VERSION = "0.2.0"
BRIDGE_NAME = "x64dbg-wbbified"
ROOT = Path(__file__).resolve().parent.parent
HOST = "127.0.0.1"
BACKEND_PROTOCOL = "2024-11-05"
CLIENT_PROTOCOLS = ("2025-11-25", "2025-03-26", "2024-11-05")
DEFAULT_RUN_ROOT = Path(os.environ.get("LOCALAPPDATA", tempfile.gettempdir())) / "x64dbg-wbbified" / "Agentic"
DEFAULT_IDLE_TIMEOUT = 120
WATCHDOG_INTERVAL = 5


def default_catalog_cache(architecture):
    return Path(os.environ.get("LOCALAPPDATA", tempfile.gettempdir())) / "x64dbg-wbbified" / f"tools-catalog-{architecture}.json"
# Loader-stop profiles written into each fresh debugger profile. "off" keeps the
# initial system pause and the entry-point stop but skips TLS/DLL/thread stops,
# so one `run` reaches the entry point. "stock" preserves x64dbg defaults.
LOADER_BREAKS_PROFILES = {
    "off": {"SystemBreakpoint": 1, "EntryBreakpoint": 1, "TlsCallbacks": 0, "TlsCallbacksSystem": 0,
            "DllEntry": 0, "DllEntrySystem": 0, "DllLoad": 0, "DllLoadSystem": 0,
            "DllUnload": 0, "DllUnloadSystem": 0, "ThreadEntry": 0, "ThreadStart": 0,
            "ThreadEnd": 0, "ThreadNameSet": 0, "DebugStrings": 0, "NtTerminateProcess": 0},
    "stock": {"SystemBreakpoint": 1, "EntryBreakpoint": 1, "TlsCallbacks": 1, "TlsCallbacksSystem": 0,
              "DllEntry": 0, "DllEntrySystem": 0, "DllLoad": 0, "DllLoadSystem": 0,
              "DllUnload": 0, "DllUnloadSystem": 0, "ThreadEntry": 0, "ThreadStart": 0,
              "ThreadEnd": 0, "ThreadNameSet": 0, "DebugStrings": 0, "NtTerminateProcess": 0},
}
BARE_RVA = re.compile(r"\.([0-9A-Fa-f]+)$")
BRIDGE_TOOL = {"name": "BridgeInfo",
               "description": "Describe this bridge session: bridge/backend versions, debugger PID, profile (PEB hiding, loader breaks), and environment notes.",
               "inputSchema": {"type": "object", "properties": {}}}

KERNEL = ctypes.WinDLL("kernel32", use_last_error=True)
USER = ctypes.WinDLL("user32", use_last_error=True)
JOB_OBJECT_KILL_ON_CLOSE = 0x2000
JOB_OBJECT_EXTENDED_LIMITS = 9
TCP_OWNER_PID_LISTENERS = 3
WINDOW_CLOSE = 0x10
KERNEL.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
KERNEL.CreateJobObjectW.restype = wintypes.HANDLE
KERNEL.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
KERNEL.SetInformationJobObject.restype = wintypes.BOOL
KERNEL.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
KERNEL.AssignProcessToJobObject.restype = wintypes.BOOL
KERNEL.CloseHandle.argtypes = [wintypes.HANDLE]
KERNEL.GetProcessTimes.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
USER.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.c_void_p]
USER.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]


class BridgeError(Exception):
    pass


def log(message, token=None):
    if token:
        message = message.replace(token, "[redacted]")
    sys.stderr.write(f"[bridge] {message}\n")
    sys.stderr.flush()


class JobLimits(ctypes.Structure):
    _fields_ = [("processTime", ctypes.c_int64), ("jobTime", ctypes.c_int64),
                ("flags", wintypes.DWORD), ("minimumWorkingSet", ctypes.c_size_t),
                ("maximumWorkingSet", ctypes.c_size_t), ("activeProcessLimit", wintypes.DWORD),
                ("affinity", ctypes.c_size_t), ("priority", wintypes.DWORD),
                ("scheduling", wintypes.DWORD)]


class IoCounters(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint64) for name in
                ("readOperations", "writeOperations", "otherOperations", "readBytes", "writeBytes", "otherBytes")]


class ExtendedJobLimits(ctypes.Structure):
    _fields_ = [("basic", JobLimits), ("io", IoCounters), ("processMemory", ctypes.c_size_t),
                ("jobMemory", ctypes.c_size_t), ("peakProcessMemory", ctypes.c_size_t),
                ("peakJobMemory", ctypes.c_size_t)]


class OwnedJob:
    def __init__(self):
        self.handle = KERNEL.CreateJobObjectW(None, None)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        limits = ExtendedJobLimits()
        limits.basic.flags = JOB_OBJECT_KILL_ON_CLOSE
        if not KERNEL.SetInformationJobObject(self.handle, JOB_OBJECT_EXTENDED_LIMITS, ctypes.byref(limits), ctypes.sizeof(limits)):
            error = ctypes.get_last_error()
            self.close()
            raise ctypes.WinError(error)

    def assign(self, process):
        if not KERNEL.AssignProcessToJobObject(self.handle, wintypes.HANDLE(int(process._handle))):
            raise ctypes.WinError(ctypes.get_last_error())

    def close(self):
        if self.handle:
            KERNEL.CloseHandle(self.handle)
            self.handle = None


def process_identity(process):
    times = [wintypes.FILETIME() for _ in range(4)]
    if not KERNEL.GetProcessTimes(wintypes.HANDLE(int(process._handle)), *(ctypes.byref(value) for value in times)):
        raise ctypes.WinError(ctypes.get_last_error())
    created = (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
    return {"pid": process.pid, "creationTime": str(created)}


def listener_pid(port):
    library = ctypes.WinDLL("iphlpapi", use_last_error=True)
    size = wintypes.DWORD()
    library.GetExtendedTcpTable(None, ctypes.byref(size), False, socket.AF_INET, TCP_OWNER_PID_LISTENERS, 0)
    if size.value > 8 * 1024 * 1024:
        raise BridgeError("TCP inventory exceeded its bound")
    buffer = ctypes.create_string_buffer(size.value)
    result = library.GetExtendedTcpTable(buffer, ctypes.byref(size), False, socket.AF_INET, TCP_OWNER_PID_LISTENERS, 0)
    if result:
        raise ctypes.WinError(result)
    rows = ctypes.cast(buffer, ctypes.POINTER(wintypes.DWORD))
    for index in range(rows[0]):
        offset = 1 + index * 6
        if socket.ntohs(rows[offset + 2] & 0xFFFF) == port:
            return rows[offset + 5]
    return None


def close_owned_windows(pid):
    callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

    def close_owned_window(window, context):
        process_id = wintypes.DWORD()
        USER.GetWindowThreadProcessId(window, ctypes.byref(process_id))
        if process_id.value == pid:
            USER.PostMessageW(window, WINDOW_CLOSE, 0, 0)
        return True

    callback = callback_type(close_owned_window)
    USER.EnumWindows(callback, 0)
    return callback


def free_port():
    with socket.socket() as probe:
        probe.bind((HOST, 0))
        return probe.getsockname()[1]


def stage_deployment(deployment, run_root, architecture):
    """Copy the debugger deployment into a private run directory."""
    deployment = Path(deployment)
    suffix = ".dp64" if architecture == "x64" else ".dp32"
    baseline_plugin = deployment / "plugins" / f"x64dbg-MCP-Server{suffix}"
    if not baseline_plugin.is_file():
        raise BridgeError(f"Legacy MCP baseline plugin is unavailable for {architecture}")
    stage = Path(run_root) / "deploy"
    stage.mkdir(parents=True)
    for source in deployment.iterdir():
        if source.is_file() and source.suffix.lower() in (".dll", ".exe"):
            shutil.copy2(source, stage / source.name)
    for directory in ("platforms", "iconengines", "imageformats", "styles"):
        source = deployment / directory
        if source.is_dir():
            shutil.copytree(source, stage / directory)
    plugins = stage / "plugins"
    shutil.copytree(deployment / "plugins", plugins)
    return stage


def write_profile_ini(profile, hide_debugger, loader_breaks):
    events = "\n".join(f"{key}={value}" for key, value in sorted(LOADER_BREAKS_PROFILES[loader_breaks].items()))
    (Path(profile) / "wininspect.ini").write_text(
        f"[Engine]\nHideDebugger={int(hide_debugger)}\nNoConsoleWindow=1\n[Misc]\nLoadLastSession=0\n[Events]\n{events}\n",
        encoding="utf-8")


class Backend:
    """One owned debugger process plus its authenticated MCP HTTP session."""

    def __init__(self, architecture, deployment=None, run_root=None, hide_debugger=True,
                 startup_timeout=45, request_timeout=60, loader_breaks="off",
                 idle_timeout=DEFAULT_IDLE_TIMEOUT, catalog_cache=None):
        if loader_breaks not in LOADER_BREAKS_PROFILES:
            raise BridgeError(f"Unknown loader-breaks profile '{loader_breaks}'")
        self.architecture = architecture
        self.loader_breaks = loader_breaks
        self.deployment = Path(deployment) if deployment else ROOT / "WinTools" / architecture
        if run_root:
            self.run_root = Path(run_root)
        else:
            DEFAULT_RUN_ROOT.mkdir(parents=True, exist_ok=True)
            self.run_root = Path(tempfile.mkdtemp(prefix="agentic-", dir=str(DEFAULT_RUN_ROOT)))
        self.hide_debugger = hide_debugger
        self.startup_timeout = startup_timeout
        self.request_timeout = request_timeout
        self.idle_timeout = idle_timeout
        self.catalog_cache = Path(catalog_cache) if catalog_cache else default_catalog_cache(architecture)
        self.auth = secrets.token_hex(32)
        self.port = None
        self.stage = None
        self.profile = None
        self.proc = None
        self.job = None
        self.rid = 1
        self.session = None
        self.server_info = None
        self.capabilities = None
        self.instructions = None
        self.started = False
        self.last_activity = time.monotonic()
        self._guard = threading.RLock()

    def is_running(self):
        proc = self.__dict__.get("proc")
        return proc is not None and proc.poll() is None

    def note_activity(self):
        self.last_activity = time.monotonic()

    def ensure_started(self):
        """Launch the owned debugger on first use; no-op while it runs."""
        with self._guard:
            if self.is_running():
                return self.server_info
            self.start()
            return self.server_info

    def check_idle(self):
        """Stop a debugger that outlived ``idle_timeout``. Returns True if stopped."""
        if not self.__dict__.get("idle_timeout"):
            return False
        with self._guard:
            if not self.is_running():
                return False
            if time.monotonic() - self.last_activity < self.idle_timeout:
                return False
            log(f"debugger idle for {self.idle_timeout}s, stopping GUI (state is discarded)")
            self.stop()
            return True

    def deployment_plugin_id(self):
        suffix = ".dp64" if self.architecture == "x64" else ".dp32"
        try:
            plugin = Path(self.deployment) / "plugins" / f"x64dbg-MCP-Server{suffix}"
            stat = plugin.stat()
            return f"{stat.st_size}:{stat.st_mtime_ns}"
        except OSError:
            return "unknown"

    def save_cached_catalog(self, result):
        try:
            self.catalog_cache.parent.mkdir(parents=True, exist_ok=True)
            self.catalog_cache.write_text(json.dumps({
                "backendVersion": (self.server_info or {}).get("version", "unknown"),
                "pluginId": self.deployment_plugin_id(),
                "result": result,
            }), encoding="utf-8")
        except OSError as error:
            log(f"catalog cache write failed: {error}")

    def load_cached_catalog(self):
        try:
            cached = json.loads(self.catalog_cache.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if not isinstance(cached, dict) or not isinstance(cached.get("result"), dict):
            return None
        if cached.get("pluginId") != self.deployment_plugin_id():
            return None
        return cached["result"]

    def start(self):
        self.run_root.mkdir(parents=True, exist_ok=True)
        self.stage = stage_deployment(self.deployment, self.run_root, self.architecture)
        self.profile = self.run_root / "profile"
        self.profile.mkdir(exist_ok=True)
        write_profile_ini(self.profile, self.hide_debugger, self.loader_breaks)
        self.port = free_port()
        (self.stage / "mcp_config.json").write_text(
            json.dumps({"IpAddress": HOST, "Port": self.port, "AutoStart": True, "AuthToken": self.auth}),
            encoding="utf-8")
        environment = os.environ.copy()
        for variable in ("QTDIR", "QT_PLUGIN_PATH", "QT_QPA_PLATFORM_PLUGIN_PATH", "QML_IMPORT_PATH", "QML2_IMPORT_PATH"):
            environment.pop(variable, None)
        self.job = OwnedJob()
        command = [str(self.stage / "wininspect.exe"), "-userdir", str(self.profile)]
        self.proc = subprocess.Popen(command, cwd=str(self.run_root), env=environment)
        try:
            self.job.assign(self.proc)
            identity = process_identity(self.proc)
            log(f"debugger pid={identity['pid']} port={self.port} stage={self.stage}")
            deadline = time.monotonic() + self.startup_timeout
            while time.monotonic() < deadline:
                if self.proc.poll() is not None:
                    raise BridgeError(f"Debugger exited during startup with code {self.proc.returncode}")
                try:
                    with socket.create_connection((HOST, self.port), 0.3):
                        break
                except OSError:
                    time.sleep(0.15)
            else:
                raise BridgeError("Owned MCP endpoint did not become ready")
            if listener_pid(self.port) != self.proc.pid:
                raise BridgeError("MCP listener does not belong to the owned debugger process")
            response = self.raw({"jsonrpc": "2.0", "id": 0, "method": "initialize",
                                 "params": {"protocolVersion": BACKEND_PROTOCOL, "capabilities": {},
                                            "clientInfo": {"name": BRIDGE_NAME, "version": BRIDGE_VERSION}}})
            result = (response or {}).get("result", {})
            if not result.get("serverInfo"):
                raise BridgeError("Legacy initialization failed")
            self.server_info = result["serverInfo"]
            self.capabilities = result.get("capabilities", {})
            self.instructions = result.get("instructions")
            self.raw({"jsonrpc": "2.0", "method": "notifications/initialized"})
            log(f"backend ready: {self.server_info.get('name')} {self.server_info.get('version')}")
            self.started = True
            self.note_activity()
        except BaseException:
            self.stop()
            raise
        return self.server_info

    def stop(self):
        if self.proc is not None:
            if self.proc.poll() is None:
                close_owned_windows(self.proc.pid)
                try:
                    self.proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
                    self.proc.wait(timeout=5)
            self.proc = None
        if self.job is not None:
            self.job.close()
            self.job = None
        self.session = None
        self.started = False

    def raw(self, payload):
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                   "Authorization": "Bearer " + self.auth}
        if self.session:
            headers["Mcp-Session-Id"] = self.session
        request = urllib.request.Request(f"http://{HOST}:{self.port}/", data=json.dumps(payload).encode(), headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=self.request_timeout) as response:
                session_id = response.headers.get("Mcp-Session-Id")
                if session_id:
                    self.session = session_id
                body = response.read().decode()
                content_type = response.headers.get("Content-Type", "")
        except Exception as error:
            raise BridgeError(f"Backend request failed: {type(error).__name__}: {error}")
        if content_type.startswith("text/event-stream"):
            frames = [line[5:].strip() for line in body.splitlines() if line.startswith("data:")]
            return json.loads("\n".join(frames)) if frames else None
        return json.loads(body) if body.strip() else None

    def call_backend(self, method, params=None):
        payload = {"jsonrpc": "2.0", "id": self.rid, "method": method}
        self.rid += 1
        if params is not None:
            payload["params"] = params
        return self.raw(payload)

    def list_tools(self, cursor=None):
        params = {"cursor": cursor} if cursor else None
        response = self.call_backend("tools/list", params)
        if not response or "result" not in response:
            raise BridgeError(f"Backend tools/list failed: {json.dumps(response)[:300]}")
        return response["result"]

    def call_tool(self, name, arguments=None):
        response = self.call_backend("tools/call", {"name": name, "arguments": arguments or {}})
        if response is None:
            raise BridgeError(f"Tool {name} returned no response")
        if response.get("error"):
            raise BridgeError(f"Tool {name} RPC error: {json.dumps(response['error'])[:300]}")
        return response.get("result", {})


class StdioServer:
    """Newline-delimited JSON-RPC front end forwarding to one Backend."""

    def __init__(self, backend):
        self.backend = backend
        self.stdin = sys.stdin.buffer
        self.stdout = sys.stdout.buffer
        self.journal = collections.deque(maxlen=64)

    def reply(self, envelope):
        self.stdout.write((json.dumps(envelope) + "\n").encode())
        self.stdout.flush()

    def bridge_instructions(self):
        idle = self.backend.__dict__.get("idle_timeout", DEFAULT_IDLE_TIMEOUT)
        idle_note = (f"Debugger GUI starts visibly on the first tool call and stops after {idle}s idle. "
                     if idle else "Debugger GUI starts visibly on the first tool call and stays until the session ends. ")
        return (f"{BRIDGE_NAME} stdio bridge {BRIDGE_VERSION}. One isolated debugger per session (staged copy, fresh profile). "
                + idle_note +
                "All backend tools plus BridgeInfo are callable; "
                "results end with a [state] trailer and GetEventLog carries a bridge journal with observed addresses. "
                "Stopping the idle debugger discards debug state (target, breakpoints); the next call starts fresh. "
                "Loader stops: TLS/DLL/thread breaks off, entry stop on. "
                "Bare `.RVA` addresses resolve against the current module. "
                "Third-party DLLs (shell mods, AV) may inject into debug targets and appear in module lists.")

    def bridge_info_text(self):
        windows = sys.getwindowsversion()
        running = self.backend.is_running() if hasattr(self.backend, "is_running") else False
        proc = self.backend.__dict__.get("proc")
        info = {
            "bridge": {"name": BRIDGE_NAME, "version": BRIDGE_VERSION},
            "backend": self.backend.server_info or {"status": "not-started"},
            "lifecycle": {"mode": "lazy", "running": running,
                          "idleTimeout": self.backend.__dict__.get("idle_timeout", DEFAULT_IDLE_TIMEOUT)},
            "debugger": {"pid": proc.pid if running else None, "architecture": self.backend.architecture},
            "profile": {"hideDebugger": self.backend.hide_debugger, "loaderBreaks": self.backend.loader_breaks},
            "host": {"windows": f"{windows.major}.{windows.minor}.{windows.build}", "isolatedStage": True},
            "notes": ["Bare `.RVA` addresses are resolved against the current module before forwarding.",
                      "Third-party DLLs injected into targets (shell extensions, mods, AV) show up in ListModules.",
                      "The debugger GUI only runs while tools are in use; an idle stop discards debug state."],
        }
        return json.dumps(info, indent=2)

    def normalize_arguments(self, arguments):
        """Rewrite a bare `.RVA` address against the current module base."""
        if not isinstance(arguments, dict) or not isinstance(arguments.get("address"), str):
            return arguments
        match = BARE_RVA.match(arguments["address"].strip())
        if not match:
            return arguments
        try:
            state = self.backend.call_tool("GetDebugState", {})
            state_text = "\n".join(item.get("text", "") for item in state.get("content", []))
            module = next(line.split(":", 1)[1].strip() for line in state_text.splitlines() if line.startswith("currentModule:"))
            modules = self.backend.call_tool("ListModules", {})
            module_text = "\n".join(item.get("text", "") for item in modules.get("content", []))
            for line in module_text.splitlines():
                fields = [field.strip() for field in line.split("|")]
                if len(fields) < 3:
                    continue
                name = fields[2]
                if name == module or name.lower() == module.lower() + ".dll" or name.split(".")[0].lower() == module.lower():
                    rewritten = {**arguments, "address": f"0x{int(fields[0], 16) + int(match.group(1), 16):x}"}
                    log(f"normalized {arguments['address']} to {rewritten['address']} via {name}")
                    return rewritten
            log(f"current module {module} not in module list; forwarding {arguments['address']} unchanged")
        except BridgeError as error:
            log(f"address normalization failed, forwarding unchanged: {error}")
        return arguments

    def record_journal(self, name, result):
        if not isinstance(result, dict):
            return
        texts = [item.get("text", "") for item in result.get("content", [])]
        events = [line for text in texts for line in text.splitlines() if line.startswith("[event:")]
        states = [line for text in texts for line in text.splitlines() if line.startswith("[state]")]
        if events and states:
            self.journal.append({"tool": name, "events": events[-4:], "state": states[-1]})

    def journal_appendix(self):
        if not self.journal:
            return None
        lines = ["[bridge journal: session events with observed addresses]"]
        for entry in list(self.journal)[-20:]:
            for event in entry["events"]:
                lines.append(f"- {event} @ {entry['state']}")
        return "\n".join(lines)

    def handle(self, message):
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0" or "method" not in message:
            if isinstance(message, dict) and "id" in message:
                return {"jsonrpc": "2.0", "id": message["id"],
                        "error": {"code": -32600, "message": "Invalid JSON-RPC request"}}
            return None
        method = message["method"]
        params = message.get("params", {})
        has_id = "id" in message
        try:
            if method == "initialize":
                requested = params.get("protocolVersion", BACKEND_PROTOCOL)
                version = requested if requested in CLIENT_PROTOCOLS else BACKEND_PROTOCOL
                backend_version = self.backend.server_info.get("version", "unknown") if self.backend.server_info else "not-started"
                result = {"protocolVersion": version, "capabilities": self.backend.capabilities or {"tools": {}},
                          "serverInfo": {"name": BRIDGE_NAME, "version": f"{BRIDGE_VERSION}+backend-{backend_version}"}}
                notes = self.bridge_instructions()
                result["instructions"] = f"{self.backend.instructions}\n{notes}" if self.backend.instructions else notes
                return {"jsonrpc": "2.0", "id": message["id"], "result": result} if has_id else None
            if method == "ping":
                return {"jsonrpc": "2.0", "id": message["id"], "result": {}} if has_id else None
            if method == "tools/list":
                if self.backend.is_running():
                    with self.backend._guard:
                        self.backend.ensure_started()
                        response = self.backend.call_backend(method, params or None)
                    if response is None:
                        raise BridgeError(f"Backend {method} returned no response")
                    if "error" in response and response["error"]:
                        return {"jsonrpc": "2.0", "id": message["id"], "error": response["error"]} if has_id else None
                    merged = dict(response.get("result", {}))
                    self.backend.note_activity()
                    self.backend.save_cached_catalog(merged)
                else:
                    cached = self.backend.load_cached_catalog()
                    if cached is None:
                        log("no cached tool catalog, starting debugger for tools/list")
                        with self.backend._guard:
                            self.backend.ensure_started()
                            response = self.backend.call_backend(method, params or None)
                        if response is None:
                            raise BridgeError(f"Backend {method} returned no response")
                        if "error" in response and response["error"]:
                            return {"jsonrpc": "2.0", "id": message["id"], "error": response["error"]} if has_id else None
                        merged = dict(response.get("result", {}))
                        self.backend.note_activity()
                        self.backend.save_cached_catalog(merged)
                    else:
                        merged = dict(cached)
                merged["tools"] = [*merged.get("tools", []), dict(BRIDGE_TOOL)]
                return {"jsonrpc": "2.0", "id": message["id"], "result": merged} if has_id else None
            if method == "tools/call":
                name = (params or {}).get("name")
                if name == "BridgeInfo":
                    info = {"content": [{"type": "text", "text": self.bridge_info_text()}]}
                    return {"jsonrpc": "2.0", "id": message["id"], "result": info} if has_id else None
                with self.backend._guard:
                    self.backend.ensure_started()
                    forwarded = dict(params or {})
                    if isinstance(forwarded.get("arguments"), dict):
                        forwarded["arguments"] = self.normalize_arguments(forwarded["arguments"])
                    response = self.backend.call_backend(method, forwarded or None)
                    self.backend.note_activity()
                if response is None:
                    raise BridgeError(f"Backend {method} returned no response")
                if "error" in response and response["error"]:
                    return {"jsonrpc": "2.0", "id": message["id"], "error": response["error"]} if has_id else None
                merged = dict(response.get("result", {}))
                self.record_journal(name, merged)
                if name == "GetEventLog":
                    appendix = self.journal_appendix()
                    if appendix:
                        merged["content"] = [*merged.get("content", []), {"type": "text", "text": appendix}]
                return {"jsonrpc": "2.0", "id": message["id"], "result": merged} if has_id else None
            if method.startswith("notifications/"):
                if self.backend.is_running():
                    try:
                        self.backend.raw({"jsonrpc": "2.0", "method": method, "params": params or {}})
                    except BridgeError as error:
                        log(f"notification forward failed: {error}")
                return None
            if not self.backend.is_running():
                if has_id:
                    return {"jsonrpc": "2.0", "id": message["id"],
                            "error": {"code": -32601, "message": f"Method not found: {method}"}}
                return None
            with self.backend._guard:
                self.backend.ensure_started()
                response = self.backend.call_backend(method, params or None)
                self.backend.note_activity()
            if response is None or not has_id:
                return None
            if "error" in response and response["error"]:
                return {"jsonrpc": "2.0", "id": message["id"], "error": response["error"]}
            return {"jsonrpc": "2.0", "id": message["id"], "result": response.get("result", {})}
        except BridgeError as error:
            log(f"request {method} failed: {error}")
            if has_id:
                return {"jsonrpc": "2.0", "id": message["id"],
                        "error": {"code": -32603, "message": str(error)[:500]}}
            return None

    def watch_idle(self, stop_event):
        while not stop_event.wait(WATCHDOG_INTERVAL):
            try:
                self.backend.check_idle()
            except Exception as error:
                log(f"idle watchdog failed: {type(error).__name__}: {error}")

    def serve(self):
        stop_watch = threading.Event()
        watcher = None
        if self.backend.__dict__.get("idle_timeout"):
            watcher = threading.Thread(target=self.watch_idle, args=(stop_watch,), daemon=True)
            watcher.start()
        try:
            while True:
                line = self.stdin.readline()
                if not line:
                    log("stdin EOF, shutting down")
                    return
                line = line.strip()
                if not line:
                    continue
                try:
                    message = json.loads(line.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    self.reply({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}})
                    continue
                try:
                    response = self.handle(message)
                except Exception as error:  # never let one request kill the session
                    log(f"handler crashed: {type(error).__name__}: {error}")
                    response = {"jsonrpc": "2.0", "id": message.get("id"),
                                "error": {"code": -32603, "message": "Internal bridge error"}} if "id" in message else None
                if response is not None:
                    self.reply(response)
        finally:
            stop_watch.set()
            if watcher is not None:
                watcher.join(timeout=5)


def run_self_test():
    """Translate stdio<->HTTP against a fake in-process backend (no debugger)."""
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    calls = []

    class FakeBackend(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            payload = json.loads(self.rfile.read(length).decode())
            calls.append(payload)
            if payload.get("method") == "initialize":
                result = {"protocolVersion": BACKEND_PROTOCOL, "capabilities": {"tools": {}},
                          "serverInfo": {"name": "fake-mcp", "version": "9.9"}}
            elif payload.get("method") == "tools/list":
                result = {"tools": [{"name": "Echo", "description": "echo",
                                     "inputSchema": {"type": "object", "properties": {"message": {"type": "string"}}}}]}
            elif payload.get("method") == "tools/call":
                args = (payload.get("params") or {}).get("arguments", {})
                name = (payload.get("params") or {}).get("name", "")
                if name == "GetDebugState":
                    result = {"content": [{"type": "text", "text": "currentModule: fake-mod\ncurrentAddress: 0x1010"}]}
                elif name == "ListModules":
                    result = {"content": [{"type": "text", "text": "0x1000 | 0x100 | fake-mod.dll"}]}
                elif name == "Disassemble":
                    result = {"content": [{"type": "text", "text": "disasm at " + str(args.get("address", ""))},
                                          {"type": "text", "text": "[event:info] Debugger paused.\n[state] PAUSED at 0x1010 (fake-mod)"}]}
                elif name == "GetEventLog":
                    result = {"content": [{"type": "text", "text": "[x64dbg-MCP Server] Breakpoint hit."}]}
                else:
                    result = {"content": [{"type": "text", "text": "fake:" + args.get("message", "")}]}
            elif payload.get("method") == "ping":
                result = {}
            else:
                body = json.dumps({"jsonrpc": "2.0", "id": payload.get("id"),
                                   "error": {"code": -32601, "message": "Method not found"}}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if "id" not in payload:
                self.send_response(202)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            body = json.dumps({"jsonrpc": "2.0", "id": payload["id"], "result": result}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = HTTPServer((HOST, 0), FakeBackend)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    class _RunningProc:
        def __init__(self, pid):
            self.pid = pid

        def poll(self):
            return None

    def _lazy_backend(cache_file):
        lazy = Backend.__new__(Backend)
        lazy.port = server.server_port
        lazy.auth = "self-test-token"
        lazy.session = None
        lazy.rid = 1
        lazy.request_timeout = 10
        lazy.server_info = None
        lazy.capabilities = None
        lazy.instructions = None
        lazy.proc = None
        lazy.started = False
        lazy.architecture = "x64"
        lazy.deployment = ROOT / "WinTools" / "x64"
        lazy.hide_debugger = True
        lazy.loader_breaks = "off"
        lazy.idle_timeout = 120
        lazy.catalog_cache = Path(cache_file)
        lazy.last_activity = time.monotonic()
        lazy._guard = threading.RLock()
        return lazy

    def _lazy_frontend(lazy):
        frontend = StdioServer.__new__(StdioServer)
        frontend.backend = lazy
        frontend.journal = collections.deque(maxlen=64)
        return frontend

    try:
        cache_dir = tempfile.mkdtemp(prefix="bridge-catalog-")
        backend = Backend.__new__(Backend)
        backend.port = server.server_port
        backend.auth = "self-test-token"
        backend.session = None
        backend.rid = 1
        backend.request_timeout = 10
        backend.server_info = {"name": "fake-mcp", "version": "9.9"}
        backend.capabilities = {"tools": {}}
        backend.instructions = None
        backend.proc = _RunningProc(424242)
        backend.started = True
        backend.architecture = "x64"
        backend.deployment = ROOT / "WinTools" / "x64"
        backend.hide_debugger = True
        backend.loader_breaks = "off"
        backend.idle_timeout = 0
        backend.catalog_cache = Path(cache_dir) / "running-catalog.json"
        backend.last_activity = time.monotonic()
        backend._guard = threading.RLock()
        frontend = StdioServer.__new__(StdioServer)
        frontend.backend = backend
        frontend.journal = collections.deque(maxlen=64)

        initialize = frontend.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                      "params": {"protocolVersion": "2025-03-26", "capabilities": {},
                                                 "clientInfo": {"name": "self-test", "version": "0"}}})
        assert initialize["result"]["protocolVersion"] == "2025-03-26", initialize
        assert initialize["result"]["serverInfo"]["name"] == BRIDGE_NAME, initialize
        assert BRIDGE_NAME in initialize["result"]["instructions"], initialize
        listed = frontend.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        assert [tool["name"] for tool in listed["result"]["tools"]] == ["Echo", "BridgeInfo"], listed
        info = frontend.handle({"jsonrpc": "2.0", "id": 20, "method": "tools/call",
                                "params": {"name": "BridgeInfo", "arguments": {}}})
        assert f'"version": "{BRIDGE_VERSION}"' in info["result"]["content"][0]["text"], info
        assert '"loaderBreaks": "off"' in info["result"]["content"][0]["text"], info
        assert not any(call.get("method") == "tools/call" and (call.get("params") or {}).get("name") == "BridgeInfo" for call in calls)
        disasm = frontend.handle({"jsonrpc": "2.0", "id": 21, "method": "tools/call",
                                  "params": {"name": "Disassemble", "arguments": {"address": ".10", "count": 2}}})
        forwarded = [call for call in calls if (call.get("params") or {}).get("name") == "Disassemble"]
        assert forwarded and forwarded[-1]["params"]["arguments"]["address"] == "0x1010", forwarded
        assert "0x1010" in disasm["result"]["content"][0]["text"], disasm
        absolute = frontend.handle({"jsonrpc": "2.0", "id": 22, "method": "tools/call",
                                    "params": {"name": "Disassemble", "arguments": {"address": "0x2000"}}})
        forwarded = [call for call in calls if (call.get("params") or {}).get("name") == "Disassemble"]
        assert forwarded[-1]["params"]["arguments"]["address"] == "0x2000", forwarded
        assert "result" in absolute, absolute
        events = frontend.handle({"jsonrpc": "2.0", "id": 23, "method": "tools/call",
                                  "params": {"name": "GetEventLog", "arguments": {}}})
        appendix = events["result"]["content"][-1]["text"]
        assert "bridge journal" in appendix and "0x1010" in appendix, appendix
        profile_dir = tempfile.mkdtemp(prefix="bridge-profile-")
        write_profile_ini(profile_dir, True, "off")
        ini = Path(profile_dir, "wininspect.ini").read_text(encoding="utf-8")
        assert "TlsCallbacks=0" in ini and "EntryBreakpoint=1" in ini and "HideDebugger=1" in ini, ini
        write_profile_ini(profile_dir, False, "stock")
        ini = Path(profile_dir, "wininspect.ini").read_text(encoding="utf-8")
        assert "TlsCallbacks=1" in ini and "HideDebugger=0" in ini, ini
        shutil.rmtree(profile_dir, ignore_errors=True)
        called = frontend.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                                  "params": {"name": "Echo", "arguments": {"message": "hi"}}})
        assert called["result"]["content"][0]["text"] == "fake:hi", called
        pinged = frontend.handle({"jsonrpc": "2.0", "id": 4, "method": "ping"})
        assert pinged["result"] == {}, pinged
        unknown = frontend.handle({"jsonrpc": "2.0", "id": 5, "method": "resources/list"})
        assert unknown["error"]["code"] == -32601, unknown
        assert frontend.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
        invalid = frontend.handle({"nope": True})
        assert invalid is None
        malformed = frontend.handle({"jsonrpc": "2.0", "id": 6, "method": "tools/call"})
        assert "error" in malformed or "result" in malformed, malformed
        assert any(call.get("method") == "tools/call" for call in calls), calls
        calls_before_lazy = len(calls)
        stopped = _lazy_backend(str(Path(cache_dir) / "stopped-catalog.json"))
        stopped_frontend = _lazy_frontend(stopped)

        def _must_not_start():
            raise AssertionError("lazy path launched the debugger")

        stopped.ensure_started = _must_not_start
        lazy_init = stopped_frontend.handle({"jsonrpc": "2.0", "id": 100, "method": "initialize", "params": {}})
        assert lazy_init["result"]["serverInfo"]["name"] == BRIDGE_NAME, lazy_init
        assert "not-started" in lazy_init["result"]["serverInfo"]["version"], lazy_init
        lazy_info = stopped_frontend.handle({"jsonrpc": "2.0", "id": 101, "method": "tools/call",
                                             "params": {"name": "BridgeInfo", "arguments": {}}})
        lazy_text = lazy_info["result"]["content"][0]["text"]
        assert '"running": false' in lazy_text and '"status": "not-started"' in lazy_text, lazy_text
        stopped.save_cached_catalog({"tools": [{"name": "Echo", "description": "echo",
                                                "inputSchema": {"type": "object", "properties": {}}}]})
        lazy_list = stopped_frontend.handle({"jsonrpc": "2.0", "id": 102, "method": "tools/list", "params": {}})
        assert [tool["name"] for tool in lazy_list["result"]["tools"]] == ["Echo", "BridgeInfo"], lazy_list
        lazy_unknown = stopped_frontend.handle({"jsonrpc": "2.0", "id": 103, "method": "resources/list"})
        assert lazy_unknown["error"]["code"] == -32601, lazy_unknown
        assert stopped_frontend.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
        assert len(calls) == calls_before_lazy, "lazy metadata paths reached the backend"
        woken = _lazy_backend(str(Path(cache_dir) / "woken-catalog.json"))
        woken_frontend = _lazy_frontend(woken)
        wake_calls = []

        def _fake_ensure():
            wake_calls.append(True)
            woken.proc = _RunningProc(434343)
            woken.started = True
            woken.server_info = {"name": "fake-mcp", "version": "9.9"}
            woken.capabilities = {"tools": {}}
            woken.note_activity()
            return woken.server_info

        woken.ensure_started = _fake_ensure
        woken_echo = woken_frontend.handle({"jsonrpc": "2.0", "id": 104, "method": "tools/call",
                                            "params": {"name": "Echo", "arguments": {"message": "wake"}}})
        assert wake_calls == [True], "first tool call did not start the debugger"
        assert woken_echo["result"]["content"][0]["text"] == "fake:wake", woken_echo
        idle = _lazy_backend(str(Path(cache_dir) / "idle-catalog.json"))
        idle.proc = _RunningProc(444444)
        idle.started = True
        idle_stops = []
        idle.stop = lambda: idle_stops.append(True)
        idle.last_activity = time.monotonic() - 121
        assert idle.check_idle() is True and idle_stops == [True], "stale debugger was not stopped"
        idle.last_activity = time.monotonic()
        assert idle.check_idle() is False, "active debugger was stopped early"
        idle.proc = None
        idle.last_activity = time.monotonic() - 1000
        assert idle.check_idle() is False, "stopped backend reported an idle stop"
        idle.idle_timeout = 0
        idle.proc = _RunningProc(444444)
        assert idle.check_idle() is False, "disabled idle timeout stopped the debugger"
        shutil.rmtree(cache_dir, ignore_errors=True)
    finally:
        server.shutdown()
        thread.join(timeout=5)
    print(json.dumps({"selfTest": "passed", "backendCalls": len(calls)}))
    return 0


def run_smoke_test(architecture, deployment, run_root, hide_debugger, startup_timeout, request_timeout, loader_breaks="off"):
    """Launch a real owned debugger and exercise list + Echo + idle state."""
    backend = Backend(architecture, deployment, run_root, hide_debugger, startup_timeout, request_timeout, loader_breaks)
    summary = {"architecture": architecture, "loaderBreaks": loader_breaks}
    try:
        server = backend.start()
        summary["server"] = server
        summary["pid"] = backend.proc.pid
        ini = (backend.profile / "wininspect.ini").read_text(encoding="utf-8")
        expected_tls = "TlsCallbacks=0" if loader_breaks == "off" else "TlsCallbacks=1"
        if expected_tls not in ini or "EntryBreakpoint=1" not in ini:
            raise BridgeError(f"Smoke profile missed loader-breaks {loader_breaks}")
        summary["profileEvents"] = expected_tls
        catalog = backend.list_tools()
        names = [tool["name"] for tool in catalog.get("tools", [])]
        summary["toolCount"] = len(names)
        for required in ("Echo", "GetDebugState"):
            if required not in names:
                raise BridgeError(f"Smoke catalog is missing {required}")
        frontend = StdioServer(backend)
        merged = frontend.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
        merged_names = [tool["name"] for tool in merged["result"]["tools"]]
        if merged_names[-1] != "BridgeInfo" or len(merged_names) != len(names) + 1:
            raise BridgeError("Smoke tools/list missed the BridgeInfo merge")
        summary["mergedToolCount"] = len(merged_names)
        info = frontend.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                "params": {"name": "BridgeInfo", "arguments": {}}})
        if f'"loaderBreaks": "{loader_breaks}"' not in info["result"]["content"][0]["text"]:
            raise BridgeError("Smoke BridgeInfo missed the loader-breaks profile")
        echoed = backend.call_tool("Echo", {"message": "agentic-smoke"})
        text = "\n".join(item.get("text", "") for item in echoed.get("content", []))
        if "agentic-smoke" not in text:
            raise BridgeError(f"Echo did not round-trip: {text[:200]}")
        summary["echo"] = text[:200]
        state = backend.call_tool("GetDebugState", {})
        state_text = "\n".join(item.get("text", "") for item in state.get("content", []))
        if not state_text.strip():
            raise BridgeError("GetDebugState returned empty idle state")
        summary["idleStateLines"] = len(state_text.splitlines())
        summary["status"] = "passed"
    finally:
        backend.stop()
    summary["runRoot"] = str(backend.run_root)
    print(json.dumps(summary, indent=2))
    return 0


EXAMPLE_CONFIGS = {
    "claude-desktop": {"file": "%APPDATA%/Claude/claude_desktop_config.json", "key": "mcpServers"},
    "cursor": {"file": ".cursor/mcp.json  (project) or ~/.cursor/mcp.json (global)", "key": "mcpServers"},
    "claude-code": {"file": ".mcp.json  (project root)", "key": "mcpServers"},
    "vscode": {"file": ".vscode/mcp.json", "key": "servers"},
}


def print_config(client, architecture):
    if client not in EXAMPLE_CONFIGS:
        raise BridgeError(f"Unknown client '{client}'; choose from {sorted(EXAMPLE_CONFIGS)}")
    bridge = str(ROOT / "tools" / "mcp_stdio_bridge.py")
    entry = {"command": sys.executable, "args": [bridge, "--arch", architecture]}
    if client == "vscode":
        entry = {"type": "stdio", **entry}
    spec = EXAMPLE_CONFIGS[client]
    print(f"# {spec['file']}")
    print(json.dumps({spec["key"]: {"x64dbg": entry}}, indent=2))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="x64dbg-wbbified stdio MCP bridge for AI agents")
    parser.add_argument("--arch", choices=("x64", "x32"), default="x64")
    parser.add_argument("--deployment", default=None, help="Debugger directory (default: WinTools/<arch>)")
    parser.add_argument("--run-root", default=None, help="Private run directory (default: fresh dir under Agentic)")
    parser.add_argument("--show-debugger", action="store_true",
                        help="Leave PEB hiding off (default hides the debugger from targets)")
    parser.add_argument("--loader-breaks", choices=("off", "stock"), default="off",
                        help="Loader stops: off skips TLS/DLL/thread breaks so one run reaches the entry point; stock keeps x64dbg defaults")
    parser.add_argument("--startup-timeout", type=int, default=45)
    parser.add_argument("--request-timeout", type=int, default=60)
    parser.add_argument("--idle-timeout", type=int, default=DEFAULT_IDLE_TIMEOUT,
                        help="Stop the debugger GUI after this many idle seconds (default 120, 0 disables auto-stop)")
    parser.add_argument("--eager", action="store_true",
                        help="Launch the debugger at bridge startup instead of on the first tool call")
    parser.add_argument("--self-test", action="store_true", help="Protocol translation check without a debugger")
    parser.add_argument("--smoke-test", action="store_true", help="Real debugger launch, list, Echo and idle state")
    parser.add_argument("--print-config", choices=sorted(EXAMPLE_CONFIGS), default=None,
                        help="Print an MCP client config snippet and exit")
    arguments = parser.parse_args(argv)
    if not 1 <= arguments.startup_timeout <= 300 or not 1 <= arguments.request_timeout <= 300:
        parser.error("Timeouts must stay within 1..300 seconds")
    if not 0 <= arguments.idle_timeout <= 3600:
        parser.error("Idle timeout must stay within 0..3600 seconds")
    try:
        if arguments.print_config:
            return print_config(arguments.print_config, arguments.arch)
        if arguments.self_test:
            return run_self_test()
        if arguments.smoke_test:
            return run_smoke_test(arguments.arch, arguments.deployment, arguments.run_root,
                                  not arguments.show_debugger, arguments.startup_timeout, arguments.request_timeout,
                                  arguments.loader_breaks)
        backend = Backend(arguments.arch, arguments.deployment, arguments.run_root,
                          not arguments.show_debugger, arguments.startup_timeout, arguments.request_timeout,
                          arguments.loader_breaks, idle_timeout=arguments.idle_timeout)
        try:
            if arguments.eager:
                backend.start()
            else:
                log(f"lazy mode: debugger GUI starts on first tool call"
                    + (f", stops after {arguments.idle_timeout}s idle" if arguments.idle_timeout else ", no auto-stop"))
            StdioServer(backend).serve()
        finally:
            backend.stop()
        return 0
    except BridgeError as error:
        log(f"fatal: {error}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
