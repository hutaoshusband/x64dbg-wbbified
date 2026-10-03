import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import sys
import time
import urllib.request


ROOT = Path(__file__).resolve().parent.parent
TARGET_SOURCES = ROOT / "tests" / "targets"
HOST = "127.0.0.1"
KERNEL = ctypes.WinDLL("kernel32", use_last_error=True)
PSAPI = ctypes.WinDLL("psapi", use_last_error=True)
USER = ctypes.WinDLL("user32", use_last_error=True)
JOB_OBJECT_KILL_ON_CLOSE = 0x2000
JOB_OBJECT_EXTENDED_LIMITS = 9
TCP_OWNER_PID_LISTENERS = 3
WINDOW_CLOSE = 0x10
CREATE_SUSPENDED = 0x4
THREAD_SNAPSHOT = 0x4
THREAD_SUSPEND_RESUME = 0x2
THREAD_QUERY_INFORMATION = 0x40
KERNEL.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
KERNEL.CreateJobObjectW.restype = wintypes.HANDLE
KERNEL.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
KERNEL.SetInformationJobObject.restype = wintypes.BOOL
KERNEL.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
KERNEL.AssignProcessToJobObject.restype = wintypes.BOOL
KERNEL.CloseHandle.argtypes = [wintypes.HANDLE]
KERNEL.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
KERNEL.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
KERNEL.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
KERNEL.OpenThread.restype = wintypes.HANDLE
KERNEL.GetProcessIdOfThread.argtypes = [wintypes.HANDLE]
KERNEL.GetProcessIdOfThread.restype = wintypes.DWORD
KERNEL.ResumeThread.argtypes = [wintypes.HANDLE]
KERNEL.ResumeThread.restype = wintypes.DWORD
KERNEL.GetProcessTimes.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
PSAPI.EnumProcessModulesEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD]
PSAPI.GetModuleFileNameExW.argtypes = [wintypes.HANDLE, wintypes.HMODULE, wintypes.LPWSTR, wintypes.DWORD]
USER.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.c_void_p]
USER.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]


class McpError(Exception):
    pass


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


class ThreadEntry(ctypes.Structure):
    _fields_ = [("size", wintypes.DWORD), ("usage", wintypes.DWORD), ("threadId", wintypes.DWORD),
                ("processId", wintypes.DWORD), ("basePriority", wintypes.LONG),
                ("deltaPriority", wintypes.LONG), ("flags", wintypes.DWORD)]


KERNEL.Thread32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(ThreadEntry)]
KERNEL.Thread32First.restype = wintypes.BOOL
KERNEL.Thread32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(ThreadEntry)]
KERNEL.Thread32Next.restype = wintypes.BOOL


def resume_suspended_process(process):
    snapshot = KERNEL.CreateToolhelp32Snapshot(THREAD_SNAPSHOT, 0)
    if snapshot == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    thread_ids = []
    try:
        entry = ThreadEntry()
        entry.size = ctypes.sizeof(entry)
        found = KERNEL.Thread32First(snapshot, ctypes.byref(entry))
        while found:
            if entry.processId == process.pid:
                thread_ids.append(entry.threadId)
            entry.size = ctypes.sizeof(entry)
            found = KERNEL.Thread32Next(snapshot, ctypes.byref(entry))
        if ctypes.get_last_error() != 18:
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        KERNEL.CloseHandle(snapshot)
    if len(thread_ids) != 1:
        raise McpError("Suspended runner does not have exactly one startup thread")
    thread = KERNEL.OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, False, thread_ids[0])
    if not thread:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        owner = KERNEL.GetProcessIdOfThread(thread)
        if not owner:
            raise ctypes.WinError(ctypes.get_last_error())
        if owner != process.pid:
            raise McpError("Suspended runner thread belongs to a different process")
        count = KERNEL.ResumeThread(thread)
        if count == 0xffffffff:
            raise ctypes.WinError(ctypes.get_last_error())
        if count != 1:
            raise McpError("Runner startup thread was not suspended exactly once")
    finally:
        KERNEL.CloseHandle(thread)
    return thread_ids[0]


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

    def __enter__(self):
        return self

    def __exit__(self, error_type, error, traceback):
        self.close()

    def close(self):
        if self.handle:
            KERNEL.CloseHandle(self.handle)
            self.handle = None


def file_identity(path):
    path = Path(path).resolve()
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return {"path": str(path), "size": path.stat().st_size, "sha256": digest.hexdigest()}


def tree_identity(directory):
    return [file_identity(path) for path in sorted(Path(directory).rglob("*")) if path.is_file()]


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")


def process_identity(process):
    times = [wintypes.FILETIME() for _ in range(4)]
    if not KERNEL.GetProcessTimes(wintypes.HANDLE(int(process._handle)), *(ctypes.byref(value) for value in times)):
        raise ctypes.WinError(ctypes.get_last_error())
    created = (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
    return {"pid": process.pid, "creationTime": str(created)}


def loaded_modules(process):
    modules = (wintypes.HMODULE * 2048)()
    needed = wintypes.DWORD()
    handle = wintypes.HANDLE(int(process._handle))
    if not PSAPI.EnumProcessModulesEx(handle, modules, ctypes.sizeof(modules), ctypes.byref(needed), 3):
        raise ctypes.WinError(ctypes.get_last_error())
    if needed.value > ctypes.sizeof(modules):
        raise McpError("Loaded module inventory exceeded its bound")
    result = []
    for module in modules[:needed.value // ctypes.sizeof(wintypes.HMODULE)]:
        buffer = ctypes.create_unicode_buffer(32768)
        if not PSAPI.GetModuleFileNameExW(handle, module, buffer, len(buffer)):
            raise ctypes.WinError(ctypes.get_last_error())
        result.append(file_identity(buffer.value))
    return result


def listener_pid(port):
    library = ctypes.WinDLL("iphlpapi", use_last_error=True)
    size = wintypes.DWORD()
    library.GetExtendedTcpTable(None, ctypes.byref(size), False, socket.AF_INET, TCP_OWNER_PID_LISTENERS, 0)
    if size.value > 8 * 1024 * 1024:
        raise McpError("TCP inventory exceeded its bound")
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


def compiler_environment(architecture, toolset=None):
    if toolset is not None and not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", toolset):
        raise McpError("MSVC toolset must be an exact numeric version")
    program_files = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"))
    locator = program_files / "Microsoft Visual Studio" / "Installer" / "vswhere.exe"
    if not locator.is_file():
        raise McpError("Visual Studio discovery tool is unavailable")
    result = subprocess.run([str(locator), "-latest", "-products", "*", "-requires",
                             "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property", "installationPath"],
                            capture_output=True, text=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
    development_command = Path(result.stdout.strip()) / "Common7" / "Tools" / "VsDevCmd.bat"
    if not development_command.is_file() or any(value in str(development_command) for value in '&|<>^%!\r\n'):
        raise McpError("Visual Studio development environment path is invalid")
    target = "x86" if architecture == "x32" else "x64"
    selection = f" -vcvars_ver={toolset}" if toolset else ""
    command = f'call "{development_command}" -arch={target} -host_arch=x64{selection} >nul && set'
    result = subprocess.run(f'cmd.exe /d /s /c "{command}"', capture_output=True, text=True,
                            creationflags=subprocess.CREATE_NO_WINDOW)
    if result.returncode:
        raise McpError(f"Visual Studio environment failed: {result.stdout} {result.stderr}")
    environment = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line and not line.startswith("="))
    selected = next((value.rstrip("\\/") for key, value in environment.items() if key.lower() == "vctoolsversion"), None)
    if toolset and selected != toolset:
        raise McpError("Visual Studio selected a different toolset than requested")
    return environment


def build_targets(environment):
    compiler_variables = compiler_environment(environment.architecture)
    search_path = next(value for key, value in compiler_variables.items() if key.lower() == "path")
    compiler = shutil.which("cl.exe", path=search_path)
    if not compiler:
        raise McpError("Visual Studio compiler is unavailable")
    logs = []
    for source in sorted(TARGET_SOURCES.glob("*.c")):
        optimization = "/Od" if source.stem in ("bpmain", "patch_canary") else "/O1"
        command = [compiler, "/nologo", optimization, "/W3", str(source), f"/Fe:{source.stem}.exe",
                   "/link", "/MANIFEST:EMBED", "/MANIFESTUAC:level='asInvoker' uiAccess='false'"]
        result = subprocess.run(command, cwd=environment.targets, env=compiler_variables,
                                capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
        logs.append({"source": file_identity(source), "command": command,
                     "exitCode": result.returncode, "stdout": result.stdout, "stderr": result.stderr})
        if result.returncode:
            write_json(environment.root / "fixture-build.json", logs)
            raise McpError(f"Fixture build failed: {source.name}: {result.stdout} {result.stderr}")
    write_json(environment.root / "fixture-build.json", logs)


def resolve_build_toolchain(build, architecture, cmake=None, msvc_toolset=None, unity_build=False):
    environment = compiler_environment(architecture, msvc_toolset)
    executable_path = next(value for key, value in environment.items() if key.lower() == "path")
    cmake_path = shutil.which(str(cmake) if cmake else "cmake", path=executable_path)
    compiler_path = shutil.which("cl.exe", path=executable_path)
    if not cmake_path or not compiler_path:
        raise McpError("Native builds require resolved CMake and MSVC executables")
    cmake_path = Path(cmake_path).resolve()
    compiler_path = Path(compiler_path).resolve()
    version = subprocess.run([str(cmake_path), "--version"], env=environment, capture_output=True, text=True, timeout=10,
                             creationflags=subprocess.CREATE_NO_WINDOW)
    toolchain = {"cmake": file_identity(cmake_path), "compiler": file_identity(compiler_path),
                 "cmakeVersion": version.stdout.strip(), "versionExitCode": version.returncode, "versionStderr": version.stderr,
                 "requestedMsvcToolset": msvc_toolset, "requestedUnityBuild": unity_build,
                 "msvcToolset": next((value.rstrip("\\/") for key, value in environment.items() if key.lower() == "vctoolsversion"), None)}
    write_json(Path(build) / "toolchain.json", toolchain)
    if version.returncode or not version.stdout.startswith("cmake version "):
        raise McpError("Selected CMake executable did not report a successful version")
    return environment, cmake_path, compiler_path, toolchain


def build_debugger(output, architecture, cmake=None, msvc_toolset=None):
    source = ROOT / "x64dbg"
    build = Path(output) / f"build-{architecture}"
    build.mkdir()
    qt_build = "build64" if architecture == "x64" else "build32"
    qt = source / qt_build / "_deps" / "qt5-src" / "lib" / "cmake" / "Qt5"
    environment, cmake_path, compiler_path, toolchain = resolve_build_toolchain(build, architecture, cmake, msvc_toolset, True)
    configure = [str(cmake_path), "-S", str(source), "-B", str(build), "-G", "Ninja",
                 "-DCMAKE_BUILD_TYPE=Release", "-DCMAKE_UNITY_BUILD=ON", "-DCMAKE_UNITY_BUILD_BATCH_SIZE=6",
                 "-DCMKR_SKIP_GENERATION=ON", "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
                 f"-DCMAKE_C_COMPILER={compiler_path.as_posix()}", f"-DCMAKE_CXX_COMPILER={compiler_path.as_posix()}"]
    if qt.is_dir():
        configure.append(f"-DQt5_DIR={qt}")
    commands = [configure, [str(cmake_path), "--build", str(build), "--target", "exe", "headless", "x64dbg_tests",
                            "mcp_broker", "mcp_connect", "mcp_worker", "mcp_contract_fixture", "mcp_launch_reference", "--parallel", "6"]]
    inputs = subprocess.check_output(["git", "ls-files", "-z", "x64dbg"], cwd=ROOT).decode("utf-8").split("\0")
    source_inputs = [file_identity(ROOT / path) for path in inputs if path and (ROOT / path).is_file()]
    source_head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    source_status = subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True)
    results = []
    with (build / "build.log").open("w", encoding="utf-8") as log:
        for command in commands:
            print(f"Building native {architecture}: {command[1]}", flush=True)
            process = subprocess.run(command, env=environment, stdout=log, stderr=subprocess.STDOUT, creationflags=subprocess.CREATE_NO_WINDOW)
            log.flush()
            results.append({"command": command, "exitCode": process.returncode})
            write_json(build / "commands.json", results)
            if process.returncode:
                raise McpError(f"Native build failed: {(build / 'build.log').read_text(encoding='utf-8')[-8000:]}")
    artifacts = source / "bin" / architecture
    for entry in source_inputs:
        if file_identity(entry["path"]) != entry:
            raise McpError("Native build source changed during compilation")
    for key in ("cmake", "compiler"):
        if file_identity(toolchain[key]["path"]) != toolchain[key]:
            raise McpError("Native build tool changed during compilation")
    manifest = {"architecture": architecture, "sourceHead": source_head, "sourceStatus": source_status, "sourceInputs": source_inputs,
                "buildInputs": file_identity(build / "CMakeCache.txt"), "commands": results, "toolchain": toolchain,
                "compileCommands": json.loads((build / "compile_commands.json").read_text(encoding="utf-8")),
                "privateArtifacts": [file_identity(path) for path in sorted(build.glob("*.exe"))],
                "artifacts": [file_identity(path) for path in sorted(artifacts.rglob("*"))
                              if path.is_file() and path.suffix.lower() in (".exe", ".dll", ".dp64", ".dp32", ".lib")]}
    write_json(build / "build-manifest.json", manifest)
    print(f"[VERIFIED] Native {architecture} release build: {build}", flush=True)
    return manifest


class SuiteEnvironment:
    def __init__(self, root, architecture, deployment):
        self.root = Path(root).resolve()
        self.architecture = architecture
        self.deployment = Path(deployment).resolve()
        self.targets = self.root / "targets"
        self.targets.mkdir(parents=True)
        self.stages = {}
        self.processes = []
        self.requests = []
        self.legacy_catalog = None
        self.before = tree_identity(self.deployment)
        self.source = {"head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                       "status": subprocess.check_output(["git", "status", "--porcelain=v1"], cwd=ROOT, text=True),
                       "patchSha256": hashlib.sha256(subprocess.check_output(["git", "diff", "HEAD", "--binary"], cwd=ROOT)).hexdigest(),
                       "testInputs": [file_identity(path) for path in sorted((ROOT / "tests").glob("*.py"))]}

    def stage(self, plugin_profile):
        if plugin_profile in self.stages:
            return self.stages[plugin_profile]
        stage = self.root / f"deploy-{plugin_profile}"
        stage.mkdir()
        for source in self.deployment.iterdir():
            if source.is_file() and source.suffix.lower() in (".dll", ".exe"):
                shutil.copy2(source, stage / source.name)
        for directory in ("platforms", "iconengines", "imageformats", "styles"):
            source = self.deployment / directory
            if source.is_dir():
                shutil.copytree(source, stage / directory)
        plugins = stage / "plugins"
        plugins.mkdir()
        suffix = ".dp64" if self.architecture == "x64" else ".dp32"
        baseline_plugin = self.deployment / "plugins" / f"x64dbg-MCP-Server{suffix}"
        if plugin_profile != "native" and not baseline_plugin.is_file():
            raise McpError(f"Legacy MCP baseline plugin is unavailable for {self.architecture}")
        if plugin_profile != "native":
            shutil.copy2(baseline_plugin, plugins / baseline_plugin.name)
        if plugin_profile in ("shipped", "native") and (self.deployment / "plugins").is_dir():
            for source in (self.deployment / "plugins").iterdir():
                if plugin_profile == "native" and source.name.lower() == baseline_plugin.name.lower():
                    continue
                if source.is_file() and source.suffix.lower() in (suffix, ".dll", ".ini"):
                    shutil.copy2(source, plugins / source.name)
        self.stages[plugin_profile] = stage
        return stage

    def fixture(self, name):
        return str(self.targets / f"{name}.exe")

    def marker(self, name):
        return str(self.targets / f"{name}_result.txt")

    def wipe_markers(self):
        for marker in self.targets.glob("*_result.txt"):
            marker.unlink()

    def retain(self, results, phase="baseline"):
        after = tree_identity(self.deployment)
        unchanged = after == self.before
        write_json(self.root / "requests.json", self.requests)
        write_json(self.root / "legacy-catalog.json", self.legacy_catalog)
        write_json(self.root / "evidence.json", {"schemaVersion": 1, "phase": phase,
                   "source": self.source, "architecture": self.architecture, "processes": self.processes,
                   "environment": {"windowsVersion": list(sys.getwindowsversion()), "pythonVersion": sys.version},
                   "sourceDeployment": self.before, "fixtures": tree_identity(self.targets),
                   "results": results, "personalDeploymentUnchanged": unchanged})
        if not unchanged:
            raise McpError("The personal deployment changed during verification")


def read_kv(path):
    with open(path, encoding="utf-8") as stream:
        return dict(line.split("=", 1) for line in stream.read().strip().splitlines())


class WinInspect:
    def __init__(self, environment, plugin_profile="shipped", hide_debugger=True, timeout=45):
        self.environment = environment
        self.plugin_profile = plugin_profile
        self.hide_debugger = hide_debugger
        self.timeout = timeout
        self.proc = None
        self.job = None
        self.sid = None
        self.rid = 1
        self.auth = secrets.token_hex(32)
        self.port = None
        self.record = None

    def fixture(self, name):
        return self.environment.fixture(name)

    def marker(self, name):
        return self.environment.marker(name)

    def wipe_markers(self):
        self.environment.wipe_markers()

    def start(self, initial_command=None):
        if self.plugin_profile == "native" and not initial_command:
            raise McpError("Native inventory startup requires its explicit observation command")
        stage = self.environment.stage(self.plugin_profile)
        profile = self.environment.root / f"profile-{len(self.environment.processes)}"
        profile.mkdir()
        (profile / "wininspect.ini").write_text(
            f"[Engine]\nHideDebugger={int(self.hide_debugger)}\nNoConsoleWindow=1\n[Misc]\nLoadLastSession=0\n", encoding="utf-8")
        if self.plugin_profile != "native":
            with socket.socket() as probe:
                probe.bind((HOST, 0))
                self.port = probe.getsockname()[1]
            configuration = {"IpAddress": HOST, "Port": self.port, "AutoStart": True, "AuthToken": self.auth}
            write_json(stage / "mcp_config.json", configuration)
        self.job = OwnedJob()
        process_environment = os.environ.copy()
        for variable in ("QTDIR", "QT_PLUGIN_PATH", "QT_QPA_PLATFORM_PLUGIN_PATH", "QML_IMPORT_PATH", "QML2_IMPORT_PATH"):
            process_environment.pop(variable, None)
        command = [str(stage / "wininspect.exe"), "-userdir", str(profile)]
        if initial_command:
            command.extend(("-c", initial_command))
        self.proc = subprocess.Popen(command,
                                     cwd=self.environment.targets, env=process_environment)
        try:
            self.job.assign(self.proc)
            self.record = {**process_identity(self.proc), "deployment": str(stage), "profile": str(profile),
                           "port": self.port, "plugins": self.plugin_profile, "hideDebugger": self.hide_debugger}
            self.environment.processes.append(self.record)
            if self.plugin_profile == "native":
                self.record["startupCommand"] = initial_command
                return {"mode": "native-command-startup"}
            deadline = time.monotonic() + self.timeout
            while time.monotonic() < deadline:
                if self.proc.poll() is not None:
                    raise McpError(f"Debugger exited during startup with code {self.proc.returncode}")
                try:
                    with socket.create_connection((HOST, self.port), 0.3):
                        break
                except OSError:
                    time.sleep(0.15)
            else:
                raise McpError("Owned MCP endpoint did not become ready")
            if listener_pid(self.port) != self.proc.pid:
                raise McpError("MCP listener does not belong to the owned debugger process")
            response = self.raw({"jsonrpc": "2.0", "id": 0, "method": "initialize",
                                 "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                                            "clientInfo": {"name": "wininspect-suite", "version": "2.0"}}})
            server = response.get("result", {}).get("serverInfo", {})
            if not server:
                raise McpError("Legacy initialization failed")
            self.raw({"jsonrpc": "2.0", "method": "notifications/initialized"})
            self.record["server"] = server
            self.record["loadedModules"] = loaded_modules(self.proc)
            return server
        except BaseException:
            self.stop()
            raise

    def stop(self):
        if self.proc is not None:
            if self.proc.poll() is None:
                callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

                def close_owned_window(window, context):
                    process_id = wintypes.DWORD()
                    USER.GetWindowThreadProcessId(window, ctypes.byref(process_id))
                    if process_id.value == self.proc.pid:
                        USER.PostMessageW(window, WINDOW_CLOSE, 0, 0)
                    return True

                callback = callback_type(close_owned_window)
                USER.EnumWindows(callback, 0)
                try:
                    self.proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
                    self.proc.wait(timeout=5)
            if self.record is not None:
                self.record["exitCode"] = self.proc.returncode
            self.proc = None
        if self.job is not None:
            self.job.close()
            self.job = None
        self.sid = None

    def raw(self, payload):
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                   "Authorization": "Bearer " + self.auth}
        if self.sid:
            headers["Mcp-Session-Id"] = self.sid
        request = urllib.request.Request(f"http://{HOST}:{self.port}/", data=json.dumps(payload).encode(), headers=headers)
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            session_id = response.headers.get("Mcp-Session-Id")
            if session_id:
                self.sid = session_id
            body = response.read().decode()
            content_type = response.headers.get("Content-Type", "")
        if content_type.startswith("text/event-stream"):
            frames = [line[5:].strip() for line in body.splitlines() if line.startswith("data:")]
            result = json.loads("\n".join(frames)) if frames else None
        else:
            result = json.loads(body) if body.strip() else None
        captured = json.loads(json.dumps({"request": payload, "response": result}).replace(self.auth, "[redacted]"))
        self.environment.requests.append(captured)
        return result

    def call(self, name, args=None):
        payload = {"jsonrpc": "2.0", "id": self.rid, "method": "tools/call",
                   "params": {"name": name, "arguments": args if args is not None else {}}}
        self.rid += 1
        response = self.raw(payload)
        if response is None:
            raise McpError(f"Tool {name} returned no response")
        if response.get("error"):
            raise McpError(f"Tool {name} RPC error: {json.dumps(response['error'])[:300]}")
        result = response.get("result", {})
        text = "\n".join(content.get("text", "") for content in result.get("content", []))
        if result.get("isError"):
            raise McpError(f"Tool {name} failed: {text[:300]}")
        return text

    def list_tools(self):
        tools = []
        cursor = None
        seen_cursors = set()
        while True:
            payload = {"jsonrpc": "2.0", "id": self.rid, "method": "tools/list"}
            if cursor:
                payload["params"] = {"cursor": cursor}
            self.rid += 1
            response = self.raw(payload)
            if not response or "result" not in response:
                raise McpError("Legacy tools/list failed")
            tools.extend(response["result"]["tools"])
            cursor = response["result"].get("nextCursor")
            if not cursor:
                break
            if cursor in seen_cursors:
                raise McpError("Legacy catalog pagination repeated a cursor")
            seen_cursors.add(cursor)
        names = [tool["name"] for tool in tools]
        if len(names) != len(set(names)):
            raise McpError("Legacy catalog contains duplicate names")
        self.environment.legacy_catalog = tools
        return names

    def state(self):
        return {key.strip(): value.strip() for line in self.call("GetDebugState").splitlines() if ":" in line
                for key, value in [line.split(":", 1)]}

    def eval_int(self, expression):
        first = self.call("EvalExpression", {"expression": expression}).splitlines()[0]
        return int(first.split()[0], 16)

    def registers(self):
        registers = {}
        for line in self.call("GetAllRegisters").splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                try:
                    registers[key.strip()] = int(value.strip(), 16)
                except ValueError:
                    pass
        return registers

    def read_bytes(self, address, size):
        address_text = address if isinstance(address, str) else f"0x{address:X}"
        text = self.call("ReadMemory", {"address": address_text, "size": size})
        result = []
        for line in text.splitlines():
            if ": " not in line:
                continue
            segment = re.split(r"\s{2,}", line.split(": ", 1)[1].strip())[0]
            if re.fullmatch(r"(?:[0-9A-Fa-f]{2} )*[0-9A-Fa-f]{2}", segment):
                result.extend(int(value, 16) for value in segment.split())
        return bytes(result[:size])

    def safe_stop(self):
        try:
            self.call("StopDebug")
        except McpError as error:
            if "active debug session" not in str(error):
                raise

    def load(self, path, **arguments):
        return self.call("LoadBinary", {"filePath": str(path), **arguments})

    def resume_until(self, marker=None, bp_addr=None, stop_at_bp=False, iterations=150, poll=0.4):
        info = {"bp_hits": 0, "terminated": False, "last": {}}
        deadline = time.monotonic() + min(iterations * poll, self.timeout)
        while time.monotonic() < deadline:
            state = self.state()
            info["last"] = state
            if state.get("isDebugging") == "false" or state.get("status") == "NO_TARGET":
                info["terminated"] = True
                break
            if marker and Path(marker).exists():
                break
            if state.get("isRunning") == "true":
                time.sleep(poll)
                continue
            address = state.get("currentAddress")
            if bp_addr and address and int(address, 16) == bp_addr:
                info["bp_hits"] += 1
                if stop_at_bp:
                    break
            self.call("run", {})
            time.sleep(poll)
        return info
