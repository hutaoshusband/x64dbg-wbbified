import json
import os
import re
import shutil
import socket
import subprocess
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WI64 = os.path.join(ROOT, "WinTools", "x64")
EXE = os.path.join(WI64, "wininspect.exe")
PLUGINS = os.path.join(WI64, "plugins")
INI = os.path.join(WI64, "wininspect.ini")
TARGETS = os.path.join(ROOT, "tests", "targets")
TMP = os.path.join(ROOT, "tests", "tmp")
BUILD_BAT = os.path.join(TARGETS, "build.bat")

EXITMARK_EXE = os.path.join(TARGETS, "exitmark.exe")
BPMAIN_EXE = os.path.join(TARGETS, "bpmain.exe")
PROBE_EXE = os.path.join(TARGETS, "probe.exe")
EXITMARK_MARKER = os.path.join(TARGETS, "exitmark_result.txt")
BPMAIN_MARKER = os.path.join(TARGETS, "bpmain_result.txt")
PROBE_MARKER = os.path.join(TARGETS, "probe_result.txt")

HOST = "127.0.0.1"
PORT = 9094
URL = "http://%s:%d/" % (HOST, PORT)

SCYLLA_FILES = ["ScyllaHideX64DBGPlugin.dp64", "HookLibraryx64.dll", "scylla_hide.ini", "scylla_hide.log"]
SCYLLA_STASH = os.path.join(TMP, "scylla_stash")

MARKERS = [EXITMARK_MARKER, BPMAIN_MARKER, PROBE_MARKER]


class McpError(Exception):
    pass


def token():
    with open(os.path.join(WI64, "mcp_config.json")) as f:
        return json.load(f)["AuthToken"]


def wait_port(up=True, timeout=60.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            socket.create_connection((HOST, PORT), 1).close()
            reachable = True
        except OSError:
            reachable = False
        if reachable == up:
            return True
        time.sleep(0.3)
    return False


def set_ini_flag(value):
    lines = []
    if os.path.exists(INI):
        with open(INI, encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    out = []
    section = None
    found = False
    for ln in lines:
        s = ln.strip()
        if s.startswith("[") and s.endswith("]"):
            if section == "Engine" and not found:
                out.append("HideDebugger=%d" % value)
                found = True
            section = s[1:-1]
        elif section == "Engine" and s.lower().startswith("hidedebugger="):
            out.append("HideDebugger=%d" % value)
            found = True
            continue
        out.append(ln)
    if section == "Engine" and not found:
        out.append("HideDebugger=%d" % value)
        found = True
    if not found:
        out += ["[Engine]", "HideDebugger=%d" % value]
    with open(INI, "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")


def stash_scylla():
    os.makedirs(SCYLLA_STASH, exist_ok=True)
    for name in SCYLLA_FILES:
        src = os.path.join(PLUGINS, name)
        if os.path.exists(src):
            shutil.move(src, os.path.join(SCYLLA_STASH, name))


def restore_scylla():
    if not os.path.isdir(SCYLLA_STASH):
        return
    for name in os.listdir(SCYLLA_STASH):
        shutil.move(os.path.join(SCYLLA_STASH, name), os.path.join(PLUGINS, name))


def read_kv(path):
    with open(path) as f:
        return dict(line.split("=", 1) for line in f.read().strip().splitlines())


def wipe_markers():
    for m in MARKERS:
        if os.path.exists(m):
            os.remove(m)


class WinInspect:
    def __init__(self):
        self.proc = None
        self.sid = None
        self.rid = 0
        self.auth = token()

    def start(self):
        self.proc = subprocess.Popen([EXE])
        if not wait_port(up=True, timeout=60):
            raise McpError("MCP port %d never came up" % PORT)
        time.sleep(1.5)
        r = self.raw({"jsonrpc": "2.0", "id": 0, "method": "initialize",
                      "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                                 "clientInfo": {"name": "wininspect-suite", "version": "1.0"}}})
        server = r.get("result", {}).get("serverInfo", {})
        if not server:
            raise McpError("initialize failed: %s" % json.dumps(r)[:300])
        self.raw({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return server

    def stop(self):
        if self.proc:
            self.proc.kill()
            self.proc.wait()
            self.proc = None
        wait_port(up=False, timeout=15)
        self.sid = None

    def raw(self, payload):
        headers = {"Content-Type": "application/json",
                   "Accept": "application/json, text/event-stream",
                   "Authorization": "Bearer " + self.auth}
        if self.sid:
            headers["Mcp-Session-Id"] = self.sid
        req = urllib.request.Request(URL, data=json.dumps(payload).encode(), headers=headers)
        with urllib.request.urlopen(req, timeout=90) as r:
            sid = r.headers.get("Mcp-Session-Id")
            if sid:
                self.sid = sid
            body = r.read().decode()
        if r.headers.get("Content-Type", "").startswith("text/event-stream"):
            for line in body.splitlines():
                if line.startswith("data:"):
                    return json.loads(line[5:].strip())
            return None
        return json.loads(body) if body.strip() else None

    def call(self, name, args=None):
        payload = {"jsonrpc": "2.0", "id": self.rid, "method": "tools/call",
                   "params": {"name": name, "arguments": args if args is not None else {}}}
        self.rid += 1
        r = self.raw(payload)
        if r is None:
            raise McpError("tool %s returned no response" % name)
        if r.get("error"):
            raise McpError("tool %s rpc error: %s" % (name, json.dumps(r["error"])[:300]))
        result = r.get("result", {})
        text = "\n".join(c.get("text", "") for c in result.get("content", []))
        if result.get("isError"):
            raise McpError("tool %s failed: %s" % (name, text[:300]))
        return text

    def list_tools(self):
        r = self.raw({"jsonrpc": "2.0", "id": self.rid, "method": "tools/list"})
        self.rid += 1
        return [t["name"] for t in r["result"]["tools"]]

    def state(self):
        d = {}
        for ln in self.call("GetDebugState").splitlines():
            if ":" in ln:
                k, v = ln.split(":", 1)
                d[k.strip()] = v.strip()
        return d

    def eval_int(self, expression):
        first = self.call("EvalExpression", {"expression": expression}).splitlines()[0]
        return int(first.split()[0], 16)

    def registers(self):
        d = {}
        for ln in self.call("GetAllRegisters").splitlines():
            if ":" in ln:
                k, v = ln.split(":", 1)
                try:
                    d[k.strip()] = int(v.strip(), 16)
                except ValueError:
                    pass
        return d

    def read_bytes(self, address, size):
        addr = address if isinstance(address, str) else "0x%X" % address
        text = self.call("ReadMemory", {"address": addr, "size": size})
        out = []
        for ln in text.splitlines():
            if ": " not in ln:
                continue
            after = ln.split(": ", 1)[1].strip()
            seg = re.split(r"\s{2,}", after)
            if seg and re.fullmatch(r"(?:[0-9A-Fa-f]{2} )*[0-9A-Fa-f]{2}", seg[0]):
                out += [int(b, 16) for b in seg[0].split()]
        return bytes(out[:size])

    def safe_stop(self):
        try:
            self.call("StopDebug")
        except McpError as e:
            if "active debug session" not in str(e):
                raise

    def load(self, path):
        return self.call("LoadBinary", {"filePath": path})

    def resume_until(self, marker=None, bp_addr=None, stop_at_bp=False, iterations=150, poll=0.4):
        info = {"bp_hits": 0, "terminated": False, "last": {}}
        for _ in range(iterations):
            st = self.state()
            info["last"] = st
            if st.get("isDebugging") == "false" or st.get("status") == "NO_TARGET":
                info["terminated"] = True
                break
            if bp_addr and st.get("currentAddress"):
                try:
                    if int(st["currentAddress"], 16) == bp_addr:
                        info["bp_hits"] += 1
                        if stop_at_bp:
                            break
                except ValueError:
                    pass
            if marker and os.path.exists(marker):
                time.sleep(0.5)
                break
            if st.get("isRunning") == "true":
                time.sleep(poll)
                continue
            self.call("run", {})
            time.sleep(poll)
        return info
