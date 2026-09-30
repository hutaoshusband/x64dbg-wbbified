import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import cases
from wi_driver import (BUILD_BAT, PROBE_EXE, PROBE_MARKER, TARGETS, WinInspect,
                       restore_scylla, set_ini_flag, stash_scylla, wipe_markers, read_kv)

TARGET_EXES = ["exitmark.exe", "bpmain.exe", "probe.exe"]


def ensure_targets():
    if all(os.path.exists(os.path.join(TARGETS, n)) for n in TARGET_EXES):
        return
    r = subprocess.run(["cmd", "/c", BUILD_BAT], cwd=TARGETS, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout)
        print(r.stderr)
        raise SystemExit("target build failed")


def kill_stale():
    subprocess.run(["taskkill", "/F", "/IM", "wininspect.exe"], capture_output=True)
    time.sleep(1)


def run_functional(results):
    wi = WinInspect()
    try:
        server = wi.start()
        print("wininspect up, MCP server: %s %s" % (server.get("name"), server.get("version")))
        for fn in cases.CASES:
            t0 = time.time()
            try:
                fn(wi)
                results.append((fn.__name__, None))
                print("[PASS] %s (%.1fs)" % (fn.__name__, time.time() - t0))
            except Exception as e:
                results.append((fn.__name__, str(e)))
                print("[FAIL] %s (%.1fs): %s" % (fn.__name__, time.time() - t0, e))
            wi.safe_stop()
    finally:
        wi.stop()


def run_hide_case(label, ini_value, expect_hidden, results):
    wi = WinInspect()
    t0 = time.time()
    try:
        wi.start()
        if os.path.exists(PROBE_MARKER):
            os.remove(PROBE_MARKER)
        r = wi.load(PROBE_EXE)
        assert "SUCCESS" in r, r[:200]
        info = wi.resume_until(marker=PROBE_MARKER)
        assert os.path.exists(PROBE_MARKER), "probe marker missing, last state: %s" % info["last"]
        kv = read_kv(PROBE_MARKER)
        bd = int(kv["BeingDebugged"])
        ngf = int(kv["NtGlobalFlag"], 16)
        if expect_hidden:
            assert bd == 0, "BeingDebugged=%d, expected 0 (%s)" % (bd, kv)
            assert ngf & 0x70 == 0, "NtGlobalFlag=0x%x, debug bits set (%s)" % (ngf, kv)
        else:
            assert bd == 1, "BeingDebugged=%d, expected 1 (%s)" % (bd, kv)
        results.append((label, None))
        print("[PASS] %s (%.1fs): %s" % (label, time.time() - t0,
                                         " ".join("%s=%s" % kv2 for kv2 in sorted(kv.items()))))
    except Exception as e:
        results.append((label, str(e)))
        print("[FAIL] %s (%.1fs): %s" % (label, time.time() - t0, e))
    finally:
        wi.stop()


def main():
    ensure_targets()
    kill_stale()
    os.makedirs(os.path.join(os.path.dirname(TARGETS), "tmp"), exist_ok=True)
    wipe_markers()
    set_ini_flag(1)

    results = []
    run_functional(results)

    stash_scylla()
    try:
        set_ini_flag(1)
        run_hide_case("test_peb_autohide_on", 1, True, results)
        set_ini_flag(0)
        run_hide_case("test_peb_autohide_control", 0, False, results)
    finally:
        set_ini_flag(1)
        restore_scylla()

    failed = [(n, e) for n, e in results if e]
    print("")
    print("summary: %d/%d passed" % (len(results) - len(failed), len(results)))
    for n, e in failed:
        print("  FAILED %s: %s" % (n, e))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
