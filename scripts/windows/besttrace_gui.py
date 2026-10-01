#!/usr/bin/env python3
"""Run the real Windows BestTrace GUI and retain evidence of its ICMP trace.

Requires Windows, Python 3, pywinauto and Pillow. --exe is the installed
17monipdb.exe, not IPIP's besttrace.exe installer. No BestTrace command-line
trace options are assumed. Control IDs below come from the official Windows
3.8.0 dialog resources; captions provide a fallback for nearby releases.

Exit codes: 0 pass, 1 fail, 2 inconclusive, 3 blocked. A GUI launch alone cannot
pass. Public networks can hide every intermediate hop, making a trace
inconclusive even when the application completes successfully.
"""

from __future__ import annotations

import argparse
import ctypes
import datetime as dt
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
import time
import traceback


CONTROL_IDS = {
    "main_target": 1000,
    "open_trace": 1006,
    "trace_target": 1014,
    "tcp": 1059,
    "run": 1064,
    "results": 1013,
    "vantage": 1057,
}


class Blocked(RuntimeError):
    """The environment or GUI cannot provide the requested evidence."""


def safe(call, default=None):
    try:
        return call()
    except Exception:
        return default


def normalize(text):
    return re.sub(r"\s+", "", text.replace("&", "")).casefold()


def addresses(text):
    """Extract addresses from table cells, excluding invalid numeric strings."""
    candidates = re.findall(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", text)
    candidates += re.findall(r"(?<![\w:])[0-9a-fA-F]*(?::[0-9a-fA-F.]*){2,}(?:%[\w.-]+)?", text)
    found = []
    for candidate in candidates:
        try:
            address = str(ipaddress.ip_address(candidate))
            if address not in found:
                found.append(address)
        except ValueError:
            pass
    return found


def classify_rows(rows, target):
    hops = []
    observed = []
    for row in rows:
        columns = row["columns"]
        hop_match = re.fullmatch(r"\s*(\d+)\s*", columns[0]) if columns else None
        hop = int(hop_match.group(1)) if hop_match else row["index"] + 1
        for address in addresses(row["text"]):
            if address not in observed:
                observed.append(address)
            hops.append({"hop": hop, "address": address, "row_index": row["index"],
                         "hop_inferred": hop_match is None})
    target_hops = [item["hop"] for item in hops if item["address"] == target]
    target_hop = min(target_hops) if target_hops else None
    intermediate = [item for item in hops if item["address"] != target and
                    (target_hop is None or item["hop"] < target_hop)]
    return hops, observed, intermediate


def describe(control):
    rect = safe(control.rectangle)
    return {
        "handle": safe(lambda: int(control.handle)),
        "control_id": safe(control.control_id),
        "class_name": safe(control.class_name, ""),
        "text": safe(control.window_text, ""),
        "visible": safe(control.is_visible),
        "enabled": safe(control.is_enabled),
        "rectangle": [rect.left, rect.top, rect.right, rect.bottom] if rect else None,
    }


def by_id(window, control_id, class_name=None):
    for control in window.descendants():
        if safe(control.control_id) == control_id and (
            class_name is None or safe(control.class_name) == class_name
        ):
            return control
    return None


def by_caption(window, captions, class_name="Button"):
    wanted = {normalize(caption) for caption in captions}
    for control in window.descendants():
        if safe(control.class_name) == class_name and normalize(
            safe(control.window_text, "")
        ) in wanted:
            return control
    return None


def activate_button(control):
    """Click the actual center of a button, with a native-message fallback.

    BestTrace ignored ButtonWrapper.click() at its default (0, 0) corner on
    the Windows runner. click_input() targets the center and delivers actual
    input. A posted BM_CLICK supports environments where input is unavailable
    and avoids synchronously blocking when the button opens a modal dialog.
    """
    safe(lambda: control.top_level_parent().set_focus())
    try:
        control.click_input()
        return "click_input"
    except Exception:
        control.post_message(0x00F5, 0, 0)  # BM_CLICK
        return "posted_BM_CLICK"


def read_rows(window):
    table = by_id(window, CONTROL_IDS["results"], "SysListView32")
    if table is None:
        tables = [c for c in window.descendants() if safe(c.class_name) == "SysListView32"
                  and safe(c.is_visible, False)]
        if len(tables) != 1:
            raise Blocked("Cannot identify the BestTrace result table unambiguously")
        table = tables[0]
    # SysListView32 uses cross-process memory; the application and Python should
    # both be x64. Do not substitute a window caption for actual result rows.
    count = min(table.item_count(), 256)
    column_count = min(table.column_count(), 32)
    if column_count < 1:
        raise Blocked("BestTrace result table exposes no readable columns")
    rows = []
    for index in range(count):
        columns = [table.get_item(index, column).text() for column in range(column_count)]
        rows.append({"index": index, "columns": columns, "text": "\t".join(columns)})
    return rows


def session_information():
    sid = ctypes.c_ulong()
    ok = ctypes.windll.kernel32.ProcessIdToSessionId(os.getpid(), ctypes.byref(sid))
    return {"session_id": int(sid.value) if ok else None,
            "is_admin": bool(ctypes.windll.shell32.IsUserAnAdmin())}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", required=True, type=Path)
    parser.add_argument("--target", required=True,
                        help="A real literal IP address; use the same IP for every scenario")
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--timeout", default=90, type=float,
                        help="Seconds allowed for the actual trace after Start")
    args = parser.parse_args()
    out = args.output_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    result = {"status": "blocked", "reason": "Not run", "target": args.target,
              "exe": str(args.exe.resolve()), "trace_started": False,
              "trace_completed": False, "busy_observed": False,
              "target_observed": False, "rows": [], "hops": [],
              "observed_addresses": [], "intermediate_hops": [],
              "screenshot_paths": [], "screenshot_captured": False,
              "control_tree_paths": [], "errors": [], "pid": None,
              "session_id": None, "started_at": dt.datetime.now(dt.timezone.utc).isoformat()}
    app = None
    trace_window = None
    desktop = None

    def windows():
        return desktop.windows(process=result["pid"], visible_only=False)

    def evidence(label, primary=None):
        """Always retain readable trees; a screenshot is independently checked."""
        trees = []
        for window in safe(windows, []):
            controls = safe(window.descendants, [])[:1500]
            trees.append({"window": describe(window), "controls": [describe(c) for c in controls]})
        tree_path = out / f"{label}-controls.json"
        tree_path.write_text(json.dumps(trees, ensure_ascii=False, indent=2), encoding="utf-8")
        result["control_tree_paths"].append(str(tree_path))
        (out / f"{label}-controls.txt").write_text(
            "\n\n".join(json.dumps(tree, ensure_ascii=False, indent=2) for tree in trees),
            encoding="utf-8")
        screenshot_ok = False
        if primary is not None:
            try:
                # Focus is best effort. Control automation above uses messages,
                # rather than assuming that keyboard/mouse input is possible.
                safe(primary.restore)
                safe(primary.set_focus)
                shot = primary.capture_as_image()
                if shot is None:
                    raise RuntimeError("capture_as_image returned no image")
                path = out / f"{label}.png"
                shot.save(path)
                result["screenshot_paths"].append(str(path))
                extrema = shot.convert("RGB").getextrema()
                screenshot_ok = min(shot.size) >= 100 and any(lo != hi for lo, hi in extrema)
                if not screenshot_ok:
                    result["errors"].append(f"{label}: screenshot blank or too small")
            except Exception as exc:
                result["errors"].append(f"{label}: screenshot capture: {exc}")
        return screenshot_ok

    try:
        try:
            target = str(ipaddress.ip_address(args.target))
        except ValueError as exc:
            raise ValueError("--target must be a literal IPv4 or IPv6 address") from exc
        result["target"] = target
        if args.timeout <= 0:
            raise ValueError("--timeout must be positive")
        if sys.platform != "win32":
            raise Blocked("This test requires actual Windows and the Windows BestTrace GUI")
        result.update(session_information())
        if not args.exe.is_file():
            raise Blocked(f"Installed application does not exist: {args.exe}")
        if args.exe.name.casefold() != "17monipdb.exe":
            raise Blocked("--exe must be installed 17monipdb.exe, not the BestTrace installer")
        try:
            from pywinauto import Application, Desktop
        except ImportError as exc:
            raise Blocked("Install Python packages pywinauto and Pillow first") from exc
        desktop = Desktop(backend="win32")
        app = Application(backend="win32").start(
            f'"{args.exe.resolve()}"', work_dir=str(args.exe.resolve().parent), timeout=20)
        result["pid"] = app.process

        def find_trace():
            for window in windows():
                if by_id(window, CONTROL_IDS["run"], "Button") is not None and \
                        by_id(window, CONTROL_IDS["trace_target"], "ComboBox") is not None:
                    return window
            return None

        startup_deadline = time.monotonic() + 20
        main_window = None
        launch_button = None
        launched_at = None
        while time.monotonic() < startup_deadline:
            trace_window = find_trace()
            if trace_window is not None:
                break
            for window in windows():
                launch = by_id(window, CONTROL_IDS["open_trace"], "Button") or by_caption(
                    window, ["Traceroute(&T)", "Traceroute", "路由跟踪(&T)", "路由跟踪"])
                if launch is not None:
                    main_window = window
                    evidence("startup", window)
                    main_edit = by_id(window, CONTROL_IDS["main_target"], "Edit")
                    if main_edit is not None:
                        main_edit.set_edit_text(target)
                    launch_button = launch
                    result["open_trace_action"] = activate_button(launch)
                    launched_at = time.monotonic()
                    break
            if main_window is not None:
                break
            time.sleep(0.25)
        while trace_window is None and time.monotonic() < startup_deadline:
            trace_window = find_trace()
            if trace_window is None and launched_at is not None and \
                    time.monotonic() - launched_at >= 3 and \
                    not result.get("open_trace_retry"):
                # The window may have appeared before the runner's desktop
                # accepted focus/input. Retry using the button's native event.
                launch_button.post_message(0x00F5, 0, 0)
                result["open_trace_retry"] = "posted_BM_CLICK"
            time.sleep(0.25)
        if trace_window is None:
            evidence("startup-blocked", main_window)
            raise Blocked("BestTrace trace dialog was unavailable; see process window/control dump")
        evidence("trace-ready", trace_window)

        vantage = by_id(trace_window, CONTROL_IDS["vantage"], "Button")
        vantage_text = safe(vantage.window_text, "") if vantage is not None else ""
        result["vantage_caption"] = vantage_text
        if normalize(vantage_text) not in {normalize(x) for x in
                ["本机网络", "Native network", "Local network"]}:
            raise Blocked(f"Cannot confirm BestTrace uses this machine's network: {vantage_text!r}")
        tcp = by_id(trace_window, CONTROL_IDS["tcp"], "Button")
        if tcp is None:
            tcp = next((c for c in trace_window.descendants()
                        if safe(c.class_name) == "Button" and
                        safe(c.window_text, "").strip().upper().startswith("TCP")), None)
        if tcp is None:
            raise Blocked("Cannot identify BestTrace TCP checkbox to verify ICMP mode")
        if tcp.get_check_state() != 0:
            # Deliver the click notification too: a bare BM_SETCHECK may leave
            # application state unchanged when a checkbox has an event handler.
            result["disable_tcp_action"] = activate_button(tcp)
        if tcp.get_check_state() != 0:
            raise Blocked("BestTrace TCP checkbox could not be disabled")
        result["probe_mode"] = "ICMP"

        combo = by_id(trace_window, CONTROL_IDS["trace_target"], "ComboBox")
        edits = [c for c in combo.descendants() if safe(c.class_name) == "Edit"]
        if len(edits) == 1:
            edits[0].set_edit_text(target)
        else:
            combo.set_edit_text(target)
        entered = safe(combo.window_text, "")
        if target not in entered:
            entered = safe(lambda: edits[0].window_text(), "") if edits else entered
        result["entered_target"] = entered
        if entered.strip() != target:
            raise Blocked(f"Cannot verify BestTrace target input: {entered!r}")

        run_button = by_id(trace_window, CONTROL_IDS["run"], "Button") or by_caption(
            trace_window, ["Start", "开始"])
        if run_button is None:
            raise Blocked("Cannot identify BestTrace Start button")
        initial_rows = read_rows(trace_window)
        evidence("configured", trace_window)
        result["start_trace_action"] = activate_button(run_button)
        result["trace_started"] = True
        deadline = time.monotonic() + args.timeout
        started = time.monotonic()
        last_rows = initial_rows
        last_change = started
        seen_new_rows = False
        table_errors = []
        while time.monotonic() < deadline:
            caption = normalize(safe(run_button.window_text, ""))
            enabled = safe(run_button.is_enabled, False)
            is_busy = caption in {normalize(x) for x in ["Stop", "停止", "Stoping", "Stopping", "停止中"]}
            result["busy_observed"] = result["busy_observed"] or is_busy
            try:
                rows = read_rows(trace_window)
                if rows != last_rows:
                    last_change = time.monotonic()
                    seen_new_rows = True
                    last_rows = rows
                result["rows"] = rows
            except Exception as exc:
                if len(table_errors) < 3:
                    table_errors.append(str(exc))
            idle = enabled and caption in {normalize("Start"), normalize("开始")}
            stable = time.monotonic() - last_change >= 3
            # Busy->idle is direct completion evidence. Extremely quick traces
            # may finish between polls; then require new stable result rows.
            if idle and ((result["busy_observed"] and stable) or
                         (seen_new_rows and result["rows"] and stable)):
                result["trace_completed"] = True
                result["completion_evidence"] = "busy_to_idle" if result["busy_observed"] else "new_rows_stable_start_idle"
                break
            time.sleep(0.25)
        result["elapsed_seconds"] = round(time.monotonic() - started, 3)
        result["errors"].extend(table_errors)
        hops, observed, intermediate = classify_rows(result["rows"], target)
        result.update(hops=hops, observed_addresses=observed, intermediate_hops=intermediate,
                      target_observed=target in observed)
        result["screenshot_captured"] = evidence("final", trace_window)
        (out / "rows.tsv").write_text("\n".join(row["text"] for row in result["rows"]), encoding="utf-8")
        if not result["screenshot_captured"]:
            raise Blocked("Actual BestTrace final window screenshot could not be captured")
        if table_errors and not result["rows"]:
            raise Blocked("BestTrace result table was not readable; see recorded errors")
        if not result["trace_completed"]:
            result.update(status="inconclusive", reason="BestTrace did not finish within the trace timeout")
        elif not result["target_observed"]:
            result.update(status="inconclusive", reason="BestTrace completed without a responding target")
        elif not intermediate:
            result.update(status="inconclusive", reason="BestTrace completed but showed no responding intermediate hop")
        else:
            result.update(status="pass", reason="Actual Windows BestTrace ICMP trace completed with target and intermediate hop(s)")
    except Blocked as exc:
        result.update(status="blocked", reason=str(exc))
    except Exception as exc:
        result.update(status="fail", reason=f"{type(exc).__name__}: {exc}")
        (out / "exception.txt").write_text(traceback.format_exc(), encoding="utf-8")
    finally:
        if desktop is not None and result["status"] in {"blocked", "fail"}:
            safe(lambda: evidence("failure", trace_window))
        if app is not None:
            # Only terminate the application launched for this test.
            safe(lambda: app.kill(soft=False))
        result["finished_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
        (out / "result.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps({"status": result["status"], "reason": result["reason"],
                          "result": str(out / "result.json")}, ensure_ascii=False))
    return {"pass": 0, "fail": 1, "inconclusive": 2, "blocked": 3}[result["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
