"""Collect actual Windows BestTrace GUI controls before runtime validation."""
import argparse
import json
import os
from pathlib import Path
import time
import traceback

from pywinauto import Application


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()
    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    result = {"status": "error", "executable": args.exe, "pid": None, "windows": []}
    app = None
    try:
        exe = Path(args.exe).resolve()
        app = Application(backend="win32").start(str(exe), work_dir=str(exe.parent))
        result["pid"] = app.process
        for attempt in range(12):
            windows = app.windows()
            if any(w.is_visible() for w in windows):
                break
            time.sleep(1)
        for index, window in enumerate(app.windows()):
            controls = []
            for control in window.descendants():
                try:
                    controls.append({"class": control.class_name(), "id": control.control_id(),
                                     "text": control.window_text(), "visible": control.is_visible(),
                                     "enabled": control.is_enabled()})
                except Exception as error:
                    controls.append({"error": str(error)})
            result["windows"].append({"title": window.window_text(), "class": window.class_name(),
                                      "controls": controls})
            try:
                window.capture_as_image().save(out / f"window-{index}.png")
            except Exception as error:
                result.setdefault("screenshot_errors", []).append(str(error))
        result["status"] = "observed" if result["windows"] else "blocked"
    except Exception:
        result["error"] = traceback.format_exc()
    finally:
        (out / "gui-environment.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps(result, ensure_ascii=False))
        if app:
            try:
                app.kill()
            except Exception:
                pass
    return 0 if result["status"] == "observed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
