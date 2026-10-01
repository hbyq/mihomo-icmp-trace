"""Require execution of Windows transport tests; a skipped raw socket is not a pass."""
import argparse
import json
from pathlib import Path


def inspect(path):
    tests = {}
    packages = {}
    other = []
    for line in path.read_text(encoding="utf-8-sig", errors="replace").splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            other.append(line)
            continue
        action = event.get("Action")
        if action in ("pass", "fail", "skip"):
            if event.get("Test"):
                tests[event["Test"]] = action
            elif event.get("Package"):
                packages[event["Package"]] = action
    return {"tests": tests, "packages": packages, "non_json_lines": other}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--transport", required=True, type=Path)
    parser.add_argument("--configuration", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    raw = inspect(args.transport)
    config = inspect(args.configuration)
    required = ["TestTraceRestore", "TestTraceRejectUnrelatedAndMalformed",
                "TestTraceLoopback/127.0.0.1", "TestTraceLoopback/::1",
                "TestTraceHopBudgetOnWire"]
    problems = [f"{name}: {raw['tests'].get(name, 'not executed')}" for name in required
                if raw["tests"].get(name) != "pass"]
    for section in (raw, config):
        problems += [f"{name}: {status}" for name, status in section["tests"].items()
                     if status in ("skip", "fail")]
        problems += [f"{name}: {status}" for name, status in section["packages"].items()
                     if status != "pass"]
    if not any(name.startswith("TestICMPTrace") for name in config["tests"]):
        problems.append("ICMP trace configuration tests did not execute")
    if not any(name.startswith("TestAsyncICMPTrace") for name in config["tests"]):
        problems.append("Asynchronous ICMP trace tests did not execute")
    result = {"status": "fail" if problems else "pass", "problems": problems,
              "transport": raw, "configuration": config}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps({"status": result["status"], "problems": problems}))
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
