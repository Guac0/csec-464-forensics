#!/usr/bin/env python3
"""Fake `vol` used by tests in place of volatility3 (point FT_VOL_EXECUTABLE at this file).

Behaviour is chosen by the FAKE_VOL_MODE env var (default "ok"):
  ok      - print a SYNTHETIC jsonl tree (same framing as vol's jsonl renderer: a leading blank
            line, one JSON object per root, nested "__children") and exit 0
  fail    - write an error to stderr and exit FAKE_VOL_EXIT (default 1)
  sleep   - sleep FAKE_VOL_SLEEP seconds (default 60), then exit 0
  spawn   - start a sleeping grandchild, print {"child_pid": N} to stdout, then sleep (used to
            check that the whole process group is killed)
  argv    - print the received argv (excluding argv[0]) as one JSON line and exit 0
  dump    - like vol's --dump: write a fake PE file per process into the -o directory, name it
            in a "File output" column, and exit 0
  flood   - keep writing 64 KiB chunks into the -o directory until killed (size-limit tests)
Output is SYNTHETIC test data, not real volatility output.
"""

import json
import os
import sys
import time


def main() -> int:
    mode = os.environ.get("FAKE_VOL_MODE", "ok")
    # Mimic vol: banner to stderr when using a structured renderer.
    sys.stderr.write("Volatility 3 Framework 0.0.0-fake\n")
    if mode == "fail":
        sys.stderr.write("Unsatisfied requirement plugins.Fake.kernel.layer_name\n")
        return int(os.environ.get("FAKE_VOL_EXIT", "1"))
    if mode == "sleep":
        time.sleep(float(os.environ.get("FAKE_VOL_SLEEP", "60")))
        return 0
    if mode == "spawn":
        import subprocess

        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
        sys.stdout.write(json.dumps({"child_pid": child.pid}) + "\n")
        sys.stdout.flush()
        time.sleep(120)
        return 0
    if mode in ("dump", "flood"):
        out_dir = sys.argv[sys.argv.index("-o") + 1]
        if mode == "flood":
            with open(os.path.join(out_dir, "flood.bin"), "wb") as f:
                while True:
                    f.write(b"\0" * 65536)
                    f.flush()
                    time.sleep(0.01)
        sys.stdout.write("\n")
        for pid in (4, 101):
            name = f"pid.{pid}.0x1000.dmp"
            with open(os.path.join(out_dir, name), "wb") as f:
                f.write(b"MZ" + bytes(62) + b"fake process " + str(pid).encode())
            row = {"PID": pid, "File output": name, "__children": []}
            sys.stdout.write(json.dumps(row, sort_keys=True) + "\n")
        sys.stdout.write(json.dumps({"PID": 7, "File output": "Disabled", "__children": []}) + "\n")
        return 0
    if mode == "argv":
        sys.stdout.write("\n" + json.dumps({"argv": sys.argv[1:], "__children": []}) + "\n")
        return 0
    rows = [
        {
            "PID": 4,
            "ImageFileName": "System",
            "__children": [
                {
                    "PID": 100,
                    "ImageFileName": "smss.exe",
                    "__children": [{"PID": 101, "ImageFileName": "child.exe", "__children": []}],
                },
            ],
        },
        {"PID": 200, "ImageFileName": "other.exe", "__children": []},
    ]
    sys.stdout.write("\n")
    for row in rows:
        sys.stdout.write(json.dumps(row, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
