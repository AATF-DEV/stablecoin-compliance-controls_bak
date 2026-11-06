#!/usr/bin/env python3
"""Run a command and record how long it took and how many CPU cores it had and used.

Usage (from the repository root):
  python3 scripts/timed.py LABEL [--threads N] -- COMMAND [ARGS...]
  python3 scripts/timed.py --cores          print the number of cores this process may use

The command's output is passed through unchanged. Afterwards results/timing/LABEL.json holds:
  wall_s            wall-clock time
  cpu_s             user + system CPU time of the command and every process it waited for
                    (Halmos' solver processes included)
  cores_available   cores this process may run on: the CPU affinity mask, further limited by a
                    cgroup CPU quota if one is set (containers, CI runners)
  cores_used_avg    cpu_s / wall_s, the average number of cores actually busy
  solver_threads    the --threads value, i.e. what was passed to `halmos --solver-threads`
  checks            for Halmos runs, every check's name, result, paths and time, and the suite
                    total; for the mutation check, every mutant's result and time (all read from
                    the command's output)
plus the CPU model, OS, Python and Halmos versions and the git commit. Timing varies from run to
run, so results/timing/ is git-ignored and is NOT part of `make reproduce`.
The exit code is the command's.
"""
import json
import math
import os
import platform
import re
import resource
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = ROOT / "results" / "timing"
ANSI = re.compile(r"\x1b\[[0-9;]*m")
CHECK = re.compile(r"\[(PASS|FAIL|TIMEOUT|ERROR)\]\s+(\w+)\(.*?\)\s+\(paths: (\d+), time: ([\d.]+)s")
MUTANT = re.compile(r"\[(KILLED|SURVIVED)\] (.+?)  \((\w+), ([\d.]+) s\)")  # scripts/mutation_check.py
SUITE = re.compile(r"Symbolic test result: (\d+) passed; (\d+) failed; time: ([\d.]+)s")


def cores_available() -> int:
    """Cores this process may use: affinity mask, capped by a cgroup v2/v1 CPU quota."""
    n = len(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else (os.cpu_count() or 1)
    quota = None
    try:  # cgroup v2: "max 100000" or "200000 100000"
        q, p = Path("/sys/fs/cgroup/cpu.max").read_text().split()
        if q != "max":
            quota = int(q) / int(p)
    except (OSError, ValueError):
        try:  # cgroup v1
            q = int(Path("/sys/fs/cgroup/cpu/cpu.cfs_quota_us").read_text())
            p = int(Path("/sys/fs/cgroup/cpu/cpu.cfs_period_us").read_text())
            if q > 0:
                quota = q / p
        except (OSError, ValueError):
            pass
    if quota is not None:
        n = min(n, max(1, math.ceil(quota)))
    return n


def cpu_model() -> str:
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    if platform.system() == "Darwin":
        r = subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"], capture_output=True, text=True)
        if r.returncode == 0:
            return r.stdout.strip()
    return platform.processor() or "unknown"


def tool_version(cmd) -> str | None:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = (r.stdout + r.stderr).strip()
    return text.splitlines()[-1] if r.returncode == 0 and text else None


def git_commit() -> str | None:
    r = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, capture_output=True, text=True)
    if r.returncode != 0:
        return None
    dirty = subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"], cwd=ROOT,
                           capture_output=True, text=True).stdout.strip()
    return r.stdout.strip() + ("-dirty" if dirty else "")


def main() -> int:
    argv = sys.argv[1:]
    if argv == ["--cores"]:
        print(cores_available())
        return 0
    if "--" not in argv or argv.index("--") == 0:
        print(__doc__, file=sys.stderr)
        return 2
    sep = argv.index("--")
    head, cmd = argv[:sep], argv[sep + 1:]
    label, threads = head[0], None
    if head[1:2] == ["--threads"] and len(head) == 3:
        threads = int(head[2])
    elif len(head) != 1:
        print(__doc__, file=sys.stderr)
        return 2
    if not cmd:
        print(__doc__, file=sys.stderr)
        return 2

    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    started = datetime.now(timezone.utc)
    t0 = time.monotonic()
    checks, suite = [], None
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    assert proc.stdout is not None
    for line in proc.stdout:
        sys.stdout.write(line)
        sys.stdout.flush()
        plain = ANSI.sub("", line)
        m = CHECK.search(plain)
        if m:
            checks.append({"check": m[2], "result": m[1], "paths": int(m[3]), "time_s": float(m[4])})
        m = MUTANT.search(plain)
        if m:
            checks.append({"check": f"{m[2]} ({m[3]})", "result": m[1], "paths": None, "time_s": float(m[4])})
        m = SUITE.search(plain)
        if m:
            suite = {"passed": int(m[1]), "failed": int(m[2]), "time_s": float(m[3])}
    rc = proc.wait()
    wall = time.monotonic() - t0
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    cpu = (after.ru_utime - before.ru_utime) + (after.ru_stime - before.ru_stime)

    uses_halmos = any("halmos" in Path(c).name or "mutation_check" in c for c in cmd)
    record = {
        "label": label,
        "command": " ".join(cmd),
        "exit_code": rc,
        "started_utc": started.isoformat(timespec="seconds"),
        "wall_s": round(wall, 1),
        "cpu_s": round(cpu, 1),
        "cores_available": cores_available(),
        "cores_used_avg": round(cpu / wall, 2) if wall > 0 else None,
        "solver_threads": threads,
        "cpu_model": cpu_model(),
        "logical_cpus_on_machine": os.cpu_count(),
        "os": f"{platform.system()} {platform.release()}",
        "python": platform.python_version(),
        "halmos": tool_version(["halmos", "--version"]) if uses_halmos else None,
        "git_commit": git_commit(),
        "ci": bool(os.environ.get("CI")),
        "suite": suite,
        "checks": checks,
    }
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out = OUT_DIR / f"{label}.json"
    out.write_text(json.dumps(record, indent=2) + "\n")
    print(f"[timed] {label}: {record['wall_s']} s wall, {record['cpu_s']} s CPU, "
          f"{record['cores_used_avg']} of {record['cores_available']} cores used on average -> "
          f"{out.relative_to(ROOT)}", file=sys.stderr)
    return rc


if __name__ == "__main__":
    sys.exit(main())
