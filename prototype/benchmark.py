"""Benchmark selected live functions in budgeted worker processes.

Prints one JSON record per run without modifying campaign results. PDB disk
caches may be reused. By default every measurement starts a fresh verifier;
--tasks-per-worker measures the reusable campaign workers instead.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import statistics
import time

from campaign import Paths, WorkItem, _isolated_results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repository", "build", "pdb", "exe"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--symbol", action="append", required=True)
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--tasks-per-worker", type=int, default=1)
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--memory-limit", type=float, default=8.0, help="GiB per worker")
    args = parser.parse_args()
    if args.repeat < 1 or args.timeout <= 0 or args.memory_limit <= 0 or args.tasks_per_worker < 1:
        parser.error("repeat, timeout, memory-limit and tasks-per-worker must be positive")
    paths = Paths(*(str(getattr(args, name).resolve())
                    for name in ("repository", "build", "pdb", "exe")))
    items = [
        WorkItem(symbol, paths, args.timeout, 100_000, 4096,
                 worker_timeout=args.timeout + 30, function_timeout=args.timeout)
        for _ in range(args.repeat) for symbol in args.symbol
    ]
    started = time.monotonic()
    measurements: dict[str, list] = {}
    for result in _isolated_results(items, jobs=1,
                                    memory_limit=int(args.memory_limit * (1 << 30)),
                                    tasks_per_worker=args.tasks_per_worker):
        measurements.setdefault(result.selector, []).append(result)
        print(json.dumps({"kind": "measurement", **asdict(result)}), flush=True)
    print(json.dumps({
        "kind": "summary", "wall_seconds": time.monotonic() - started,
        "functions": {
            symbol: {"median_seconds": statistics.median(item.elapsed for item in results),
                     "statuses": [item.status for item in results]}
            for symbol, results in measurements.items()
        },
    }), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
