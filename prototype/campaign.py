"""Resumable parallel exact/semantic classification campaign."""

from __future__ import annotations

import argparse
import csv
import ctypes
from dataclasses import dataclass
import functools
import hashlib
import json
import logging
import multiprocessing
import os
from pathlib import Path
import random
import time
from typing import Any

logging.getLogger("angr").setLevel(logging.CRITICAL)
logging.getLogger("cle").setLevel(logging.CRITICAL)

import claripy

from alias_model import GlobalObject, PointerGlobal
from angr_equiv import VerificationStatus, verify_under_pdb_aliasing
from live_extract import (
    external_call_contracts,
    extract,
    global_object_contracts,
    pointer_field_types,
    pointer_global_contracts,
    stack_allocation_contracts,
    type_placements,
)
from proof_record import proof_fingerprint


TERMINAL = {
    "EXACT_NOW", "EQUIVALENT", "NOT_EQUIVALENT", "INCONCLUSIVE",
    "MODEL_INCOMPLETE", "UNSUPPORTED", "EXTRACTION_FAILED", "SOLVER_CRASH",
}


@dataclass(frozen=True)
class Paths:
    repository: str
    build: str
    pdb: str
    exe: str


@dataclass(frozen=True)
class WorkItem:
    selector: str
    paths: Paths
    timeout: float
    maximum_steps: int
    maximum_alias_cases: int
    worker_timeout: float | None = None
    function_timeout: float | None = None
    previous_status: str | None = None
    previous_fingerprint: str | None = None


@dataclass(frozen=True)
class WorkResult:
    selector: str
    status: str
    fingerprint: str | None
    reasons: tuple[str, ...]
    counterexample: tuple[int, ...] | None
    elapsed: float
    cached: bool = False


def _inventory_selectors(path: Path) -> tuple[list[str], dict[str, int]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    values = [function["selector"]
              for unit in raw["translation_units"]
              for function in unit["functions"]]
    counts: dict[str, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    return sorted(counts), counts


def _ledger_selectors(root: Path) -> list[str]:
    values: set[str] = set()
    for path in root.rglob("*.txt"):
        for raw in path.read_text(encoding="utf-8").splitlines():
            value = raw.strip()
            if value and not value.startswith("#"):
                values.add(value)
    return sorted(values)


def split_inventory(repository: Path, output: Path) -> dict[str, Any]:
    selectors, counts = _inventory_selectors(
        repository / "config" / "byte_match" / "function_inventory.json"
    )
    ledger = _ledger_selectors(repository / "config" / "byte_match" / "functions")
    inventory_set = set(selectors)
    ledger_set = set(ledger)
    exact = sorted(inventory_set & ledger_set)
    inexact = sorted(inventory_set - ledger_set)
    ledger_only = sorted(ledger_set - inventory_set)
    duplicates = {key: value for key, value in counts.items() if value != 1}
    result = {
        "schema": 1,
        "inventory_unique": len(selectors),
        "ledger_unique": len(ledger),
        "exact": exact,
        "inexact": inexact,
        "ledger_only": ledger_only,
        "duplicate_inventory_selectors": duplicates,
    }
    output.mkdir(parents=True, exist_ok=True)
    (output / "manifest.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8",
    )
    for name, values in (("exact.txt", exact), ("inexact.txt", inexact),
                         ("ledger_only.txt", ledger_only)):
        (output / name).write_text("\n".join(values) + "\n", encoding="utf-8")
    return result


RESULT_COLUMNS = (
    "selector", "status", "fingerprint", "reasons", "counterexample", "elapsed",
)


def _read_results(path: Path) -> dict[str, WorkResult]:
    if not path.is_file():
        return {}
    results: dict[str, WorkResult] = {}
    with path.open("r", encoding="utf-8", newline="") as stream:
        for row in csv.DictReader(stream, delimiter="\t"):
            result = WorkResult(
                selector=row["selector"], status=row["status"],
                fingerprint=row["fingerprint"] or None,
                reasons=tuple(json.loads(row["reasons"])),
                counterexample=(
                    tuple(json.loads(row["counterexample"]))
                    if row["counterexample"] else None
                ),
                elapsed=float(row["elapsed"]),
            )
            results[result.selector] = result
    return results


def _write_results(path: Path, results: dict[str, WorkResult]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=RESULT_COLUMNS, delimiter="\t")
        writer.writeheader()
        for result in sorted(results.values(), key=lambda item: item.selector):
            writer.writerow({
                "selector": result.selector,
                "status": result.status,
                "fingerprint": result.fingerprint or "",
                "reasons": json.dumps(result.reasons, separators=(",", ":")),
                "counterexample": (
                    json.dumps(result.counterexample, separators=(",", ":"))
                    if result.counterexample is not None else ""
                ),
                "elapsed": f"{result.elapsed:.6f}",
            })
    temporary.replace(path)


def _argument(name: str, size: int) -> claripy.ast.BV:
    return claripy.BVS(name, size * 8, explicit_name=True)


@functools.lru_cache(maxsize=None)
def _file_sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _frontend_identity(paths: Paths, matcher) -> dict[str, str]:
    """Inputs outside the function bytes that shape extraction and contracts."""
    repository = Path(paths.repository)
    files = {
        "matcher": repository / "tools" / "byte_match" / "iw4match.py",
        "target_data_rvas": repository / matcher.DEFAULT_TARGET_DATA_RVAS,
        "target_function_rvas": repository / matcher.DEFAULT_TARGET_FUNCTION_RVAS,
        "target_exe": Path(paths.exe),
        "target_pdb": Path(paths.pdb),
    }
    return {
        name: _file_sha256(str(path)) if path.is_file() else "missing"
        for name, path in files.items()
    }


def borrowed_identities(pair: dict) -> list[str]:
    """Candidate data identities copied from the reference instruction.

    Neither byte identity nor an equivalence proof can detect a wrong
    reference whose target was taken from the reference itself, so no
    success may rest on one.
    """
    return sorted({
        relocation.get("target") or "?"
        for relocation in pair["relocation_resolutions"]
        if relocation.get("identity_rule") == "reference_address_hint"
    })


def _classify(item: WorkItem) -> WorkResult:
    started = time.monotonic()

    def finish(status: str, fingerprint: str | None, reasons: tuple[str, ...],
               counterexample: tuple[int, ...] | None = None,
               cached: bool = False) -> WorkResult:
        return WorkResult(
            item.selector, status, fingerprint, reasons, counterexample,
            time.monotonic() - started, cached,
        )

    try:
        pair = extract(
            Path(item.paths.repository), Path(item.paths.build),
            Path(item.paths.pdb), Path(item.paths.exe), item.selector,
        )
        signature = pair["signature"]
        frontend = _frontend_identity(item.paths, pair["matcher"])
        borrowed = borrowed_identities(pair)
        if pair["reference"] == pair["candidate"] and not borrowed:
            fingerprint = proof_fingerprint(
                symbol=item.selector,
                reference=pair["reference"], candidate=pair["candidate"],
                candidate_relocations=pair["relocation_resolutions"],
                signature=signature,
                options={"classification": "byte-exact"},
                assumptions={"frontend_issues": pair["frontend_issues"], "frontend": frontend},
            )
            cached = (item.previous_status == "EXACT_NOW" and
                      item.previous_fingerprint == fingerprint)
            return finish("EXACT_NOW", fingerprint, (), cached=cached)
        reference_calls, candidate_calls = external_call_contracts(pair)
        global_descriptors = global_object_contracts(pair)
        pointer_descriptors = pointer_global_contracts(pair)
        reference_allocations, candidate_allocations = stack_allocation_contracts(pair)
        placements = type_placements(pair)
        pointer_types = pointer_field_types(pair)
    except FileNotFoundError as error:
        return finish(VerificationStatus.UNSUPPORTED.value, None,
                      (f"MISSING_CANDIDATE_OBJECT:{error}",))
    except Exception as error:
        return finish("EXTRACTION_FAILED", None, (f"{type(error).__name__}:{error}",))

    global_objects = tuple(
        GlobalObject(item.logical_id, item.address, item.size, item.type_index)
        for item in global_descriptors
    )
    pointer_globals = tuple(
        PointerGlobal(item.logical_id, item.address, item.pointee_size)
        for item in pointer_descriptors
    )
    # Mutable globals are not declared: a named global resolves to the same
    # address on both sides, so the engine models exactly the bytes an
    # execution touches, by address. Declaring whole objects (e.g. the 1 MB
    # cgArray) and snapshotting them at every call exhausted memory. Only
    # constants with known contents are declared. Globals stay alias targets.
    declared = tuple(
        descriptor for descriptor in global_descriptors if descriptor.content is not None
    )
    common_memory = tuple(
        (descriptor.address, claripy.BVV(
            int.from_bytes(descriptor.content, "little"), descriptor.size * 8,
        ) if descriptor.content is not None else claripy.BVS(
            f"campaign_global_{index}_{descriptor.address:x}", descriptor.size * 8,
            explicit_name=True,
        ))
        for index, descriptor in enumerate(declared)
    )
    observed_memory = tuple(
        (descriptor.address, descriptor.size) for descriptor in declared
    )
    call_results = tuple(
        claripy.BVS(
            f"campaign_call_{index}",
            (64 if call.return_register == "x87_st0" else
             call.signature.return_type.size * 8
             if call.signature and call.signature.return_type.size else 32),
            explicit_name=True,
        )
        for index, call in enumerate(reference_calls)
    )
    fingerprint = proof_fingerprint(
        symbol=item.selector,
        reference=pair["reference"], candidate=pair["candidate"],
        candidate_relocations=pair["relocation_resolutions"],
        signature=signature, options={
            "timeout": item.timeout,
            "maximum_steps": item.maximum_steps,
            "maximum_alias_cases": item.maximum_alias_cases,
            "function_timeout": item.function_timeout,
            "call_contracts": tuple(
                (call.address, call.decorated_symbol, call.argument_count,
                 call.callsite_argument_counts, call.x87_pops, repr(call.signature),
                 call.frontend_issues, call.entry_homes)
                for calls in (reference_calls, candidate_calls) for call in calls
            ),
            "entry_homes": (pair["reference_homes"], pair["candidate_homes"]),
            "global_objects": tuple(
                (descriptor.logical_id, descriptor.address, descriptor.size,
                 descriptor.type_index,
                 descriptor.content.hex() if descriptor.content is not None else None)
                for descriptor in global_descriptors
            ),
            "pointer_globals": tuple(
                (descriptor.logical_id, descriptor.address, descriptor.pointee_size)
                for descriptor in pointer_descriptors
            ),
            "stack_allocations": (reference_allocations, candidate_allocations),
        }, assumptions={"frontend_issues": pair["frontend_issues"], "frontend": frontend},
    )
    if (item.previous_status in TERMINAL and
            item.previous_fingerprint == fingerprint):
        return finish(item.previous_status, fingerprint, (), cached=True)
    if signature is None:
        return finish(VerificationStatus.UNSUPPORTED.value, fingerprint,
                      pair["frontend_issues"] or ("UNSUPPORTED_PDB_ABI",))
    mismatch = tuple(
        issue for issue in pair["frontend_issues"]
        if issue.startswith("CANDIDATE_SIGNATURE_MISMATCH")
    )
    if mismatch:
        # The candidate declares a different interface; callers cannot
        # observe the same behavior through it.
        return finish(VerificationStatus.NOT_EQUIVALENT.value, fingerprint, mismatch)

    try:
        result = verify_under_pdb_aliasing(
            pair["reference"], pair["candidate"], signature,
            reference_calls=reference_calls, candidate_calls=candidate_calls,
            call_results=call_results,
            common_memory=common_memory,
            observed_memory=observed_memory,
            global_objects=global_objects,
            pointer_globals=pointer_globals,
            reference_base=pair["address"], candidate_base=pair["address"],
            frontend_issues=pair["frontend_issues"],
            maximum_cases=item.maximum_alias_cases,
            execute_options={
                "timeout_seconds": item.timeout,
                "maximum_steps": item.maximum_steps,
            },
            # One budget for every alias case of the function; running out
            # is INCONCLUSIVE (ALIAS_CAMPAIGN_TIMEOUT).
            total_timeout_seconds=item.function_timeout,
            reference_stack_allocations=reference_allocations,
            candidate_stack_allocations=candidate_allocations,
            placements=placements,
            reference_entry_homes=pair["reference_homes"],
            candidate_entry_homes=pair["candidate_homes"],
            pointer_types=pointer_types,
        )
    except MemoryError as error:
        return finish(VerificationStatus.INCONCLUSIVE.value, fingerprint,
                      (f"RESOURCE_EXHAUSTED:{type(error).__name__}:{error}",))
    except claripy.errors.ClaripySolverInterruptError as error:
        return finish(VerificationStatus.INCONCLUSIVE.value, fingerprint,
                      (f"SOLVER_LIMIT:{error}",))
    except Exception as error:
        # Verifier failures are not extraction failures and never successes.
        return finish(VerificationStatus.INCONCLUSIVE.value, fingerprint,
                      (f"VERIFIER_ERROR:{type(error).__name__}:{error}",))

    if result.status == VerificationStatus.EQUIVALENT and borrowed:
        # The candidate's data identity was copied from the reference, so an
        # equivalence proof could not have detected a wrong reference.
        return finish(VerificationStatus.MODEL_INCOMPLETE.value, fingerprint,
                      tuple(f"BORROWED_DATA_IDENTITY:{symbol}" for symbol in borrowed))
    return finish(result.status.value, fingerprint, result.reasons, result.counterexample)


def _isolated_entry(item: WorkItem, connection: Any) -> None:
    """Run one classification behind a native-process failure boundary."""
    try:
        connection.send(_classify(item))
    finally:
        connection.close()


class _MemoryStatus(ctypes.Structure):
    _fields_ = [
        ("length", ctypes.c_ulong), ("load", ctypes.c_ulong),
        ("total_physical", ctypes.c_ulonglong), ("available_physical", ctypes.c_ulonglong),
        ("total_page_file", ctypes.c_ulonglong), ("available_page_file", ctypes.c_ulonglong),
        ("total_virtual", ctypes.c_ulonglong), ("available_virtual", ctypes.c_ulonglong),
        ("available_extended_virtual", ctypes.c_ulonglong),
    ]


class _ProcessMemoryCounters(ctypes.Structure):
    _fields_ = [
        ("size", ctypes.c_ulong), ("page_fault_count", ctypes.c_ulong),
        ("peak_working_set", ctypes.c_size_t), ("working_set", ctypes.c_size_t),
        ("quota_peak_paged_pool", ctypes.c_size_t), ("quota_paged_pool", ctypes.c_size_t),
        ("quota_peak_nonpaged_pool", ctypes.c_size_t), ("quota_nonpaged_pool", ctypes.c_size_t),
        ("pagefile_usage", ctypes.c_size_t), ("peak_pagefile_usage", ctypes.c_size_t),
    ]


def _available_memory() -> int | None:
    """Free physical memory in bytes (Windows), or None when unknown."""
    if os.name != "nt":
        return None
    status = _MemoryStatus()
    status.length = ctypes.sizeof(status)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
        return None
    return status.available_physical


def _process_memory(pid: int) -> int | None:
    """Committed private memory of a process in bytes (Windows)."""
    if os.name != "nt":
        return None
    handle = ctypes.windll.kernel32.OpenProcess(0x1000 | 0x0010, False, pid)
    if not handle:
        return None
    try:
        counters = _ProcessMemoryCounters()
        counters.size = ctypes.sizeof(counters)
        if not ctypes.windll.psapi.GetProcessMemoryInfo(
                handle, ctypes.byref(counters), counters.size):
            return None
        return counters.pagefile_usage
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)


def _isolated_results(items: list[WorkItem], jobs: int, memory_limit: int | None = None):
    """Yield results while allowing a native crash to affect only one item.

    A worker that exceeds ``memory_limit`` bytes is killed and reported as
    INCONCLUSIVE. New workers start only while at least that much physical
    memory is free, so every core is used when memory allows it.
    """
    context = multiprocessing.get_context("spawn")
    remaining = iter(items)
    active: dict[Any, tuple[WorkItem, Any, float]] = {}
    exhausted = False

    def stop(process, item, connection, started, reason):
        process.terminate()
        process.join()
        connection.close()
        del active[process]
        return WorkResult(
            item.selector, VerificationStatus.INCONCLUSIVE.value, None, (reason,), None,
            time.monotonic() - started,
        )

    while active or not exhausted:
        while not exhausted and len(active) < jobs:
            available = _available_memory()
            if (active and memory_limit is not None and available is not None and
                    available < memory_limit):
                break
            try:
                item = next(remaining)
            except StopIteration:
                exhausted = True
                break
            parent, child = context.Pipe(duplex=False)
            process = context.Process(target=_isolated_entry, args=(item, child))
            process.start()
            child.close()
            active[process] = (item, parent, time.monotonic())

        made_progress = False
        for process, (item, connection, started) in list(active.items()):
            result = None
            if connection.poll():
                try:
                    result = connection.recv()
                except EOFError:
                    pass
            elif process.is_alive():
                used = _process_memory(process.pid) if memory_limit is not None else None
                if used is not None and used > memory_limit:
                    made_progress = True
                    yield stop(process, item, connection, started,
                               f"MEMORY_LIMIT:{used >> 20}MB")
                elif (item.worker_timeout is not None and
                        time.monotonic() - started > item.worker_timeout):
                    made_progress = True
                    yield stop(process, item, connection, started,
                               f"WORKER_TIMEOUT:{item.worker_timeout:g}s")
                continue

            process.join()
            if result is None and connection.poll():
                try:
                    result = connection.recv()
                except EOFError:
                    pass
            connection.close()
            del active[process]
            made_progress = True

            if result is None:
                result = WorkResult(
                    item.selector, "SOLVER_CRASH", None,
                    (f"WORKER_EXIT_CODE:{process.exitcode}",), None,
                    time.monotonic() - started,
                )
            yield result

        if active and not made_progress:
            time.sleep(0.2)


def _summary(results: dict[str, WorkResult]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for result in results.values():
        counts[result.status] = counts.get(result.status, 0) + 1
    return dict(sorted(counts.items()))


def _export_results(results: dict[str, WorkResult], output: Path) -> None:
    result_root = output / "results"
    result_root.mkdir(parents=True, exist_ok=True)
    statuses = sorted({result.status for result in results.values()})
    for status in statuses:
        selectors = sorted(result.selector for result in results.values()
                           if result.status == status)
        name = status.lower() + ".txt"
        (result_root / name).write_text(
            "\n".join(selectors) + ("\n" if selectors else ""), encoding="utf-8",
        )


def run_campaign(args: argparse.Namespace) -> int:
    manifest = json.loads((args.output / "manifest.json").read_text(encoding="utf-8"))
    selectors = list(manifest["inexact"])
    results = _read_results(args.results)
    if args.order == "hash":
        selectors.sort(key=lambda value: hashlib.sha256(value.encode("utf-8")).digest())
    elif args.order == "random":
        random.Random(args.seed).shuffle(selectors)
    if args.start:
        selectors = selectors[args.start:]
    if args.limit is not None:
        selectors = selectors[:args.limit]
    paths = Paths(*(str(value.resolve()) for value in (
        args.repository, args.build, args.pdb, args.exe,
    )))
    items = [WorkItem(
        selector, paths, args.timeout, args.maximum_steps,
        args.maximum_alias_cases, args.worker_timeout, args.function_timeout,
        results[selector].status if selector in results else None,
        results[selector].fingerprint if selector in results else None,
    ) for selector in selectors]
    completed = 0
    for result in _isolated_results(items, args.jobs, int(args.memory_limit * (1 << 30))):
        if not result.cached:
            results[result.selector] = result
            _write_results(args.results, results)
        completed += 1
        if completed % args.progress_every == 0 or completed == len(items):
            print(json.dumps({
                "completed": completed, "total": len(items),
                "counts": _summary(results),
            }, sort_keys=True), flush=True)
    _export_results(results, args.output)
    print(json.dumps({"counts": _summary(results)}, indent=2, sort_keys=True))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("campaign"))
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("split")
    run = subparsers.add_parser("run")
    run.add_argument("--build", type=Path, required=True)
    run.add_argument("--pdb", type=Path, required=True)
    run.add_argument("--exe", type=Path, required=True)
    run.add_argument("--results", type=Path)
    run.add_argument("--jobs", type=int, default=os.cpu_count() or 1)
    run.add_argument(
        "--memory-limit", type=float, default=8.0,
        help="GiB per worker; larger workers are killed (INCONCLUSIVE) and new "
             "workers wait until this much memory is free",
    )
    run.add_argument("--limit", type=int)
    run.add_argument("--start", type=int, default=0)
    run.add_argument("--order", choices=("lexical", "hash", "random"), default="hash")
    run.add_argument("--seed", type=int, help="shuffle seed for --order random")
    run.add_argument("--timeout", type=float, default=60.0)
    run.add_argument("--maximum-steps", type=int, default=100_000)
    run.add_argument("--maximum-alias-cases", type=int, default=4096)
    run.add_argument(
        "--function-timeout", type=float, default=60.0,
        help="verification budget per function across all alias cases",
    )
    run.add_argument(
        "--worker-timeout", type=float,
        help="hard kill per function (default: function timeout plus 120 s for "
             "extraction and a solver query that overruns the budget)",
    )
    run.add_argument("--progress-every", type=int, default=10)
    args = parser.parse_args()
    args.repository = args.repository.resolve()
    args.output = args.output.resolve()
    if args.command == "split":
        result = split_inventory(args.repository, args.output)
        print(json.dumps({key: len(value) if isinstance(value, list) else value
                          for key, value in result.items() if key != "schema"},
                         indent=2, sort_keys=True))
        return 0
    args.results = (args.results or args.output / "results.tsv").resolve()
    if args.worker_timeout is None:
        args.worker_timeout = args.function_timeout + 120.0
    if args.order == "random" and args.seed is None:
        args.seed = random.SystemRandom().randrange(1 << 32)
        print(json.dumps({"seed": args.seed}), flush=True)
    return run_campaign(args)


if __name__ == "__main__":
    raise SystemExit(main())
