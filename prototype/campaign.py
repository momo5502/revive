"""Resumable parallel exact/semantic classification campaign."""

from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass
import hashlib
import json
import logging
import multiprocessing
import os
from pathlib import Path
import time
from typing import Any

logging.getLogger("angr").setLevel(logging.CRITICAL)
logging.getLogger("cle").setLevel(logging.CRITICAL)

import claripy

from alias_model import GlobalObject, PointerGlobal
from angr_equiv import (
    bounded_external_regions,
    VerificationStatus,
    execute,
    verify_equivalence,
    verify_under_pdb_aliasing,
)
from live_extract import (
    external_call_contracts,
    extract,
    global_object_contracts,
    pointer_global_contracts,
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


def _classify(item: WorkItem) -> WorkResult:
    started = time.monotonic()
    try:
        pair = extract(
            Path(item.paths.repository), Path(item.paths.build),
            Path(item.paths.pdb), Path(item.paths.exe), item.selector,
        )
        signature = pair["signature"]
        if pair["reference"] == pair["candidate"]:
            fingerprint = proof_fingerprint(
                symbol=item.selector,
                reference=pair["reference"], candidate=pair["candidate"],
                candidate_relocations=pair["relocation_resolutions"],
                signature=signature,
                options={"classification": "byte-exact"},
                assumptions={"frontend_issues": pair["frontend_issues"]},
            )
            if (item.previous_status == "EXACT_NOW" and
                    item.previous_fingerprint == fingerprint):
                return WorkResult(
                    item.selector, "EXACT_NOW", fingerprint, (), None,
                    time.monotonic() - started, True,
                )
            return WorkResult(
                item.selector, "EXACT_NOW", fingerprint, (), None,
                time.monotonic() - started,
            )
        calls = external_call_contracts(pair)
        global_descriptors = global_object_contracts(pair)
        pointer_descriptors = pointer_global_contracts(pair)
        global_objects = tuple(
            GlobalObject(item.logical_id, item.address, item.size)
            for item in global_descriptors
        )
        pointer_globals = tuple(
            PointerGlobal(item.logical_id, item.address, item.pointee_size)
            for item in pointer_descriptors
        )
        common_memory = tuple(
            (item.address, claripy.BVV(
                int.from_bytes(item.content, "little"), item.size * 8,
            ) if item.content is not None else claripy.BVS(
                f"campaign_global_{index}_{item.address:x}", item.size * 8,
                explicit_name=True,
            ))
            for index, item in enumerate(global_descriptors)
        )
        observed_memory = tuple(
            (item.address, item.size) for item in global_descriptors
        )
        call_results = tuple(
            claripy.BVS(
                f"campaign_call_{index}",
                (64 if call.return_register == "x87_st0" else
                 call.signature.return_type.size * 8
                 if call.signature and call.signature.return_type.size else 32),
                explicit_name=True,
            )
            for index, call in enumerate(calls)
        )
        fingerprint = proof_fingerprint(
            symbol=item.selector,
            reference=pair["reference"], candidate=pair["candidate"],
            candidate_relocations=pair["relocation_resolutions"],
            signature=signature, options={
                "timeout": item.timeout,
                "maximum_steps": item.maximum_steps,
                "maximum_alias_cases": item.maximum_alias_cases,
                "call_contracts": tuple(
                    (call.address, call.decorated_symbol, call.argument_count,
                     call.callsite_argument_counts, repr(call.signature))
                    for call in calls
                ),
                "global_objects": tuple(
                    (item.logical_id, item.address, item.size,
                     item.content.hex() if item.content is not None else None)
                    for item in global_descriptors
                ),
                "pointer_globals": tuple(
                    (item.logical_id, item.address, item.pointee_size)
                    for item in pointer_descriptors
                ),
            }, assumptions={"frontend_issues": pair["frontend_issues"]},
        )
        if (item.previous_status in TERMINAL and
                item.previous_fingerprint == fingerprint):
            return WorkResult(
                item.selector, item.previous_status, fingerprint, (), None,
                time.monotonic() - started, True,
            )
        if signature is None:
            return WorkResult(
                item.selector, VerificationStatus.UNSUPPORTED.value, fingerprint,
                pair["frontend_issues"] or ("UNSUPPORTED_PDB_ABI",), None,
                time.monotonic() - started,
            )
        if (any(parameter.pointer for parameter in signature.parameters) or
                pointer_globals):
            result = verify_under_pdb_aliasing(
                pair["reference"], pair["candidate"], signature,
                reference_calls=calls, candidate_calls=calls,
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
                # Alias cases are streamed and each execution has its own
                # timeout. A single wall-clock deadline made later cases
                # inconclusive merely because earlier valid cases existed.
                total_timeout_seconds=None,
            )
        else:
            arguments = tuple(
                _argument(f"campaign_arg_{index}", parameter.size)
                for index, parameter in enumerate(signature.parameters)
            )
            reference = execute(
                pair["reference"], arguments, calls, call_results,
                common_memory,
                base=pair["address"],
                signature=signature, frontend_issues=pair["frontend_issues"],
                timeout_seconds=item.timeout, maximum_steps=item.maximum_steps,
            )
            candidate = execute(
                pair["candidate"], arguments, calls, call_results,
                common_memory,
                base=pair["address"],
                signature=signature, frontend_issues=pair["frontend_issues"],
                timeout_seconds=item.timeout, maximum_steps=item.maximum_steps,
            )
            extra_regions = bounded_external_regions(
                (reference, candidate), observed_memory,
            )
            if extra_regions:
                extra_memory = tuple(
                    (address, claripy.BVS(
                        f"campaign_bounded_{address:x}_{size}", size * 8,
                        explicit_name=True,
                    ))
                    for address, size in extra_regions
                )
                complete_memory = (*common_memory, *extra_memory)
                reference = execute(
                    pair["reference"], arguments, calls, call_results,
                    complete_memory, base=pair["address"],
                    signature=signature, frontend_issues=pair["frontend_issues"],
                    timeout_seconds=item.timeout, maximum_steps=item.maximum_steps,
                )
                candidate = execute(
                    pair["candidate"], arguments, calls, call_results,
                    complete_memory, base=pair["address"],
                    signature=signature, frontend_issues=pair["frontend_issues"],
                    timeout_seconds=item.timeout, maximum_steps=item.maximum_steps,
                )
                observed_memory = (*observed_memory, *extra_regions)
            result = verify_equivalence(
                reference, candidate, arguments,
                observed_memory=observed_memory,
            )
        return WorkResult(
            item.selector, result.status.value, fingerprint, result.reasons,
            result.counterexample, time.monotonic() - started,
        )
    except FileNotFoundError as error:
        return WorkResult(
            item.selector, VerificationStatus.UNSUPPORTED.value, None,
            (f"MISSING_CANDIDATE_OBJECT:{error}",), None,
            time.monotonic() - started,
        )
    except MemoryError as error:
        return WorkResult(
            item.selector, VerificationStatus.INCONCLUSIVE.value, None,
            (f"RESOURCE_EXHAUSTED:{type(error).__name__}:{error}",), None,
            time.monotonic() - started,
        )
    except Exception as error:
        if "out of memory" in str(error).lower():
            return WorkResult(
                item.selector, VerificationStatus.INCONCLUSIVE.value, None,
                (f"RESOURCE_EXHAUSTED:{type(error).__name__}:{error}",), None,
                time.monotonic() - started,
            )
        return WorkResult(
            item.selector, "EXTRACTION_FAILED", None,
            (f"{type(error).__name__}:{error}",), None,
            time.monotonic() - started,
        )


def _isolated_entry(item: WorkItem, connection: Any) -> None:
    """Run one classification behind a native-process failure boundary."""
    try:
        connection.send(_classify(item))
    finally:
        connection.close()


def _isolated_results(items: list[WorkItem], jobs: int):
    """Yield results while allowing a native crash to affect only one item."""
    context = multiprocessing.get_context("spawn")
    remaining = iter(items)
    active: dict[Any, tuple[WorkItem, Any, float]] = {}
    exhausted = False

    while active or not exhausted:
        while not exhausted and len(active) < jobs:
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
            time.sleep(0.05)


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
    if args.start:
        selectors = selectors[args.start:]
    if args.limit is not None:
        selectors = selectors[:args.limit]
    paths = Paths(*(str(value.resolve()) for value in (
        args.repository, args.build, args.pdb, args.exe,
    )))
    items = [WorkItem(
        selector, paths, args.timeout, args.maximum_steps,
        args.maximum_alias_cases,
        results[selector].status if selector in results else None,
        results[selector].fingerprint if selector in results else None,
    ) for selector in selectors]
    completed = 0
    for result in _isolated_results(items, args.jobs):
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
    run.add_argument("--jobs", type=int, default=max(1, min(4, os.cpu_count() or 1)))
    run.add_argument("--limit", type=int)
    run.add_argument("--start", type=int, default=0)
    run.add_argument("--order", choices=("lexical", "hash"), default="hash")
    run.add_argument("--timeout", type=float, default=300.0)
    run.add_argument("--maximum-steps", type=int, default=100_000)
    run.add_argument("--maximum-alias-cases", type=int, default=4096)
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
    return run_campaign(args)


if __name__ == "__main__":
    raise SystemExit(main())
