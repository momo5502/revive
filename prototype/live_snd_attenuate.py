"""Check an x87-returning mismatch whose candidate relocations moved."""

from __future__ import annotations

import argparse
from pathlib import Path

import claripy

from angr_equiv import CallTarget, VerificationStatus, execute, verify_equivalence
from live_extract import execution_metadata, extract


def finite(values: tuple[claripy.ast.BV, ...]) -> tuple[claripy.ast.Bool, ...]:
    return tuple((value & 0x7F800000) != 0x7F800000 for value in values)


def run(args: argparse.Namespace, finite_only: bool) -> bool:
    symbol = "?SND_Attenuate@@YAMPAUSndCurve@@MMM@Z"
    pair = extract(args.repository, args.build, args.pdb, args.exe, symbol)
    curve = claripy.BVS("attenuate_curve", 32, explicit_name=True)
    floats = tuple(
        claripy.BVS(name, 32, explicit_name=True)
        for name in ("attenuate_mindist", "attenuate_maxdist", "attenuate_distance")
    )
    arguments = (curve, *floats)
    calls = (
        CallTarget(0x64E140, "_MyAssertHandler", 5, havoc_memory=False),
        CallTarget(
            0x65D5A0, "?Com_GetVolumeFalloffCurveValue@@YAMPAUSndCurve@@M@Z",
            2, havoc_memory=False, return_register="x87_st0",
        ),
    )
    results = (
        claripy.BVS("attenuate_assert_result", 32, explicit_name=True),
        claripy.BVS("attenuate_curve_result", 64, explicit_name=True),
    )
    constraints = finite(floats) if finite_only else ()
    reference = execute(
        pair["reference"], arguments, calls, results, base=pair["address"],
        constraints=constraints, **execution_metadata(pair),
    )
    candidate = execute(
        pair["candidate"], arguments, calls, results, base=pair["address"],
        constraints=constraints, **execution_metadata(pair),
    )
    result = verify_equivalence(
        reference, candidate, arguments, return_register="x87_st0",
    )
    scope = "finite floats" if finite_only else "all float bit patterns"
    print(f"{result.status.value}: {symbol} [{scope}]")
    if result.counterexample is not None:
        print("  counterexample: " + ", ".join(f"0x{x:08x}" for x in result.counterexample))
    if result.reasons:
        print("  reasons: " + ", ".join(result.reasons))
    return result.status == VerificationStatus.EQUIVALENT


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--pdb", type=Path, required=True)
    parser.add_argument("--exe", type=Path, required=True)
    args = parser.parse_args()
    args.repository = args.repository.resolve()
    args.build = args.build.resolve()
    args.pdb = args.pdb.resolve()
    args.exe = args.exe.resolve()
    run(args, finite_only=False)
    run(args, finite_only=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
