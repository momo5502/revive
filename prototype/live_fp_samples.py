"""Exercise relocation-free x87 mismatches from live artifacts."""

from __future__ import annotations

import argparse
from pathlib import Path

import claripy

from angr_equiv import counterexample, execute
from live_extract import execution_metadata, extract


def symbolic_words(prefix: str, count: int) -> tuple[claripy.ast.BV, ...]:
    return tuple(
        claripy.BVS(f"{prefix}_{index}", 32, explicit_name=True)
        for index in range(count)
    )


def finite(values: tuple[claripy.ast.BV, ...]) -> tuple[claripy.ast.Bool, ...]:
    return tuple((value & 0x7F800000) != 0x7F800000 for value in values)


def prove_vector_copy(args: argparse.Namespace) -> bool:
    selector = "@physics/ode/src/ode.cpp:0x2dbd00:0x1c58"
    pair = extract(args.repository, args.build, args.pdb, args.exe, selector)
    joint, direction = 0x300000, 0x310000
    values = symbolic_words("contact_direction", 3)
    old_values = symbolic_words("old_contact_direction", 3)
    memory = tuple((direction + 4 * i, value) for i, value in enumerate(values))
    memory += tuple((joint + 0x8C + 4 * i, value) for i, value in enumerate(old_values))
    arguments = (claripy.BVV(joint, 32), claripy.BVV(direction, 32))
    reference = execute(pair["reference"], arguments, initial_memory=memory,
                        base=pair["address"], **execution_metadata(pair))
    candidate = execute(pair["candidate"], arguments, initial_memory=memory,
                        base=pair["address"], **execution_metadata(pair))
    observed = tuple((joint + 0x8C + 4 * i, 4) for i in range(3))
    model = counterexample(
        reference, candidate, values + old_values,
        observed_memory=observed, compare_return=False,
    )
    print(("EQUIVALENT" if model is None else "NOT_EQUIVALENT") + f": {selector}")
    return model is None


def prove_component_hit_test(args: argparse.Namespace, finite_only: bool = False) -> bool:
    symbol = "?GetCompAtLocation@UI_Component@@UAEPAV1@QAM@Z"
    pair = extract(args.repository, args.build, args.pdb, args.exe, symbol)
    component, location = 0x300000, 0x310000
    values = symbolic_words("component_hit_float", 4)
    memory = (
        (component + 4, values[0]),
        (component + 8, values[1]),
        (location, values[2]),
        (location + 4, values[3]),
    )
    arguments = (claripy.BVV(component, 32), claripy.BVV(location, 32))
    constraints = finite(values) if finite_only else ()
    reference = execute(
        pair["reference"], arguments, initial_memory=memory,
        base=pair["address"], constraints=constraints, **execution_metadata(pair),
    )
    candidate = execute(
        pair["candidate"], arguments, initial_memory=memory,
        base=pair["address"], constraints=constraints, **execution_metadata(pair),
    )
    model = counterexample(reference, candidate, values)
    scope = " [finite inputs]" if finite_only else " [all bit patterns]"
    print(("EQUIVALENT" if model is None else "NOT_EQUIVALENT") + f": {symbol}{scope}")
    if model is not None:
        print("  counterexample bits: " + ", ".join(f"0x{x:08x}" for x in model))
    return model is None


def prove_rotational_limit(args: argparse.Namespace, finite_only: bool = False) -> bool:
    symbol = "?testRotationalLimit@dxJointLimitMotor@@QBEHM@Z"
    pair = extract(args.repository, args.build, args.pdb, args.exe, symbol)
    motor = 0x300000
    values = symbolic_words("rotational_limit_float", 3)
    old_status = claripy.BVS("rotational_limit_old_status", 32, explicit_name=True)
    old_error = claripy.BVS("rotational_limit_old_error", 32, explicit_name=True)
    memory = (
        (motor + 8, values[0]),
        (motor + 0xC, values[1]),
        (motor + 0x24, old_status),
        (motor + 0x28, old_error),
    )
    arguments = (claripy.BVV(motor, 32), values[2])
    constraints = finite(values) if finite_only else ()
    reference = execute(
        pair["reference"], arguments, initial_memory=memory,
        base=pair["address"], constraints=constraints, **execution_metadata(pair),
    )
    candidate = execute(
        pair["candidate"], arguments, initial_memory=memory,
        base=pair["address"], constraints=constraints, **execution_metadata(pair),
    )
    inputs = values + (old_status, old_error)
    model = counterexample(
        reference, candidate, inputs,
        observed_memory=((motor + 0x24, 4), (motor + 0x28, 4)),
    )
    scope = " [finite inputs]" if finite_only else " [all bit patterns]"
    print(("EQUIVALENT" if model is None else "NOT_EQUIVALENT") + f": {symbol}{scope}")
    if model is not None:
        print("  counterexample bits: " + ", ".join(f"0x{x:08x}" for x in model))
    return model is None


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
    outcomes = (
        prove_vector_copy(args),
        prove_component_hit_test(args),
        prove_rotational_limit(args),
        prove_component_hit_test(args, finite_only=True),
        prove_rotational_limit(args, finite_only=True),
    )
    print(f"LIVE_FP_SAMPLE_RESULT: {sum(outcomes)}/{len(outcomes)} checks equivalent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
