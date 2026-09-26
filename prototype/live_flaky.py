"""Check a documented flaky register-allocation function from live artifacts."""

from __future__ import annotations

import argparse
from pathlib import Path

import claripy

from angr_equiv import CallTarget, counterexample, execute
from live_extract import execution_metadata, extract


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--pdb", type=Path, required=True)
    parser.add_argument("--exe", type=Path, required=True)
    args = parser.parse_args()

    symbol = "?GetVariableKeyObject@@YAIII@Z"
    pair = extract(
        args.repository.resolve(), args.build.resolve(), args.pdb.resolve(),
        args.exe.resolve(), symbol,
    )

    parent_id = claripy.BVS("flaky_parent_id", 32, explicit_name=True)
    child_id = claripy.BVS("flaky_child_id", 32, explicit_name=True)
    variable_entry = claripy.BVS("flaky_variable_entry", 32, explicit_name=True)
    entry_address = claripy.BVV(0x2D67288, 32) + ((parent_id + child_id) << 4)

    assertion = CallTarget(0x64E140, "_MyAssertHandler", 5)
    assertion_result = claripy.BVS("flaky_assert_result", 32, explicit_name=True)
    arguments = (parent_id, child_id)
    initial_memory = ((entry_address, variable_entry),)

    reference = execute(
        pair["reference"], arguments, (assertion,), (assertion_result,),
        initial_memory, base=pair["address"], **execution_metadata(pair),
    )
    candidate = execute(
        pair["candidate"], arguments, (assertion,), (assertion_result,),
        initial_memory, base=pair["address"], **execution_metadata(pair),
    )
    inputs = (parent_id, child_id, variable_entry)
    model = counterexample(reference, candidate, inputs)
    if model is not None:
        print(f"NOT_EQUIVALENT: documented flaky pair produced {model}")
        return 1
    print(f"EQUIVALENT: {symbol}")

    # Negative control: change the returned object-index bias by one.
    wrong = bytearray(pair["candidate"])
    marker = wrong.rfind(bytes.fromhex("2d00000100"))
    if marker < 0:
        raise RuntimeError("negative-control subtraction not found")
    wrong[marker + 1] = 1
    broken = execute(
        bytes(wrong), arguments, (assertion,), (assertion_result,),
        initial_memory, base=pair["address"], **execution_metadata(pair),
    )
    model = counterexample(reference, broken, inputs)
    if model is None:
        print("FAILED_NEGATIVE_CONTROL: mutation was accepted")
        return 1
    print(
        "NOT_EQUIVALENT: negative control "
        f"parent=0x{model[0]:08x} child=0x{model[1]:08x} "
        f"entry=0x{model[2]:08x}"
    )
    print("FLAKY_PROTOTYPE_RESULT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
