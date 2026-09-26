"""Check a documented private-stack-slot flaky function from live artifacts."""

from __future__ import annotations

import argparse
from pathlib import Path
import struct

import claripy

from angr_equiv import CallTarget, counterexample, execute
from live_extract import execution_metadata, extract


def bits32(value: float) -> claripy.ast.BV:
    return claripy.BVV(struct.unpack("<I", struct.pack("<f", value))[0], 32)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--pdb", type=Path, required=True)
    parser.add_argument("--exe", type=Path, required=True)
    args = parser.parse_args()

    symbol = "?UI_MouseEvent@@YAXHHH@Z"
    pair = extract(
        args.repository.resolve(), args.build.resolve(), args.pdb.resolve(),
        args.exe.resolve(), symbol,
    )

    x = claripy.BVS("mouse_x", 32, explicit_name=True)
    y = claripy.BVS("mouse_y", 32, explicit_name=True)
    milliseconds = claripy.BVS("mouse_milliseconds", 32, explicit_name=True)
    menu_count = claripy.BVS("mouse_menu_count", 32, explicit_name=True)
    move_result = claripy.BVS("mouse_move_result", 32, explicit_name=True)
    placement_address = 0x300000
    ui_context = 0x73EAD50

    calls = (
        CallTarget(
            0x4CCE80, "?ScrPlace_GetFullPlacement@@YAPBUScreenPlacement@@XZ", 0,
            fresh_result=False,
        ),
        CallTarget(0x64E140, "_MyAssertHandler", 6),
        CallTarget(0x6877B0, "?Sys_Milliseconds@@YAHXZ", 0),
        CallTarget(0x498850, "?CL_ShowSystemCursor@@YAXH@Z", 1),
        CallTarget(0x63D710, "?Menu_Count@@YAHPAUUiContext@@@Z", 1),
        CallTarget(0x6421B0, "?Display_MouseMove@@YAHPAUUiContext@@@Z", 1),
    )
    call_results = (
        claripy.BVV(placement_address, 32),
        claripy.BVS("mouse_assert_result", 32, explicit_name=True),
        milliseconds,
        claripy.BVS("mouse_cursor_result", 32, explicit_name=True),
        menu_count,
        move_result,
    )

    image = pair["matcher"].PEImage(args.exe.resolve())
    image_base = image.image_base
    float_limit = int.from_bytes(image.read(0x82BB04 - image_base, 4), "little")
    double_limit = int.from_bytes(image.read(0x841960 - image_base, 8), "little")

    initial_memory = (
        (placement_address + 8, bits32(640.0)),
        (placement_address + 12, bits32(480.0)),
        (ui_context + 0x10, bits32(0.25)),
        (ui_context + 0x14, bits32(0.5)),
        (ui_context + 0x18, claripy.BVS("mouse_old_time", 32, explicit_name=True)),
        (ui_context + 0x1C, claripy.BVS("mouse_old_cursor", 32, explicit_name=True)),
        (0x82BB04, claripy.BVV(float_limit, 32)),
        (0x841960, claripy.BVV(double_limit, 64)),
    )
    observed_memory = tuple((ui_context + offset, 4) for offset in (0x10, 0x14, 0x18, 0x1C))
    arguments = (claripy.BVV(0, 32), x, y)

    reference = execute(
        pair["reference"], arguments, calls, call_results, initial_memory,
        base=pair["address"], **execution_metadata(pair),
    )
    candidate = execute(
        pair["candidate"], arguments, calls, call_results, initial_memory,
        base=pair["address"], **execution_metadata(pair),
    )
    inputs = (x, y, milliseconds, menu_count, move_result)
    model = counterexample(
        reference, candidate, inputs, observed_memory=observed_memory,
        compare_return=False,
    )
    if model is not None:
        print(f"NOT_EQUIVALENT: documented stack-slot flaky pair produced {model}")
        return 1
    print(f"EQUIVALENT: {symbol}")
    print("STACK_FLAKY_PROTOTYPE_RESULT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
