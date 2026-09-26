"""Run the relational prototype on a real PE/PDB/COFF function pair."""

from __future__ import annotations

import argparse
from pathlib import Path

import claripy

from angr_equiv import CallTarget, counterexample, execute
from live_extract import execution_metadata, extract, pdb_call_target


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--pdb", type=Path, required=True)
    parser.add_argument("--exe", type=Path, required=True)
    args = parser.parse_args()

    symbol = "?BG_IsWeaponUsableInState@@YA_NPBUplayerState_s@@I@Z"
    pair = extract(
        args.repository.resolve(), args.build.resolve(), args.pdb.resolve(),
        args.exe.resolve(), symbol,
    )

    player_address = 0x300000
    weapon_definition_address = 0x400000
    weapon_index = claripy.BVS("live_weapon_index", 32, explicit_name=True)
    player_flags = claripy.BVS("live_player_flags", 32, explicit_name=True)
    weapon_flag = claripy.BVS("live_weapon_flag", 8, explicit_name=True)

    callee, _ = pdb_call_target(
        pair, 0x4256E0, "?BG_GetWeaponDef@@YAPAUWeaponDef@@I@Z",
        fresh_result=False,
    )
    arguments = (claripy.BVV(player_address, 32), weapon_index)
    call_result = (claripy.BVV(weapon_definition_address, 32),)
    initial_memory = (
        (player_address + 0xC, player_flags),
        (weapon_definition_address + 0x66F, weapon_flag),
    )

    reference = execute(
        pair["reference"], arguments, (callee,), call_result, initial_memory,
        base=pair["address"], **execution_metadata(pair),
    )
    candidate = execute(
        pair["candidate"], arguments, (callee,), call_result, initial_memory,
        base=pair["address"], **execution_metadata(pair),
    )
    inputs = (weapon_index, player_flags, weapon_flag)
    model = counterexample(reference, candidate, inputs, return_bits=8)
    if model is not None:
        print(f"NOT_EQUIVALENT: live pair produced {model}")
        return 1
    print(f"EQUIVALENT: {symbol}")

    # Negative control: change the final `and eax, 1` into `and eax, 0`.
    wrong = bytearray(pair["candidate"])
    marker = wrong.rfind(bytes.fromhex("83e001"))
    if marker < 0:
        raise RuntimeError("negative-control instruction not found")
    wrong[marker + 2] = 0
    broken = execute(
        bytes(wrong), arguments, (callee,), call_result, initial_memory,
        base=pair["address"], **execution_metadata(pair),
    )
    model = counterexample(reference, broken, inputs, return_bits=8)
    if model is None:
        print("FAILED_NEGATIVE_CONTROL: mutation was accepted")
        return 1
    print(
        "NOT_EQUIVALENT: negative control "
        f"weapon_index=0x{model[0]:08x} player_flags=0x{model[1]:08x} "
        f"weapon_flag=0x{model[2]:02x}"
    )
    print("LIVE_PROTOTYPE_RESULT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
