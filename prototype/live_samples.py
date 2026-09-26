"""Exercise several small, currently inexact functions from live artifacts."""

from __future__ import annotations

import argparse
from pathlib import Path

import claripy

from angr_equiv import CallTarget, counterexample, execute
from live_extract import execution_metadata, extract


def prove_session_failure(args: argparse.Namespace) -> bool:
    symbol = "?IWNet_HandleSessionUpdateFailure@@YA_NPAUIWNetCommandData@@PAUmsg_t@@@Z"
    pair = extract(args.repository, args.build, args.pdb, args.exe, symbol)
    command, session = 0x300000, 0x310000
    old_status = claripy.BVS("session_failure_old_status", 32, explicit_name=True)
    message = claripy.BVS("session_failure_message", 32, explicit_name=True)
    memory = (
        (command + 0xC, claripy.BVV(session, 32)),
        (session + 0x10, old_status),
    )
    arguments = (claripy.BVV(command, 32), message)
    reference = execute(pair["reference"], arguments, initial_memory=memory,
                        base=pair["address"], **execution_metadata(pair))
    candidate = execute(pair["candidate"], arguments, initial_memory=memory,
                        base=pair["address"], **execution_metadata(pair))
    model = counterexample(
        reference, candidate, (message, old_status),
        observed_memory=((session + 0x10, 4),), return_bits=8,
    )
    print(("EQUIVALENT" if model is None else "NOT_EQUIVALENT") + f": {symbol}")
    return model is None


def prove_storage_write(args: argparse.Namespace) -> bool:
    selector = "@iwnet/iwnet_storage.cpp:0x308ec0:0xd18"
    pair = extract(args.repository, args.build, args.pdb, args.exe, selector)
    command, transfer, dvar = 0x300000, 0x310000, 0x320000
    flag = claripy.BVS("storage_infinite_flag", 8, explicit_name=True)
    position = claripy.BVS("storage_position", 32, explicit_name=True)
    limit = claripy.BVS("storage_limit", 32, explicit_name=True)
    memory = (
        (0x78B37E8, claripy.BVV(dvar, 32)),
        (dvar + 0x10, flag),
        (command + 0xC, claripy.BVV(transfer, 32)),
        (transfer + 0x48, limit),
        (transfer + 0x58, position),
    )
    # The second msg_t* parameter is unused by this implementation but remains
    # part of the authoritative PDB ABI.
    arguments = (claripy.BVV(command, 32), claripy.BVV(0x330000, 32))
    result = claripy.BVS("storage_next_write_result", 32, explicit_name=True)
    reference_call = CallTarget(
        0x708D80, "?IWNet_Storage_UtilNextWrite@@YAXPAUIWNetCommandData@@@Z",
        0, ("edi",), havoc_memory=False,
    )
    candidate_call = CallTarget(
        0x708D80, "?IWNet_Storage_UtilNextWrite@@YAXPAUIWNetCommandData@@@Z",
        0, ("ebx",), havoc_memory=False,
    )
    reference = execute(
        pair["reference"], arguments, (reference_call,), (result,), memory,
        base=pair["address"], **execution_metadata(pair),
    )
    candidate = execute(
        pair["candidate"], arguments, (candidate_call,), (result,), memory,
        base=pair["address"], **execution_metadata(pair),
    )
    model = counterexample(
        reference, candidate, (flag, position, limit),
        observed_memory=((transfer + 0x58, 4),), compare_return=False,
    )
    print(("EQUIVALENT" if model is None else "NOT_EQUIVALENT") + f": {selector}")
    return model is None


def prove_nonce_success(args: argparse.Namespace) -> bool:
    symbol = "?IWNet_HandleCreateNonceSuccess@@YA_NPAUIWNetCommandData@@PAUmsg_t@@@Z"
    pair = extract(args.repository, args.build, args.pdb, args.exe, symbol)
    command, session, message = 0x300000, 0x310000, 0x320000
    controller = claripy.BVS("nonce_controller", 32, explicit_name=True)
    session_type = claripy.BVS("nonce_session_type", 32, explicit_name=True)
    old_status = claripy.BVS("nonce_old_status", 32, explicit_name=True)
    nonce = claripy.BVS("nonce_value", 32, explicit_name=True)
    created = claripy.BVS("nonce_created", 32, explicit_name=True)
    error_result = claripy.BVS("nonce_error_result", 32, explicit_name=True)
    memory = (
        (command + 0xC, claripy.BVV(session, 32)),
        (command + 0x1C, controller),
        (command + 0x20, session_type),
        (session + 0x10, old_status),
    )
    calls = (
        CallTarget(0x5AEFD0, "?MSG_ReadLong@@YAHPAUmsg_t@@@Z", 1, havoc_memory=False),
        CallTarget(
            0x707770, "?IWNet_CreateSession_Internal@@YA_NHHPAUSessionData@@H@Z",
            4, havoc_memory=False,
        ),
        CallTarget(
            0x5A0710, "?Com_Error@@YAXW4errorParm_t@@PBDZZ",
            2, havoc_memory=False,
        ),
    )
    results = (nonce, created, error_result)
    arguments = (claripy.BVV(command, 32), claripy.BVV(message, 32))
    reference = execute(
        pair["reference"], arguments, calls, results, memory,
        base=pair["address"], **execution_metadata(pair),
    )
    candidate = execute(
        pair["candidate"], arguments, calls, results, memory,
        base=pair["address"], **execution_metadata(pair),
    )
    inputs = (controller, session_type, old_status, nonce, created)
    model = counterexample(
        reference, candidate, inputs,
        observed_memory=((session + 0x10, 4),), return_bits=8,
    )
    print(("EQUIVALENT" if model is None else "NOT_EQUIVALENT") + f": {symbol}")
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
        prove_session_failure(args),
        prove_storage_write(args),
        prove_nonce_success(args),
    )
    print("LIVE_SAMPLE_RESULT: " + ("PASS" if all(outcomes) else "FAIL"))
    return 0 if all(outcomes) else 1


if __name__ == "__main__":
    raise SystemExit(main())
