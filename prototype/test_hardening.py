from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path

import claripy

from angr_equiv import (
    BASE,
    CallTarget,
    LogicalAllocation,
    STACK_BASE,
    VerificationStatus,
    bounded_external_regions,
    execute,
    rel32,
    verify_equivalence,
    verify_under_pdb_aliasing,
)
from alias_model import ALLOCATION_BASE, PointerGlobal, alias_scenarios
from pdb_frontend import ABISignature, ABIType
from proof_record import ProofRecord, proof_fingerprint, read_record, write_record


def many_paths() -> bytes:
    code = bytearray.fromhex("8b442404")
    for bit in range(6):
        code += b"\xa9" + struct.pack("<I", 1 << bit)
        code += bytes.fromhex("7401 90")
    code += b"\xc3"
    return bytes(code)


class HardeningTests(unittest.TestCase):
    @staticmethod
    def integer(index: int = 0x75) -> ABIType:
        return ABIType(index, "unsigned int", 4, "integer")

    @staticmethod
    def pointer(index: int, restrict: bool = False) -> ABIType:
        return ABIType(index, "int*", 4, "pointer", restrict=restrict, pointee_size=4)

    def test_incoming_register_state_is_shared(self) -> None:
        # RET exposes the incoming EAX value.  Independently generated
        # unconstrained registers make even these identical blobs look
        # different, so this is also a determinism regression test.
        reference = execute(bytes.fromhex("c3"), ())
        candidate = execute(bytes.fromhex("c3"), ())
        result = verify_equivalence(reference, candidate, ())
        self.assertEqual(VerificationStatus.EQUIVALENT, result.status)

    def test_pdb_fastcall_signature_places_register_arguments(self) -> None:
        signature = ABISignature(
            0x2000, "NearFast", self.integer(),
            (self.integer(), self.integer()),
        )
        left = claripy.BVS("fastcall_left", 32, explicit_name=True)
        right = claripy.BVS("fastcall_right", 32, explicit_name=True)
        code = bytes.fromhex("8bc1 03c2 c3")
        reference = execute(code, (left, right), signature=signature)
        candidate = execute(code, (left, right), signature=signature)
        self.assertTrue(reference.states[0].solver.is_true(
            reference.states[0].regs.eax == left + right
        ))
        self.assertEqual(
            VerificationStatus.EQUIVALENT,
            verify_equivalence(reference, candidate, (left, right)).status,
        )

    def test_alias_model_enumerates_null_alias_and_order_cases(self) -> None:
        signature = ABISignature(
            0x2001, "NearC", self.integer(),
            (self.pointer(0x2100), self.pointer(0x2101)),
        )
        cases = alias_scenarios(signature)
        self.assertEqual(6, len(cases))
        partitions = {case.pointer_partition for case in cases}
        self.assertIn((ALLOCATION_BASE, ALLOCATION_BASE), partitions)
        self.assertIn((0, 0), partitions)

    def test_alias_model_includes_pointer_valued_global(self) -> None:
        signature = ABISignature(0x2004, "NearC", self.integer(), ())
        root = PointerGlobal("global_ptr", 0x220000, 4)
        cases = alias_scenarios(signature, pointer_globals=(root,))
        self.assertEqual(2, len(cases))
        values = {
            case.initial_memory[-1][1].concrete_value for case in cases
        }
        self.assertEqual({0, ALLOCATION_BASE}, values)

    def test_pointer_argument_can_alias_pointer_global_pointee(self) -> None:
        signature = ABISignature(
            0x2005, "NearC", self.integer(), (self.pointer(0x2202),),
        )
        root = PointerGlobal("global_ptr", 0x220000, 4)
        cases = alias_scenarios(signature, pointer_globals=(root,))
        self.assertTrue(any(
            case.arguments[0].concrete_value ==
            case.initial_memory[-1][1].concrete_value != 0
            for case in cases
        ))

    def test_integrated_alias_proof_checks_every_case(self) -> None:
        signature = ABISignature(
            0x2002, "NearC", self.integer(),
            (self.pointer(0x2200), self.pointer(0x2201)),
        )
        # Return p == q. This observes nullability and every alias partition
        # without dereferencing an otherwise unconstrained null pointer.
        code = bytes.fromhex("8b442404 3b442408 0f94c0 0fb6c0 c3")
        result = verify_under_pdb_aliasing(code, code, signature)
        self.assertEqual(VerificationStatus.EQUIVALENT, result.status)

    def test_escaped_stack_allocation_is_compared_logically(self) -> None:
        target = BASE + 0x100
        reference_code = (
            bytes.fromhex("83ec08 8d442404 50 e8") + rel32(BASE + 8, target) +
            bytes.fromhex("83c404 83c408 c3")
        )
        candidate_code = (
            bytes.fromhex("83ec0c 8d442404 50 e8") + rel32(BASE + 8, target) +
            bytes.fromhex("83c404 83c40c c3")
        )
        call = CallTarget(
            target, "?consume@@YAXPAH@Z", 1, fresh_result=False,
            havoc_memory=False, argument_pointer_mask=(True,),
            argument_pointee_sizes=(4,),
        )
        result = claripy.BVV(0, 32)
        reference = execute(
            reference_code, (), (call,), (result,),
            stack_allocations=(LogicalAllocation("temporary", STACK_BASE - 4, 4),),
        )
        candidate = execute(
            candidate_code, (), (call,), (result,),
            stack_allocations=(LogicalAllocation("temporary", STACK_BASE - 8, 4),),
        )
        self.assertEqual(
            VerificationStatus.EQUIVALENT,
            verify_equivalence(reference, candidate, (), compare_return=False).status,
        )

    def test_escaped_stack_return_is_compared_logically(self) -> None:
        reference_code = bytes.fromhex("83ec08 8d442404 83c408 c3")
        candidate_code = bytes.fromhex("83ec0c 8d442404 83c40c c3")
        reference = execute(
            reference_code, (),
            stack_allocations=(LogicalAllocation("return-object", STACK_BASE - 4, 4),),
        )
        candidate = execute(
            candidate_code, (),
            stack_allocations=(LogicalAllocation("return-object", STACK_BASE - 8, 4),),
        )
        self.assertEqual(
            VerificationStatus.EQUIVALENT,
            verify_equivalence(reference, candidate, (), return_pointer=True).status,
        )

    def test_pdb_64_bit_return_compares_edx_eax(self) -> None:
        wide = ABIType(0x13, "long long", 8, "integer")
        signature = ABISignature(0x2003, "NearC", wide, ())
        reference = execute(
            bytes.fromhex("b801000000 ba02000000 c3"), (), signature=signature,
        )
        candidate = execute(
            bytes.fromhex("b801000000 ba03000000 c3"), (), signature=signature,
        )
        self.assertEqual(
            VerificationStatus.NOT_EQUIVALENT,
            verify_equivalence(reference, candidate, ()).status,
        )

    def test_frontend_unsupported_issue_is_propagated(self) -> None:
        reference = execute(bytes.fromhex("c3"), (), frontend_issues=("UNSUPPORTED_VOLATILE_LOCAL",))
        candidate = execute(bytes.fromhex("c3"), (), frontend_issues=("UNSUPPORTED_VOLATILE_LOCAL",))
        self.assertEqual(
            VerificationStatus.UNSUPPORTED,
            verify_equivalence(reference, candidate, ()).status,
        )

    def test_seh_chain_access_is_unsupported(self) -> None:
        code = bytes.fromhex("64a100000000c3")
        result = verify_equivalence(execute(code, ()), execute(code, ()), ())
        self.assertEqual(VerificationStatus.UNSUPPORTED, result.status)


    def test_execution_does_not_silently_cap_terminal_paths(self) -> None:
        value = claripy.BVS("many_paths_value", 32, explicit_name=True)
        result = execute(many_paths(), (value,))
        self.assertTrue(result.complete, result.issues)
        self.assertEqual(64, len(result.states))

    def test_undeclared_global_is_modeled_by_address(self) -> None:
        # A named global resolves to the same address on both sides; its bytes
        # are shared, address-named values without being declared.
        read_global = bytes.fromhex("a100002000c3")
        same = verify_equivalence(execute(read_global, ()), execute(read_global, ()), ())
        self.assertEqual(VerificationStatus.EQUIVALENT, same.status, same.reasons)
        other_global = bytes.fromhex("a104002000c3")
        different = verify_equivalence(execute(read_global, ()), execute(other_global, ()), ())
        self.assertEqual(VerificationStatus.NOT_EQUIVALENT, different.status)

    def test_access_through_unconstrained_pointer_is_model_incomplete(self) -> None:
        code = bytes.fromhex("8b442404 8b00 c3")
        value = claripy.BVS("unconstrained_pointer", 32, explicit_name=True)
        result = verify_equivalence(execute(code, (value,)), execute(code, (value,)), (value,))
        self.assertEqual(VerificationStatus.MODEL_INCOMPLETE, result.status)
        self.assertIn("UNMODELED_POINTER_ACCESS", result.reasons)

    def test_bounded_symbolic_table_range_is_discovered(self) -> None:
        index = claripy.BVS("bounded_index", 32, explicit_name=True)
        code = bytes.fromhex("8b442404 83e003 8b048500002000 c3")
        execution = execute(code, (index,))
        self.assertEqual(
            ((0x200000, 16),),
            bounded_external_regions((execution,)),
        )

    def test_undeclared_global_writes_are_observed(self) -> None:
        one = bytes.fromhex("c70500002000 01000000 c3")
        two = bytes.fromhex("c70500002000 02000000 c3")
        same = verify_equivalence(execute(one, ()), execute(one, ()), ())
        self.assertEqual(VerificationStatus.EQUIVALENT, same.status, same.reasons)
        different = verify_equivalence(execute(one, ()), execute(two, ()), ())
        self.assertEqual(VerificationStatus.NOT_EQUIVALENT, different.status)
        # A write the other side does not make is observed against the
        # shared untouched value, and snapshotted at calls.
        missing = verify_equivalence(execute(one, ()), execute(bytes.fromhex("c3"), ()), ())
        self.assertEqual(VerificationStatus.NOT_EQUIVALENT, missing.status)

    def test_nontermination_is_inconclusive(self) -> None:
        value = claripy.BVS("loop_value", 32, explicit_name=True)
        code = bytes.fromhex("8b442404 85c0 7402 ebfe c3")
        reference = execute(code, (value,), maximum_steps=20, timeout_seconds=None)
        candidate = execute(code, (value,), maximum_steps=20, timeout_seconds=None)
        result = verify_equivalence(reference, candidate, (value,))
        self.assertEqual(VerificationStatus.INCONCLUSIVE, result.status)
        self.assertIn("STEP_LIMIT_REACHED", result.reasons)

    def test_unmodeled_call_target_is_inconclusive(self) -> None:
        target = BASE + 0x100
        code = b"\xe8" + rel32(BASE, target) + b"\xc3"
        reference = execute(code, ())
        candidate = execute(code, ())
        result = verify_equivalence(reference, candidate, ())
        self.assertEqual(VerificationStatus.MODEL_INCOMPLETE, result.status)
        self.assertTrue(any(reason.startswith("UNMODELED_CONTROL_TARGET") for reason in result.reasons))

    def test_atomic_instruction_is_unsupported(self) -> None:
        code = bytes.fromhex("f0ff0500002000c3")
        reference = execute(code, ())
        candidate = execute(code, ())
        result = verify_equivalence(reference, candidate, ())
        self.assertEqual(VerificationStatus.UNSUPPORTED, result.status)
        self.assertTrue(any(reason.startswith("UNSUPPORTED_ATOMIC") for reason in result.reasons))

    def test_fp_environment_instruction_is_modeled(self) -> None:
        code = bytes.fromhex("d92d00002000c3")
        control = ((0x200000, claripy.BVV(0x0400, 16)),)
        reference = execute(code, (), initial_memory=control)
        candidate = execute(bytes.fromhex("c3"), (), initial_memory=control)
        result = verify_equivalence(reference, candidate, ())
        self.assertEqual(VerificationStatus.NOT_EQUIVALENT, result.status)

    def test_repeated_calls_receive_distinct_shared_results(self) -> None:
        target = BASE + 0x100
        first_call = BASE
        second_call = BASE + 5
        code = (
            b"\xe8" + rel32(first_call, target) +
            b"\xe8" + rel32(second_call, target) + b"\xc3"
        )
        call = CallTarget(target, "?stateful@@YAHXZ", 0, fresh_result=True)
        placeholder = claripy.BVS("placeholder", 32, explicit_name=True)
        reference = execute(code, (), (call,), (placeholder,))
        candidate = execute(code, (), (call,), (placeholder,))
        self.assertTrue(reference.complete, reference.issues)
        left_calls = reference.states[0].globals["calls"]
        self.assertEqual(2, len(left_calls))
        self.assertFalse(reference.states[0].regs.eax.structurally_match(placeholder))
        self.assertTrue(
            reference.states[0].regs.eax.structurally_match(candidate.states[0].regs.eax)
        )

    def test_proof_record_invalidates_on_any_code_change(self) -> None:
        original = proof_fingerprint(
            symbol="?f@@YAHH@Z", reference=b"\xc3", candidate=b"\xc3",
            signature={"return": "int", "arguments": ["int"]},
            memory_model={"regions": []}, options={"return_bits": 32},
        )
        changed = proof_fingerprint(
            symbol="?f@@YAHH@Z", reference=b"\xc3", candidate=b"\x90\xc3",
            signature={"return": "int", "arguments": ["int"]},
            memory_model={"regions": []}, options={"return_bits": 32},
        )
        self.assertNotEqual(original, changed)
        result = verify_equivalence(
            execute(bytes.fromhex("31c0c3"), ()),
            execute(bytes.fromhex("31c0c3"), ()), (),
        )
        record = ProofRecord.create("?f@@YAHH@Z", original, result)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "proof.json"
            write_record(path, record)
            loaded = read_record(path)
        self.assertTrue(loaded.matches(original))
        self.assertFalse(loaded.matches(changed))

    def test_x87_return_value_is_observable(self) -> None:
        one = execute(bytes.fromhex("d9e8c3"), ())
        zero = execute(bytes.fromhex("d9eec3"), ())
        result = verify_equivalence(
            one, zero, (), return_register="x87_st0",
        )
        self.assertEqual(VerificationStatus.NOT_EQUIVALENT, result.status)

    def test_external_call_can_return_through_x87_stack(self) -> None:
        target = BASE + 0x100
        code = b"\xe8" + rel32(BASE, target) + b"\xc3"
        placeholder = claripy.BVS("x87_call_placeholder", 64, explicit_name=True)
        call = CallTarget(
            target, "?float_call@@YAMXZ", 0, fresh_result=True,
            havoc_memory=False, return_register="x87_st0",
        )
        reference = execute(code, (), (call,), (placeholder,))
        candidate = execute(code, (), (call,), (placeholder,))
        result = verify_equivalence(
            reference, candidate, (), return_register="x87_st0",
        )
        self.assertEqual(VerificationStatus.EQUIVALENT, result.status)

    def test_external_call_can_return_through_edx_eax(self) -> None:
        target = BASE + 0x100
        code = b"\xe8" + rel32(BASE, target) + b"\xc3"
        placeholder = claripy.BVS("wide_call_placeholder", 64, explicit_name=True)
        signature = ABISignature(
            0, "NearC", ABIType(0, "__int64", 8, "integer"), (),
        )
        call = CallTarget(
            target, "__ftol2_sse", 0, fresh_result=True,
            havoc_memory=False, return_register="edx_eax", signature=signature,
        )
        reference = execute(code, (), (call,), (placeholder,))
        candidate = execute(code, (), (call,), (placeholder,))
        result = verify_equivalence(
            reference, candidate, (), return_register="edx_eax",
        )
        self.assertEqual(VerificationStatus.EQUIVALENT, result.status)

    def test_fsin_is_a_shared_semantic_operation(self) -> None:
        code = bytes.fromhex("d9fe c3")
        reference = execute(code, ())
        candidate = execute(code, ())
        self.assertTrue(reference.complete, reference.issues)
        self.assertTrue(candidate.complete, candidate.issues)
        result = verify_equivalence(
            reference, candidate, (), return_register="x87_st0",
        )
        self.assertEqual(VerificationStatus.EQUIVALENT, result.status)

    def test_indirect_call_compares_target_and_arguments(self) -> None:
        reference_code = bytes.fromhex("6a07 b800002000 ffd0 c3")
        candidate_code = bytes.fromhex("6a07 b804002000 ffd0 c3")
        same = verify_equivalence(
            execute(reference_code, ()), execute(reference_code, ()), (),
        )
        different = verify_equivalence(
            execute(reference_code, ()), execute(candidate_code, ()), (),
        )
        self.assertEqual(VerificationStatus.EQUIVALENT, same.status)
        self.assertEqual(VerificationStatus.NOT_EQUIVALENT, different.status)


def _call_code(prefix: str, target: int, suffix: str) -> bytes:
    head = bytes.fromhex(prefix + "e8")
    return head + rel32(BASE + len(head) - 1, target) + bytes.fromhex(suffix)


class ReviewRegressionTests(unittest.TestCase):
    """Defects found by the 2026-09-26 review, asserted as correct behavior."""

    INT = ABIType(0x74, "int", 4, "integer")
    VOID = ABIType(3, "void", 0, "void")

    def pair(self, reference: bytes, candidate: bytes, *, signature=None,
             arguments=(), **verify_options):
        return verify_equivalence(
            execute(reference, arguments, signature=signature),
            execute(candidate, arguments, signature=signature),
            arguments, **verify_options,
        )

    def test_x87_transcendentals_are_shared_semantic_operations(self) -> None:
        # FSINCOS, FCOS, FPTAN and FPATAN lower to VEX ops angr cannot run.
        for name, operation in (("fsincos", "d9fb"), ("fcos", "d9ff"),
                                ("fptan", "d9f2"), ("fpatan", "d9e8 d9f3")):
            with self.subTest(name):
                code = bytes.fromhex(f"d9e8 {operation} c3")
                result = self.pair(code, code, return_register="x87_st0")
                self.assertEqual(VerificationStatus.EQUIVALENT, result.status, result.reasons)
        different = self.pair(
            bytes.fromhex("d9e8 d9fe c3"), bytes.fromhex("d9e8 d9ff c3"),
            return_register="x87_st0",
        )
        self.assertEqual(VerificationStatus.NOT_EQUIVALENT, different.status)

    def test_fsincos_leaves_cosine_on_top_of_sine(self) -> None:
        # FSINCOS pushes: ST0 = cos(x), ST1 = sin(x).  Popping must expose sin.
        fsincos = bytes.fromhex("d9e8 d9fb ddd8 c3")
        fsin = bytes.fromhex("d9e8 d9fe c3")
        result = self.pair(fsincos, fsin, return_register="x87_st0")
        self.assertEqual(VerificationStatus.EQUIVALENT, result.status, result.reasons)

    def test_debugbreak_is_an_ordered_event_not_an_error(self) -> None:
        code = bytes.fromhex("cc c3")
        same = self.pair(code, code)
        self.assertEqual(VerificationStatus.EQUIVALENT, same.status, same.reasons)
        missing = self.pair(code, bytes.fromhex("c3"))
        self.assertEqual(VerificationStatus.NOT_EQUIVALENT, missing.status)

    def test_in_function_jump_table_survives_region_discovery(self) -> None:
        prefix = bytes.fromhex("8b442404 83e003 ff2485")
        cases_offset = len(prefix) + 4
        cases = b"".join(
            b"\xb8" + struct.pack("<I", 10 * index) + b"\xc3" for index in range(4)
        )
        table_offset = cases_offset + len(cases)
        code = (
            prefix + struct.pack("<I", BASE + table_offset) + cases +
            b"".join(struct.pack("<I", BASE + cases_offset + 6 * index) for index in range(4))
        )
        value = claripy.BVS("jump_table_value", 32, explicit_name=True)
        signature = ABISignature(0, "NearC", self.INT, (self.INT,))
        first = (execute(code, (value,), signature=signature),
                 execute(code, (value,), signature=signature))
        self.assertEqual((), bounded_external_regions(first))
        result = verify_equivalence(*first, (value,))
        self.assertEqual(VerificationStatus.EQUIVALENT, result.status, result.reasons)

    def test_callee_may_write_beyond_declared_pointee_size(self) -> None:
        # char buf[8] = {0}; fill(buf); return *(int *)(buf + 4);
        target = BASE + 0x100
        pointer = ABIType(0, "char *", 4, "pointer", pointee_size=1)
        call = CallTarget(
            target, "?fill@@YAXPAD@Z", 1,
            signature=ABISignature(0, "NearC", self.VOID, (pointer,)),
        )
        prefix = "83ec08 c7042400000000 c744240400000000 8d0424 50"
        reference = _call_code(prefix, target, "83c404 8b442404 83c408 c3")
        candidate = _call_code(prefix, target, "83c404 31c0 9090 83c408 c3")
        result_value = claripy.BVS("fill_result", 32, explicit_name=True)
        result = verify_equivalence(
            execute(reference, (), (call,), (result_value,)),
            execute(candidate, (), (call,), (result_value,)), (),
        )
        self.assertNotEqual(VerificationStatus.EQUIVALENT, result.status)

    def test_escaped_local_is_havocked_by_later_calls(self) -> None:
        # int x = 0; publish(&x); poke(); return x;  versus caching x in ESI.
        publish, poke = BASE + 0x100, BASE + 0x200
        pointer = ABIType(0, "int *", 4, "pointer", pointee_size=4)
        calls = (
            CallTarget(publish, "?publish@@YAXPAH@Z", 1,
                       signature=ABISignature(0, "NearC", self.VOID, (pointer,))),
            CallTarget(poke, "?poke@@YAXXZ", 0,
                       signature=ABISignature(0, "NearC", self.VOID, ())),
        )
        results = tuple(claripy.BVS(f"escape_result_{i}", 32, explicit_name=True) for i in range(2))
        head = bytes.fromhex("56 83ec04 c7042400000000 8d0424 50 e8")
        first = head + rel32(BASE + len(head) - 1, publish) + bytes.fromhex("83c404")
        reference_tail = bytes.fromhex("e8")
        reference = first + reference_tail + rel32(BASE + len(first), poke) + bytes.fromhex(
            "8b0424 83c404 5e c3")
        candidate_head = first + bytes.fromhex("8b3424 e8")
        candidate = candidate_head + rel32(BASE + len(candidate_head) - 1, poke) + bytes.fromhex(
            "89f0 83c404 5e c3")
        result = verify_equivalence(
            execute(reference, (), calls, results), execute(candidate, (), calls, results), (),
        )
        self.assertNotEqual(VerificationStatus.EQUIVALENT, result.status)

    def test_calls_clobber_caller_saved_registers(self) -> None:
        target = BASE + 0x100
        call = CallTarget(target, "?f@@YAXXZ", 0,
                          signature=ABISignature(0, "NearC", self.VOID, ()))
        result_value = claripy.BVS("clobber_result", 32, explicit_name=True)
        reference = _call_code("ba05000000", target, "b805000000 c3")
        candidate = _call_code("ba05000000", target, "89d0 909090 c3")
        result = verify_equivalence(
            execute(reference, (), (call,), (result_value,)),
            execute(candidate, (), (call,), (result_value,)), (),
        )
        self.assertNotEqual(VerificationStatus.EQUIVALENT, result.status)

    def test_indirect_call_register_arguments_are_not_ignored(self) -> None:
        # A virtual call on a different object must not be proved equivalent.
        result = self.pair(bytes.fromhex("b901000000 ffd0 c3"),
                           bytes.fromhex("b902000000 ffd0 c3"))
        self.assertNotEqual(VerificationStatus.EQUIVALENT, result.status)

    def test_caller_frame_is_not_private(self) -> None:
        result = self.pair(bytes.fromhex("c744244001000000 c3"),
                           bytes.fromhex("9090909090909090 c3"))
        self.assertNotEqual(VerificationStatus.EQUIVALENT, result.status)

    def test_incoming_argument_slots_are_callee_owned(self) -> None:
        signature = ABISignature(0, "NearC", self.VOID, (self.INT,))
        argument = claripy.BVS("owned_argument", 32, explicit_name=True)
        result = self.pair(bytes.fromhex("c744240401000000 c3"),
                           bytes.fromhex("9090909090909090 c3"),
                           signature=signature, arguments=(argument,))
        self.assertEqual(VerificationStatus.EQUIVALENT, result.status, result.reasons)

    def test_partial_pointer_overlap_is_a_case(self) -> None:
        # f(struct { int a, b; } *p, int *q) { p->b = 1; *q = 2; return p->b; }
        pair_pointer = ABIType(0x1001, "S *", 4, "pointer", pointee_size=8)
        int_pointer = ABIType(0x1002, "int *", 4, "pointer", pointee_size=4)
        signature = ABISignature(0, "NearC", self.INT, (pair_pointer, int_pointer))
        prefix = "8b4c2404 8b542408 c7410401000000 c70202000000"
        result = verify_under_pdb_aliasing(
            bytes.fromhex(prefix + "8b4104 c3"),
            bytes.fromhex(prefix + "b801000000 c3"), signature,
        )
        self.assertEqual(VerificationStatus.NOT_EQUIVALENT, result.status, result.reasons)

    def test_x87_condition_codes_are_not_observable(self) -> None:
        # fldz; fld1; fcompp leaves only stale C0-C3 bits behind.
        result = self.pair(bytes.fromhex("d9ee d9e8 ded9 c3"), bytes.fromhex("c3"))
        self.assertEqual(VerificationStatus.EQUIVALENT, result.status, result.reasons)

    def test_ftol2_sse_pops_its_argument(self) -> None:
        from live_extract import _untyped_call_target
        target = BASE + 0x100
        call = _untyped_call_target(target, "__ftol2_sse", [])
        placeholder = claripy.BVS("ftol_placeholder", 64, explicit_name=True)
        # fld1; fldz; call __ftol2_sse; ret  ->  1.0 remains in ST0.
        state = execute(_call_code("d9e8 d9ee", target, "c3"), (), (call,), (placeholder,)).states[0]
        self.assertTrue(state.solver.is_true((state.regs.ftop & 7) == 7))

    def test_cisqrt_replaces_its_argument(self) -> None:
        from live_extract import _untyped_call_target
        target = BASE + 0x100
        call = _untyped_call_target(target, "__CIsqrt", [])
        placeholder = claripy.BVS("sqrt_placeholder", 64, explicit_name=True)
        state = execute(_call_code("d9e8", target, "c3"), (), (call,), (placeholder,)).states[0]
        self.assertTrue(state.solver.is_true((state.regs.ftop & 7) == 7))

    def test_complex_type_index_is_never_a_simple_float(self) -> None:
        from pdb_frontend import _abi_type

        class Matcher:
            CLASS_LIKE_KINDS = frozenset({"LF_STRUCTURE", "LF_CLASS"})

            @staticmethod
            def simple_pointer_base(index):
                return None

            @staticmethod
            def type_size(db, index):
                return 12 if index == 0x1040 else 4

            @staticmethod
            def describe_type(db, index):
                return f"type{index:x}"

        class DB:
            @staticmethod
            def get(index):
                return {"Kind": "LF_STRUCTURE"} if index == 0x1040 else None

        self.assertEqual("aggregate", _abi_type(Matcher, DB, 0x1040).kind)

    def test_custom_entry_homes_are_per_side(self) -> None:
        # f(a, b) returns a - b. The reference receives a in EDX; the
        # candidate receives it in EAX. b is the first stack word on both.
        from pdb_frontend import ParameterHome
        signature = ABISignature(0, "NearC", self.INT, (self.INT, self.INT))
        a = claripy.BVS("custom_a", 32, explicit_name=True)
        b = claripy.BVS("custom_b", 32, explicit_name=True)
        reference = execute(
            bytes.fromhex("8bc2 2b442404 c3"), (a, b), signature=signature,
            entry_homes=(ParameterHome(("edx",)), ParameterHome((), 4)),
        )
        candidate = execute(
            bytes.fromhex("2b442404 c3"), (a, b), signature=signature,
            entry_homes=(ParameterHome(("eax",)), ParameterHome((), 4)),
        )
        result = verify_equivalence(reference, candidate, (a, b))
        self.assertEqual(VerificationStatus.EQUIVALENT, result.status, result.reasons)

    def test_ambiguous_entry_home_places_the_value_in_both(self) -> None:
        # Whichever ABI the body uses, it observes the same parameter.
        from pdb_frontend import ParameterHome
        signature = ABISignature(0, "NearC", self.INT, (self.INT,))
        a = claripy.BVS("ambiguous_a", 32, explicit_name=True)
        home = (ParameterHome(("eax",), 4),)
        from_register = execute(bytes.fromhex("c3"), (a,), signature=signature, entry_homes=home)
        from_stack = execute(bytes.fromhex("8b442404 c3"), (a,), signature=signature,
                             entry_homes=home)
        result = verify_equivalence(from_register, from_stack, (a,))
        self.assertEqual(VerificationStatus.EQUIVALENT, result.status, result.reasons)

    def test_standard_entry_homes_follow_the_declared_convention(self) -> None:
        from pdb_frontend import ParameterHome, standard_parameter_homes
        fastcall = ABISignature(0, "NearFast", self.INT, (self.INT, self.INT, self.INT))
        self.assertEqual(
            (ParameterHome(("ecx",)), ParameterHome(("edx",)), ParameterHome((), 4)),
            standard_parameter_homes(fastcall),
        )

    def test_parameter_homes_from_pdb_records(self) -> None:
        import pdb_frontend
        from pdb_frontend import ParameterHome

        pointer = ABIType(0x1633, "float *", 4, "pointer", pointee_size=4)
        state = ABIType(0x5B7E, "State *", 4, "pointer", pointee_size=8)
        signature = ABISignature(0, "NearC", self.VOID, (state, pointer, pointer))

        def homes(records: str, flags: str, prologue: bool = True):
            text = (
                "   100 | S_LPROC32 [size = 60] `f`\n"
                "         parent = 0, end = 200, addr = 0001:0, code size = 1\n"
                f"         type = `0x6010 (void ())`, debug start = 0, debug end = 1, flags = {flags}\n"
                + records + "   200 | S_END [size = 4]\n"
            )
            original = pdb_frontend._module_symbols
            pdb_frontend._module_symbols = lambda *_: text
            try:
                return pdb_frontend.recorded_parameter_homes(
                    None, Path("tool"), Path("pdb"), {"module": 1, "record_offset": 100},
                    signature, prologue,
                )
            finally:
                pdb_frontend._module_symbols = original

        register = "   110 | S_REGISTER [size = 16] `s`\n         register = EDX, type = 0x5B7E (State*)\n"
        stack8 = "   120 | S_BPREL32 [size = 20] `a`\n         type = 0x1633 (float*), offset = 8\n"
        stack12 = "   130 | S_BPREL32 [size = 20] `b`\n         type = 0x1633 (float*), offset = 12\n"
        stack16 = "   130 | S_BPREL32 [size = 20] `b`\n         type = 0x1633 (float*), offset = 16\n"
        # Custom: the first parameter is in EDX and the stack is packed.
        self.assertEqual(
            ((ParameterHome(("edx",)), ParameterHome((), 4), ParameterHome((), 8)), ()),
            homes(register + stack8 + stack12, "has fp"),
        )
        # Standard offsets: the register record is only where the body keeps it.
        self.assertEqual((None, ()), homes(register + stack12 + stack16, "has fp"))
        # Only stack records, even without a frame pointer: declared convention.
        self.assertEqual((None, ()), homes(stack8 + stack12, "none", prologue=False))
        # A leading register parameter without an EBP frame cannot be placed.
        result, issues = homes(register + stack8 + stack12, "none", prologue=False)
        self.assertIsNone(result)
        self.assertTrue(issues)

    def test_undeclared_large_object_ranges_are_discovered(self) -> None:
        # g is a large global that is not declared; only the touched ranges are.
        # g[0x1000] = x; f(); return g[0x2000];   versus writing g[0x1004].
        target = BASE + 0x200
        call = CallTarget(target, "?f@@YAXXZ", 0,
                          signature=ABISignature(0, "NearC", self.VOID, ()))
        results = (claripy.BVS("large_call", 32, explicit_name=True),)
        signature = ABISignature(0, "NearC", self.INT, (self.INT,))

        def code(offset: int) -> bytes:
            head = bytes.fromhex("8b442404 a3") + struct.pack("<I", 0x300000 + offset) + b"\xe8"
            return (head + rel32(BASE + len(head) - 1, target) +
                    b"\xa1" + struct.pack("<I", 0x302000) + b"\xc3")

        same = verify_under_pdb_aliasing(
            code(0x1000), code(0x1000), signature,
            reference_calls=(call,), candidate_calls=(call,), call_results=results,
        )
        self.assertEqual(VerificationStatus.EQUIVALENT, same.status, same.reasons)
        different = verify_under_pdb_aliasing(
            code(0x1000), code(0x1004), signature,
            reference_calls=(call,), candidate_calls=(call,), call_results=results,
        )
        self.assertEqual(VerificationStatus.NOT_EQUIVALENT, different.status, different.reasons)

    def test_alias_case_limit_is_enforced(self) -> None:
        pointer = ABIType(0x1002, "int *", 4, "pointer", pointee_size=4)
        signature = ABISignature(0, "NearC", self.INT, (pointer,) * 4)
        result = verify_under_pdb_aliasing(
            bytes.fromhex("c3"), bytes.fromhex("c3"), signature, maximum_cases=3,
        )
        self.assertEqual(VerificationStatus.MODEL_INCOMPLETE, result.status)
        self.assertTrue(result.reasons[0].startswith("ALIAS_MODEL_INCOMPLETE"))

    def test_pointerless_signature_uses_the_same_driver(self) -> None:
        signature = ABISignature(0, "NearC", self.INT, (self.INT,))
        result = verify_under_pdb_aliasing(
            bytes.fromhex("8b442404 40 c3"), bytes.fromhex("8b442404 83c001 c3"), signature,
        )
        self.assertEqual(VerificationStatus.EQUIVALENT, result.status, result.reasons)

    def test_pointer_may_lie_inside_a_referenced_global(self) -> None:
        # f(int *p) { g[1] = 1; *p = 2; return g[1]; }  versus  return 1.
        from alias_model import GlobalObject
        pointer = ABIType(0x1002, "int *", 4, "pointer", pointee_size=4)
        signature = ABISignature(0, "NearC", self.INT, (pointer,))
        prefix = "8b4c2404 c70504002000 01000000 c70102000000"
        global_memory = ((0x200000, claripy.BVS("interior_global", 64, explicit_name=True)),)
        result = verify_under_pdb_aliasing(
            bytes.fromhex(prefix + "a104002000 c3"),
            bytes.fromhex(prefix + "b801000000 c3"), signature,
            common_memory=global_memory, observed_memory=((0x200000, 8),),
            global_objects=(GlobalObject("g", 0x200000, 8),),
        )
        self.assertEqual(VerificationStatus.NOT_EQUIVALENT, result.status, result.reasons)

    def test_debugbreak_byte_inside_an_immediate_is_inert(self) -> None:
        same = self.pair(bytes.fromhex("b8cccccccc c3"), bytes.fromhex("b8cccccccc c3"))
        self.assertEqual(VerificationStatus.EQUIVALENT, same.status, same.reasons)
        different = self.pair(bytes.fromhex("b8cccccccc c3"), bytes.fromhex("b8cdcccccc c3"))
        self.assertEqual(VerificationStatus.NOT_EQUIVALENT, different.status)

    def test_unknown_call_identity_is_not_guessed_as_stdcall(self) -> None:
        from live_extract import _untyped_call_target
        contract = _untyped_call_target(0x401230, "address@00401230", [])
        self.assertTrue(contract.frontend_issues)


if __name__ == "__main__":
    unittest.main()
