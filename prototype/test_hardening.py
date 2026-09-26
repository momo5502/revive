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
from alias_model import PointerGlobal, alias_scenarios
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
        self.assertIn((0x300000, 0x300000), partitions)
        self.assertIn((0, 0), partitions)

    def test_alias_model_includes_pointer_valued_global(self) -> None:
        signature = ABISignature(0x2004, "NearC", self.integer(), ())
        root = PointerGlobal("global_ptr", 0x220000, 4)
        cases = alias_scenarios(signature, pointer_globals=(root,))
        self.assertEqual(2, len(cases))
        values = {
            case.initial_memory[-1][1].concrete_value for case in cases
        }
        self.assertEqual({0, 0x300000}, values)

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

    def test_unmodeled_external_read_is_not_equivalent(self) -> None:
        code = bytes.fromhex("a100002000c3")
        reference = execute(code, ())
        candidate = execute(code, ())
        result = verify_equivalence(reference, candidate, ())
        self.assertEqual(VerificationStatus.MODEL_INCOMPLETE, result.status)
        self.assertIn("UNMODELED_EXTERNAL_READ", result.reasons)

    def test_bounded_symbolic_table_range_is_discovered(self) -> None:
        index = claripy.BVS("bounded_index", 32, explicit_name=True)
        code = bytes.fromhex("8b442404 83e003 8b048500002000 c3")
        execution = execute(code, (index,))
        self.assertEqual(
            ((0x200000, 16),),
            bounded_external_regions((execution,)),
        )

    def test_unmodeled_external_write_is_not_equivalent(self) -> None:
        code = bytes.fromhex("a300002000c3")
        reference = execute(code, ())
        candidate = execute(code, ())
        result = verify_equivalence(reference, candidate, ())
        self.assertEqual(VerificationStatus.MODEL_INCOMPLETE, result.status)
        self.assertIn("UNMODELED_EXTERNAL_WRITE", result.reasons)

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


if __name__ == "__main__":
    unittest.main()
