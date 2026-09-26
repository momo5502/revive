"""Small relational-equivalence experiment using angr and Claripy.

This intentionally uses raw x86 blobs. It isolates the symbolic-equivalence
question from PDB, PE, and COFF extraction, which are independent frontend
work. Run with::

    .venv\\Scripts\\python.exe prototype\\angr_equiv.py
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import gc
import hashlib
import struct
import time

import angr
import capstone
import claripy
from angr.sim_type import (
    SimTypeBottom,
    SimTypeDouble,
    SimTypeFloat,
    SimTypeFunction,
    SimTypeNum,
    SimTypePointer,
)

from pdb_frontend import ABISignature, ABIType


BASE = 0x100000
RETURN_SENTINEL = 0xF0000000
STACK_BASE = 0x7FFF0000


@dataclass(frozen=True)
class CallTarget:
    address: int
    decorated_symbol: str
    argument_count: int = 1
    argument_registers: tuple[str, ...] = ()
    fresh_result: bool = True
    havoc_memory: bool = True
    return_register: str = "eax"
    argument_pointer_mask: tuple[bool, ...] = ()
    argument_pointee_sizes: tuple[int | None, ...] = ()
    signature: ABISignature | None = None
    frontend_issues: tuple[str, ...] = ()
    callsite_argument_counts: tuple[tuple[int, int], ...] = ()


@dataclass(frozen=True)
class LogicalAllocation:
    logical_id: str
    address: int
    size: int


@dataclass
class Execution:
    states: list[angr.SimState]
    complete: bool = True
    issues: tuple[str, ...] = ()
    initial_constraints: tuple[claripy.ast.Bool, ...] = ()
    readable_regions: tuple[tuple[object, int], ...] = ()
    signature: ABISignature | None = None
    stack_allocations: tuple[LogicalAllocation, ...] = ()


class VerificationStatus(str, Enum):
    EQUIVALENT = "EQUIVALENT"
    NOT_EQUIVALENT = "NOT_EQUIVALENT"
    INCONCLUSIVE = "INCONCLUSIVE"
    MODEL_INCOMPLETE = "MODEL_INCOMPLETE"
    UNSUPPORTED = "UNSUPPORTED"


@dataclass(frozen=True)
class VerificationResult:
    status: VerificationStatus
    counterexample: tuple[int, ...] | None = None
    reasons: tuple[str, ...] = ()


class IncompleteVerification(RuntimeError):
    pass


class RecordedCall(angr.SimProcedure):
    def __init__(self, decorated_symbol: str, result: claripy.ast.BV,
                 argument_count: int, argument_registers: tuple[str, ...],
                 fresh_result: bool, havoc_memory: bool,
                 memory_regions: tuple[tuple[object, int], ...],
                 return_register: str,
                 argument_pointer_mask: tuple[bool, ...],
                 argument_pointee_sizes: tuple[int | None, ...],
                 callsite_argument_counts: tuple[tuple[int, int], ...],
                 cc=None, prototype=None):
        super().__init__(num_args=argument_count, cc=cc, prototype=prototype)
        self.decorated_symbol = decorated_symbol
        self.result = result
        self.argument_registers = argument_registers
        self.fresh_result = fresh_result
        self.havoc_memory = havoc_memory
        self.memory_regions = memory_regions
        self.return_register = return_register
        self.argument_pointer_mask = argument_pointer_mask
        self.argument_pointee_sizes = argument_pointee_sizes
        self.callsite_argument_counts = dict(callsite_argument_counts)

    def run(self, *arguments):  # type: ignore[no-untyped-def]
        if self.argument_registers:
            arguments = tuple(
                x87_st0(self.state) if register == "x87_st0" else
                getattr(self.state.regs, register)
                for register in self.argument_registers
            )
        callsite = self.state.callstack.call_site_addr
        argument_count = self.callsite_argument_counts.get(callsite, len(arguments))
        arguments = arguments[:argument_count]
        calls = list(self.state.globals.get("calls", ()))
        ordinal = len(calls)
        snapshot = tuple(
            self.state.memory.load(address, size, endness=self.state.arch.memory_endness)
            for address, size in self.memory_regions
        )
        pointer_mask = (
            self.argument_pointer_mask[:argument_count]
            if self.argument_pointer_mask else tuple(False for _ in arguments)
        )
        pointee_sizes = (
            self.argument_pointee_sizes[:argument_count]
            if self.argument_pointee_sizes else tuple(None for _ in arguments)
        )
        if len(pointer_mask) != len(arguments) or len(pointee_sizes) != len(arguments):
            raise ValueError(f"call summary for {self.decorated_symbol} has inconsistent pointer metadata")
        argument_memory = tuple(
            self.state.memory.load(argument, size, endness=self.state.arch.memory_endness)
            if is_pointer and size else None
            for argument, is_pointer, size in zip(arguments, pointer_mask, pointee_sizes, strict=True)
        )
        calls.append((
            self.decorated_symbol, arguments, snapshot, pointer_mask,
            argument_memory,
        ))
        self.state.globals["calls"] = tuple(calls)
        digest = hashlib.sha256(self.decorated_symbol.encode("utf-8")).hexdigest()[:12]
        if self.havoc_memory:
            self.state.globals["inside_external_call"] = True
            for index, (address, size) in enumerate(self.memory_regions):
                value = claripy.BVS(
                    f"external_memory_{ordinal}_{index}_{digest}", size * 8,
                    explicit_name=True,
                )
                self.state.memory.store(address, value, endness=self.state.arch.memory_endness)
            for index, (argument, is_pointer, size) in enumerate(zip(
                    arguments, pointer_mask, pointee_sizes, strict=True)):
                if is_pointer and size:
                    value = claripy.BVS(
                        f"external_pointee_{ordinal}_{index}_{digest}", size * 8,
                        explicit_name=True,
                    )
                    self.state.memory.store(
                        argument, value, endness=self.state.arch.memory_endness,
                    )
            self.state.globals["inside_external_call"] = False
        if self.fresh_result:
            result = claripy.BVS(
                f"external_return_{ordinal}_{digest}", self.result.size(),
                explicit_name=True,
            )
        else:
            result = self.result
        if self.return_register == "eax":
            return result
        if self.return_register == "x87_st0":
            if result.size() != 64:
                raise ValueError("an x87 call summary requires a 64-bit VEX F64 result")
            new_top = (self.state.regs.ftop - 1) & 7
            for index in range(8):
                old_value = self.state.registers.load(72 + index * 8, 8)
                self.state.registers.store(
                    72 + index * 8,
                    claripy.If(new_top == index, result, old_value),
                )
            self.state.regs.ftop = new_top
            return claripy.BVV(0, 32)
        if self.return_register == "edx_eax":
            if result.size() != 64:
                raise ValueError("an EDX:EAX call summary requires a 64-bit result")
            self.state.regs.edx = result[63:32]
            # Let the SimProcedure calling convention place the full 64-bit
            # value in EDX:EAX. Returning only EAX made angr extract bits that
            # did not exist from a 32-bit expression.
            return result
        raise ValueError(f"unsupported call return register: {self.return_register}")


def project(code: bytes, base: int = BASE) -> angr.Project:
    return angr.load_shellcode(code, arch="x86", load_address=base)


def _hook_fsin(state: angr.SimState) -> None:
    """Model FSIN as a shared deterministic semantic operation."""
    argument = x87_st0(state)
    calls = list(state.globals.get("calls", ()))
    ordinal = len(calls)
    calls.append(("__x86_fsin", (argument,), (), (False,), (None,)))
    state.globals["calls"] = tuple(calls)
    result = claripy.BVS(
        f"x86_fsin_result_{ordinal}", 64, explicit_name=True,
    )
    top = state.regs.ftop & 7
    for index in range(8):
        old_value = state.registers.load(72 + index * 8, 8)
        state.registers.store(
            72 + index * 8,
            claripy.If(top == index, result, old_value),
        )


def _indirect_target(state: angr.SimState, operand: tuple) -> claripy.ast.BV:
    kind, register, base_register, index_register, scale, displacement = operand
    if kind == "reg":
        return getattr(state.regs, register)
    address = claripy.BVV(displacement & 0xFFFFFFFF, 32)
    if base_register:
        address += getattr(state.regs, base_register)
    if index_register:
        address += getattr(state.regs, index_register) * scale
    return state.memory.load(address, 4, endness=state.arch.memory_endness)


def _install_semantic_instruction_hooks(
    proj: angr.Project, code: bytes, base: int,
    memory_regions: tuple[tuple[object, int], ...],
) -> None:
    # Linear disassembly can lose synchronization on embedded jump-table
    # bytes. FSIN has the exact two-byte encoding D9 FE, so scan every offset
    # and let executed code reach only genuine instruction boundaries.
    start = 0
    while True:
        offset = code.find(b"\xd9\xfe", start)
        if offset < 0:
            break
        proj.hook(base + offset, _hook_fsin, length=2)
        start = offset + 1

    engine = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    engine.detail = True
    instructions = list(engine.disasm(code, base))
    for index, instruction in enumerate(instructions):
        if (instruction.mnemonic != "call" or len(instruction.operands) != 1 or
                instruction.operands[0].type == capstone.x86_const.X86_OP_IMM):
            continue
        raw_operand = instruction.operands[0]
        if raw_operand.type == capstone.x86_const.X86_OP_REG:
            operand = ("reg", instruction.reg_name(raw_operand.reg), "", "", 1, 0)
        elif raw_operand.type == capstone.x86_const.X86_OP_MEM:
            memory = raw_operand.mem
            operand = (
                "mem", "",
                instruction.reg_name(memory.base) if memory.base else "",
                instruction.reg_name(memory.index) if memory.index else "",
                memory.scale, memory.disp,
            )
        else:
            continue

        caller_cleanup = 0
        if index + 1 < len(instructions):
            following = instructions[index + 1]
            if (following.mnemonic == "add" and len(following.operands) == 2 and
                    following.operands[0].type == capstone.x86_const.X86_OP_REG and
                    following.reg_name(following.operands[0].reg) == "esp" and
                    following.operands[1].type == capstone.x86_const.X86_OP_IMM):
                caller_cleanup = following.operands[1].imm
        pushed = 0
        cursor = index - 1
        inspected = 0
        while cursor >= 0 and inspected < 8:
            previous = instructions[cursor]
            if previous.mnemonic.startswith(("call", "j", "ret")):
                break
            if previous.mnemonic == "push":
                pushed += 1
            if (previous.mnemonic in ("add", "sub") and previous.op_str.startswith("esp,")):
                break
            cursor -= 1
            inspected += 1
        argument_count = caller_cleanup // 4 if caller_cleanup else pushed
        callee_cleanup = 0 if caller_cleanup else argument_count * 4

        def indirect_call_hook(state, *, target_operand=operand,
                               count=argument_count, cleanup=callee_cleanup):
            target = _indirect_target(state, target_operand)
            arguments = tuple(
                state.memory.load(
                    state.regs.esp + word * 4, 4,
                    endness=state.arch.memory_endness,
                )
                for word in range(count)
            )
            calls = list(state.globals.get("calls", ()))
            ordinal = len(calls)
            snapshot = tuple(
                state.memory.load(address, size, endness=state.arch.memory_endness)
                for address, size in memory_regions
            )
            calls.append((
                "__indirect_call", (target, *arguments), snapshot,
                tuple(False for _ in range(count + 1)),
                tuple(None for _ in range(count + 1)),
            ))
            state.globals["calls"] = tuple(calls)
            state.globals["inside_external_call"] = True
            for region_index, (address, size) in enumerate(memory_regions):
                state.memory.store(
                    address,
                    claripy.BVS(
                        f"indirect_memory_{ordinal}_{region_index}", size * 8,
                        explicit_name=True,
                    ),
                    endness=state.arch.memory_endness,
                )
            state.globals["inside_external_call"] = False
            state.regs.eax = claripy.BVS(
                f"indirect_return_{ordinal}", 32, explicit_name=True,
            )
            if cleanup:
                state.regs.esp += cleanup

        proj.hook(
            instruction.address, indirect_call_hook, length=instruction.size,
        )


def _sim_type(value: ABIType, arch: object):
    if value.kind == "void":
        result = SimTypeBottom(label="void")
    elif value.kind == "pointer":
        result = SimTypePointer(SimTypeBottom(label=value.name))
    elif value.kind == "float":
        result = SimTypeFloat()
    elif value.kind == "double":
        result = SimTypeDouble()
    elif value.kind == "integer":
        result = SimTypeNum(value.size * 8, signed=False)
    elif value.kind == "aggregate":
        # On 32-bit MSVC, small by-value aggregates are passed as their raw
        # object representation.  SimTypeNum preserves the exact stack width
        # without inventing a field layout that is irrelevant to the callee.
        result = SimTypeNum(value.size * 8, signed=False)
    else:
        raise ValueError(f"unsupported by-value ABI type: {value.name}")
    return result.with_arch(arch)


def _calling_convention(proj: angr.Project, signature: ABISignature | None):
    name = signature.calling_convention.lower() if signature else "nearc"
    if name in ("nearc", "cdecl", "nearvector"):
        return angr.calling_conventions.SimCCMicrosoftCdecl(proj.arch)
    if name in ("nearstdcall", "stdcall"):
        return angr.calling_conventions.SimCCStdcall(proj.arch)
    if name in ("nearfast", "nearfastcall", "fastcall"):
        return angr.calling_conventions.SimCCMicrosoftFastcall(proj.arch)
    if name in ("thiscall", "nearthiscall"):
        return angr.calling_conventions.SimCCMicrosoftThiscall(proj.arch)
    raise ValueError(f"unsupported x86 calling convention: {signature.calling_convention}")


def _prototype(proj: angr.Project, signature: ABISignature | None, count: int):
    if signature:
        parameters = [_sim_type(item, proj.arch) for item in signature.parameters]
        if count < len(parameters):
            raise ValueError("call summary has fewer arguments than its PDB signature")
        if count > len(parameters):
            if not signature.variadic:
                raise ValueError("non-variadic call summary has excess arguments")
            word_type = SimTypeNum(32, signed=False).with_arch(proj.arch)
            parameters.extend(word_type for _ in range(count - len(parameters)))
        return SimTypeFunction(
            parameters,
            _sim_type(signature.return_type, proj.arch),
        ).with_arch(proj.arch)
    word_type = SimTypeNum(32, signed=False).with_arch(proj.arch)
    return SimTypeFunction([word_type for _ in range(count)], word_type).with_arch(proj.arch)


FP_ENVIRONMENT_INSTRUCTIONS = {
    "fclex", "fnclex", "finit", "fninit", "fldcw", "fstcw", "fnstcw",
    "ldmxcsr", "stmxcsr", "fxsave", "fxrstor", "xsave", "xrstor",
}


def unsupported_instructions(code: bytes, base: int) -> tuple[str, ...]:
    engine = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    engine.detail = True
    issues: list[str] = []
    consumed = 0
    for instruction in engine.disasm(code, base):
        consumed += instruction.size
        if 0xF0 in instruction.prefix:
            issues.append(f"UNSUPPORTED_ATOMIC_INSTRUCTION:0x{instruction.address:x}")
        # VEX models x87 control/status and MXCSR rounding state.  These are
        # initialized as shared inputs and compared as observable outputs.
        if instruction.mnemonic in ("int", "into", "ud2", "icebp"):
            issues.append(f"UNSUPPORTED_SYNCHRONOUS_EXCEPTION:0x{instruction.address:x}")
        for operand in instruction.operands:
            if operand.type != capstone.x86_const.X86_OP_MEM:
                continue
            memory = operand.mem
            if (memory.segment == capstone.x86_const.X86_REG_FS and
                    memory.base == capstone.x86_const.X86_REG_INVALID and
                    memory.index == capstone.x86_const.X86_REG_INVALID and
                    memory.disp == 0):
                issues.append(f"UNSUPPORTED_SEH_CHAIN_ACCESS:0x{instruction.address:x}")
    # Do not reject incomplete linear disassembly here: real functions can
    # contain embedded jump-table data. Executed undecodable bytes are caught
    # by the engine as execution errors instead.
    return tuple(dict.fromkeys(issues))


def execute(
    code: bytes,
    arguments: tuple[claripy.ast.BV, ...],
    calls: tuple[CallTarget, ...] = (),
    call_results: tuple[claripy.ast.BV, ...] = (),
    initial_memory: tuple[tuple[int, claripy.ast.BV], ...] = (),
    base: int = BASE,
    initial_registers: tuple[tuple[str, claripy.ast.BV], ...] = (),
    constraints: tuple[claripy.ast.Bool, ...] = (),
    timeout_seconds: float | None = 300.0,
    maximum_steps: int | None = 100_000,
    signature: ABISignature | None = None,
    frontend_issues: tuple[str, ...] = (),
    stack_allocations: tuple[LogicalAllocation, ...] = (),
) -> Execution:
    if frontend_issues:
        return Execution([], False, frontend_issues, constraints, (), signature, stack_allocations)
    feature_issues = unsupported_instructions(code, base)
    if feature_issues:
        return Execution([], False, feature_issues, constraints, (), signature, stack_allocations)
    proj = project(code, base)
    if len(calls) != len(call_results):
        raise ValueError("each call target needs a shared symbolic result")

    memory_regions = tuple((address, value.size() // 8) for address, value in initial_memory)
    _install_semantic_instruction_hooks(proj, code, base, memory_regions)
    for target, result in zip(calls, call_results, strict=True):
        if target.frontend_issues:
            return Execution(
                [], False, target.frontend_issues, constraints, memory_regions,
                signature, stack_allocations,
            )
        try:
            target_cc = _calling_convention(proj, target.signature)
            target_prototype = _prototype(proj, target.signature, target.argument_count)
        except ValueError as error:
            return Execution(
                [], False, (f"UNSUPPORTED_CALL_ABI:{target.decorated_symbol}:{error}",),
                constraints, memory_regions, signature, stack_allocations,
            )
        pointer_mask = target.argument_pointer_mask or (
            tuple(item.pointer for item in target.signature.parameters) +
            tuple(False for _ in range(
                target.argument_count - len(target.signature.parameters)
            ))
            if target.signature else ()
        )
        pointee_sizes = target.argument_pointee_sizes or (
            tuple(item.pointee_size for item in target.signature.parameters) +
            tuple(None for _ in range(
                target.argument_count - len(target.signature.parameters)
            ))
            if target.signature else ()
        )
        proj.hook(target.address, RecordedCall(
            target.decorated_symbol, result, target.argument_count,
            target.argument_registers, target.fresh_result,
            target.havoc_memory, memory_regions, target.return_register,
            pointer_mask, pointee_sizes, target.callsite_argument_counts,
            target_cc, target_prototype,
        ))

    try:
        cc = _calling_convention(proj, signature)
        if signature:
            if signature.variadic:
                raise ValueError("variadic PDB signatures require explicit vararg types")
            if len(signature.parameters) != len(arguments):
                raise ValueError(
                    f"PDB ABI expects {len(signature.parameters)} arguments, got {len(arguments)}"
                )
            for index, (parameter, argument) in enumerate(zip(signature.parameters, arguments, strict=True)):
                if argument.size() != parameter.size * 8:
                    raise ValueError(
                        f"argument {index} is {argument.size()} bits; PDB ABI requires {parameter.size * 8}"
                    )
            prototype = _prototype(proj, signature, len(arguments))
        else:
            prototype = _prototype(proj, None, len(arguments))
    except ValueError as error:
        return Execution(
            [], False, (f"UNSUPPORTED_PDB_ABI:{error}",), constraints,
            memory_regions, signature,
            stack_allocations,
        )
    state = proj.factory.call_state(
        base,
        *arguments,
        cc=cc,
        prototype=prototype,
        ret_addr=RETURN_SENTINEL,
        stack_base=STACK_BASE,
    )
    # Both programs execute from the same incoming machine state.  Letting
    # angr lazily create unconstrained register values is unsound here: its
    # process-global name allocator gives the two executions different symbols,
    # so even identical `ret` functions can appear to return different EAX
    # values.  Explicit names also make proofs independent of exploration and
    # test order.  ESP/EIP are established by call_state, and explicit ABI
    # register arguments below intentionally override these defaults.
    abi_registers = {
        location.reg_name
        for location in cc.arg_locs(prototype)
        if hasattr(location, "reg_name")
    }
    for register in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp"):
        if register in abi_registers:
            continue
        setattr(
            state.regs, register,
            claripy.BVS(f"incoming_{register}", 32, explicit_name=True),
        )
    state.regs.cc_op = claripy.BVV(0, 32)
    state.regs.cc_dep1 = claripy.BVS("incoming_eflags", 32, explicit_name=True)
    state.regs.cc_dep2 = claripy.BVV(0, 32)
    state.regs.cc_ndep = claripy.BVV(0, 32)
    state.regs.dflag = claripy.BVV(1, 32)
    state.regs.idflag = claripy.BVV(0, 32)
    state.regs.acflag = claripy.BVV(0, 32)
    for index in range(8):
        setattr(
            state.regs, f"mm{index}",
            claripy.BVS(f"incoming_mm{index}", 64, explicit_name=True),
        )
        setattr(
            state.regs, f"xmm{index}",
            claripy.BVS(f"incoming_xmm{index}", 128, explicit_name=True),
        )
    # Floating-point environment state is part of the shared input.  Functions
    # may inspect or modify it; the verifier compares the final environment.
    # The x86 ABI enters ordinary C/C++ functions with an empty x87 stack.
    # Control/status state remains symbolic, but symbolic TOP makes VEX split
    # every x87 push into eight artificial execution paths.
    state.regs.fptag = claripy.BVV(0, 64)
    state.regs.fpround = claripy.BVS("incoming_fpround", 32, explicit_name=True)
    state.regs.fc3210 = claripy.BVS("incoming_fc3210", 32, explicit_name=True)
    state.regs.ftop = claripy.BVV(0, 32)
    state.regs.sseround = claripy.BVS("incoming_sseround", 32, explicit_name=True)
    state.globals["calls"] = ()
    state.globals["stack_allocations"] = stack_allocations
    state.solver.add(*constraints)
    for register, value in initial_registers:
        setattr(state.regs, register, value)
    for address, value in initial_memory:
        state.memory.store(address, value, endness=proj.arch.memory_endness)
    allocation_ids: set[str] = set()
    allocation_ranges: list[tuple[int, int]] = []
    for allocation in stack_allocations:
        if (allocation.logical_id in allocation_ids or allocation.size <= 0 or
                not STACK_BASE - 0x100000 <= allocation.address or
                allocation.address + allocation.size > STACK_BASE + 0x10000 or
                any(allocation.address < end and start < allocation.address + allocation.size
                    for start, end in allocation_ranges)):
            return Execution(
                [], False, (f"UNMODELED_STACK_ALLOCATION:{allocation.logical_id}",),
                initialized_constraints if 'initialized_constraints' in locals() else constraints,
                memory_regions, signature, stack_allocations,
            )
        allocation_ids.add(allocation.logical_id)
        allocation_ranges.append((allocation.address, allocation.address + allocation.size))
        digest = hashlib.sha256(allocation.logical_id.encode("utf-8")).hexdigest()[:12]
        state.memory.store(
            allocation.address,
            claripy.BVS(
                f"private_allocation_{digest}", allocation.size * 8,
                explicit_name=True,
            ),
            endness=proj.arch.memory_endness,
        )
    state.globals["memory_reads"] = ()
    state.globals["memory_writes"] = ()

    def record_read(current: angr.SimState) -> None:
        address = current.inspect.attrs.mem_read_address
        length = current.inspect.attrs.mem_read_length
        if address is not None and length is not None:
            current.globals["memory_reads"] = (
                *current.globals.get("memory_reads", ()), (address, length),
            )

    def record_write(current: angr.SimState) -> None:
        if current.globals.get("inside_external_call", False):
            return
        address = current.inspect.attrs.mem_write_address
        length = current.inspect.attrs.mem_write_length
        if address is not None and length is not None:
            current.globals["memory_writes"] = (
                *current.globals.get("memory_writes", ()), (address, length),
            )

    state.inspect.b("mem_read", when=angr.BP_BEFORE, action=record_read)
    state.inspect.b("mem_write", when=angr.BP_BEFORE, action=record_write)
    initialized_constraints = tuple(state.solver.constraints)
    manager = proj.factory.simulation_manager(state)
    started = time.monotonic()
    steps = 0
    issues: list[str] = []
    manager.stashes["returned"] = []

    def at_return(current: angr.SimState) -> bool:
        return current.addr == RETURN_SENTINEL

    while manager.active:
        manager.move("active", "returned", at_return)
        if not manager.active:
            break
        if timeout_seconds is not None and time.monotonic() - started >= timeout_seconds:
            issues.append("EXECUTION_TIMEOUT")
            break
        if maximum_steps is not None and steps >= maximum_steps:
            issues.append("STEP_LIMIT_REACHED")
            break
        outside = [
            current for current in manager.active
            if not base <= current.addr < base + len(code)
            and not proj.is_hooked(current.addr)
        ]
        if outside:
            issues.append(
                "UNMODELED_CONTROL_TARGET:" +
                ",".join(f"0x{current.addr:x}" for current in outside[:8])
            )
            break
        manager.step()
        steps += 1
        if manager.errored:
            issues.extend(
                f"EXECUTION_ERROR:{type(item.error).__name__}:{item.error}"
                for item in manager.errored[:8]
            )
            break
        if manager.unconstrained:
            issues.append("UNCONSTRAINED_CONTROL_FLOW")
            break

    manager.move("active", "returned", at_return)
    if manager.active and not issues:
        issues.append("ACTIVE_STATES_REMAIN")
    if manager.deadended:
        issues.append(f"NONRETURNING_DEADENDS:{len(manager.deadended)}")
    if not manager.returned:
        issues.append("NO_RETURNING_STATE")
    return Execution(
        list(manager.returned), not issues, tuple(dict.fromkeys(issues)),
        initialized_constraints, memory_regions, signature, stack_allocations,
    )


def path_condition(state: angr.SimState) -> claripy.ast.Bool:
    return claripy.And(*state.solver.constraints)


def _logical_pointer(
    state: angr.SimState, value: claripy.ast.BV,
) -> tuple[str, str, int] | tuple[str, claripy.ast.BV]:
    if state.solver.unique(value):
        concrete = state.solver.eval(value)
        for allocation in state.globals.get("stack_allocations", ()):
            if allocation.address <= concrete < allocation.address + allocation.size:
                return ("allocation", allocation.logical_id, concrete - allocation.address)
    return ("raw", value)


def _pointer_difference(
    left_state: angr.SimState, left: claripy.ast.BV,
    right_state: angr.SimState, right: claripy.ast.BV,
) -> claripy.ast.Bool:
    lhs = _logical_pointer(left_state, left)
    rhs = _logical_pointer(right_state, right)
    if lhs[0] == "allocation" or rhs[0] == "allocation":
        return claripy.BoolV(lhs != rhs)
    return lhs[1] != rhs[1]


def calls_differ(left: angr.SimState, right: angr.SimState) -> claripy.ast.Bool:
    lhs = left.globals.get("calls", ())
    rhs = right.globals.get("calls", ())
    if len(lhs) != len(rhs):
        return claripy.true()

    differences: list[claripy.ast.Bool] = []
    for lhs_call, rhs_call in zip(lhs, rhs, strict=True):
        lhs_name, lhs_args, lhs_memory, lhs_pointers, lhs_argument_memory = lhs_call
        rhs_name, rhs_args, rhs_memory, rhs_pointers, rhs_argument_memory = rhs_call
        if lhs_name != rhs_name:
            return claripy.true()
        if len(lhs_args) != len(rhs_args) or lhs_pointers != rhs_pointers:
            return claripy.true()
        differences.extend(
            _pointer_difference(left, lhs_arg, right, rhs_arg)
            if is_pointer else lhs_arg != rhs_arg
            for lhs_arg, rhs_arg, is_pointer in zip(
                lhs_args, rhs_args, lhs_pointers, strict=True,
            )
        )
        if len(lhs_memory) != len(rhs_memory):
            return claripy.true()
        differences.extend(
            lhs_value != rhs_value
            for lhs_value, rhs_value in zip(lhs_memory, rhs_memory, strict=True)
        )
        differences.extend(
            claripy.BoolV((lhs_value is None) != (rhs_value is None))
            if lhs_value is None or rhs_value is None else lhs_value != rhs_value
            for lhs_value, rhs_value in zip(
                lhs_argument_memory, rhs_argument_memory, strict=True,
            )
        )
    return claripy.Or(*differences) if differences else claripy.false()


def _or(values: list[claripy.ast.Bool]) -> claripy.ast.Bool:
    return claripy.Or(*values) if values else claripy.false()


def _as_length(value: object) -> int | None:
    if isinstance(value, int):
        return value
    if getattr(value, "concrete", False):
        return int(value.concrete_value)
    return None


def _inside_region(address: claripy.ast.BV, length: int,
                   start: object, size: int) -> claripy.ast.Bool:
    region_start = start if hasattr(start, "size") else claripy.BVV(int(start), 32)
    return claripy.And(address >= region_start, address + length <= region_start + size)


def _access_model_issues(
    execution: Execution,
    observed_memory: tuple[tuple[int, int], ...],
) -> tuple[str, ...]:
    issues: list[str] = []
    stack_regions: tuple[tuple[object, int], ...] = ((STACK_BASE - 0x100000, 0x110000),)
    readable = execution.readable_regions + stack_regions
    writable: tuple[tuple[object, int], ...] = tuple(observed_memory) + stack_regions
    for state in execution.states:
        condition = path_condition(state)
        for kind, regions in (("READ", readable), ("WRITE", writable)):
            accesses = state.globals.get(f"memory_{kind.lower()}s", ())
            for address, raw_length in accesses:
                length = _as_length(raw_length)
                if length is None:
                    issues.append(f"SYMBOLIC_{kind}_SIZE")
                    continue
                covered = _or([
                    _inside_region(address, length, start, size)
                    for start, size in regions
                ])
                solver = claripy.Solver()
                solver.add(claripy.And(condition, claripy.Not(covered)))
                if solver.satisfiable():
                    issues.append(f"UNMODELED_EXTERNAL_{kind}")
    return tuple(dict.fromkeys(issues))


def bounded_external_regions(
    executions: tuple[Execution, ...],
    known_regions: tuple[tuple[int, int], ...] = (),
    maximum_region_size: int = 1 << 20,
) -> tuple[tuple[int, int], ...]:
    """Discover finite concrete ranges behind symbolic memory accesses.

    This covers bounded table indexing while refusing unconstrained pointers,
    whose 32-bit range would exceed the cap and remains model-incomplete.
    """
    discovered: list[tuple[int, int]] = []
    stack_start, stack_size = STACK_BASE - 0x100000, 0x110000
    known = (*known_regions, (stack_start, stack_size))
    for execution in executions:
        for state in execution.states:
            for kind in ("reads", "writes"):
                for address, raw_length in state.globals.get(f"memory_{kind}", ()):
                    length = _as_length(raw_length)
                    if length is None:
                        continue
                    try:
                        lower = state.solver.min(address)
                        upper = state.solver.max(address)
                    except Exception:
                        continue
                    size = upper - lower + length
                    if size <= 0 or size > maximum_region_size:
                        continue
                    if any(start <= lower and upper + length <= start + width
                           for start, width in known):
                        continue
                    discovered.append((lower, size))
    merged: list[tuple[int, int]] = []
    for start, size in sorted(set(discovered)):
        end = start + size
        if merged and start <= merged[-1][0] + merged[-1][1]:
            old_start, old_size = merged[-1]
            merged[-1] = (old_start, max(old_start + old_size, end) - old_start)
        else:
            merged.append((start, size))
    return tuple(merged)


def x87_st0(state: angr.SimState) -> claripy.ast.BV:
    top = state.regs.ftop & 7
    values = [state.registers.load(72 + index * 8, 8) for index in range(8)]
    result = values[-1]
    for index in reversed(range(7)):
        result = claripy.If(top == index, values[index], result)
    return result


def verify_equivalence(
    reference: Execution,
    candidate: Execution,
    inputs: tuple[claripy.ast.BV, ...],
    observed_memory: tuple[tuple[int, int], ...] = (),
    return_bits: int = 32,
    compare_return: bool = True,
    return_register: str = "auto",
    return_pointer: bool = False,
    pointer_observations: tuple[tuple[int, int], ...] = (),
) -> VerificationResult:
    execution_issues = tuple((*reference.issues, *candidate.issues))
    if not reference.complete or not candidate.complete:
        if any(reason.startswith("UNSUPPORTED_") for reason in execution_issues):
            status = VerificationStatus.UNSUPPORTED
        elif any(reason.startswith("UNMODELED_") for reason in execution_issues):
            status = VerificationStatus.MODEL_INCOMPLETE
        else:
            status = VerificationStatus.INCONCLUSIVE
        return VerificationResult(
            status,
            reasons=tuple(dict.fromkeys(execution_issues)),
        )
    if not reference.states or not candidate.states:
        return VerificationResult(
            VerificationStatus.INCONCLUSIVE, reasons=("NO_RETURNING_STATE",),
        )

    if reference.signature != candidate.signature:
        return VerificationResult(
            VerificationStatus.MODEL_INCOMPLETE,
            reasons=("PDB_SIGNATURE_MISMATCH",),
        )
    if return_register == "auto":
        result_type = reference.signature.return_type if reference.signature else None
        if result_type and result_type.kind == "void":
            compare_return = False
            return_register = "eax"
        elif result_type and result_type.kind in ("float", "double"):
            return_register = "x87_st0"
        elif result_type and result_type.size == 8:
            return_register = "edx_eax"
            return_bits = 64
        else:
            return_register = "eax"
            if result_type and result_type.size:
                return_bits = result_type.size * 8

    model_issues = tuple(dict.fromkeys((
        *_access_model_issues(reference, observed_memory),
        *_access_model_issues(candidate, observed_memory),
    )))
    if model_issues:
        return VerificationResult(VerificationStatus.MODEL_INCOMPLETE, reasons=model_issues)

    assumptions = claripy.And(
        *reference.initial_constraints, *candidate.initial_constraints,
    )
    reference_coverage = _or([path_condition(state) for state in reference.states])
    candidate_coverage = _or([path_condition(state) for state in candidate.states])
    coverage_solver = claripy.Solver()
    coverage_solver.add(claripy.And(
        assumptions, reference_coverage != candidate_coverage,
    ))
    if coverage_solver.satisfiable():
        return VerificationResult(
            VerificationStatus.NOT_EQUIVALENT,
            tuple(coverage_solver.eval(value, 1)[0] for value in inputs),
            ("RETURN_DOMAIN_MISMATCH",),
        )
    total_solver = claripy.Solver()
    total_solver.add(claripy.And(assumptions, claripy.Not(reference_coverage)))
    if total_solver.satisfiable():
        return VerificationResult(
            VerificationStatus.INCONCLUSIVE,
            reasons=("RETURN_COVERAGE_INCOMPLETE",),
        )

    solver = claripy.Solver()
    mismatches: list[claripy.ast.Bool] = []
    for lhs in reference.states:
        for rhs in candidate.states:
            shared_path = claripy.And(path_condition(lhs), path_condition(rhs))
            differences = [calls_differ(lhs, rhs)]
            differences.extend((
                lhs.regs.fptag != rhs.regs.fptag,
                lhs.regs.fpround != rhs.regs.fpround,
                lhs.regs.fc3210 != rhs.regs.fc3210,
                lhs.regs.ftop != rhs.regs.ftop,
                lhs.regs.sseround != rhs.regs.sseround,
            ))
            if compare_return:
                if return_register == "eax":
                    lhs_return = lhs.regs.eax[return_bits - 1:0]
                    rhs_return = rhs.regs.eax[return_bits - 1:0]
                    differences.append(
                        _pointer_difference(lhs, lhs_return, rhs, rhs_return)
                        if return_pointer else lhs_return != rhs_return
                    )
                elif return_register == "x87_st0":
                    differences.append(x87_st0(lhs) != x87_st0(rhs))
                elif return_register == "edx_eax":
                    differences.append(
                        claripy.Concat(lhs.regs.edx, lhs.regs.eax) !=
                        claripy.Concat(rhs.regs.edx, rhs.regs.eax)
                    )
                else:
                    return VerificationResult(
                        VerificationStatus.UNSUPPORTED,
                        reasons=(f"UNSUPPORTED_RETURN_REGISTER:{return_register}",),
                    )
            differences.extend(
                lhs.memory.load(address, size, endness=lhs.arch.memory_endness) !=
                rhs.memory.load(address, size, endness=rhs.arch.memory_endness)
                for address, size in observed_memory
            )
            differences.extend(
                _pointer_difference(
                    lhs,
                    lhs.memory.load(address, size, endness=lhs.arch.memory_endness),
                    rhs,
                    rhs.memory.load(address, size, endness=rhs.arch.memory_endness),
                )
                for address, size in pointer_observations
            )
            mismatches.append(claripy.And(shared_path, claripy.Or(*differences)))
    solver.add(claripy.And(assumptions, _or(mismatches)))
    if solver.satisfiable():
        return VerificationResult(
            VerificationStatus.NOT_EQUIVALENT,
            tuple(solver.eval(value, 1)[0] for value in inputs),
        )
    return VerificationResult(VerificationStatus.EQUIVALENT)


def counterexample(
    reference: Execution,
    candidate: Execution,
    inputs: tuple[claripy.ast.BV, ...],
    observed_memory: tuple[tuple[int, int], ...] = (),
    return_bits: int = 32,
    compare_return: bool = True,
    return_register: str = "auto",
    return_pointer: bool = False,
    pointer_observations: tuple[tuple[int, int], ...] = (),
) -> tuple[int, ...] | None:
    result = verify_equivalence(
        reference, candidate, inputs, observed_memory, return_bits,
        compare_return, return_register, return_pointer, pointer_observations,
    )
    if result.status in (
        VerificationStatus.INCONCLUSIVE,
        VerificationStatus.MODEL_INCOMPLETE,
        VerificationStatus.UNSUPPORTED,
    ):
        raise IncompleteVerification(f"{result.status.value}: {', '.join(result.reasons)}")
    return result.counterexample


def verify_under_pdb_aliasing(
    reference_code: bytes,
    candidate_code: bytes,
    signature: ABISignature,
    *,
    reference_calls: tuple[CallTarget, ...] = (),
    candidate_calls: tuple[CallTarget, ...] = (),
    call_results: tuple[claripy.ast.BV, ...] = (),
    common_memory: tuple[tuple[int, claripy.ast.BV], ...] = (),
    observed_memory: tuple[tuple[int, int], ...] = (),
    reference_base: int = BASE,
    candidate_base: int = BASE,
    frontend_issues: tuple[str, ...] = (),
    maximum_cases: int = 4096,
    global_objects: tuple[object, ...] = (),
    pointer_globals: tuple[object, ...] = (),
    execute_options: dict[str, object] | None = None,
    total_timeout_seconds: float | None = None,
) -> VerificationResult:
    """Prove every null/alias/allocation-order case admitted by PDB types."""
    from alias_model import AliasCaseLimit, iter_alias_scenarios

    try:
        scenarios = iter_alias_scenarios(
            signature, globals=global_objects, pointer_globals=pointer_globals,
            maximum_cases=None,
        )
    except ValueError as error:
        return VerificationResult(
            VerificationStatus.MODEL_INCOMPLETE,
            reasons=(f"ALIAS_MODEL_INCOMPLETE:{error}",),
        )
    incomplete: VerificationResult | None = None
    processed_cases = 0
    execution_options = execute_options or {}
    deadline = (
        time.monotonic() + total_timeout_seconds
        if total_timeout_seconds is not None else None
    )
    try:
        scenario_iterator = iter(scenarios)
    except (AliasCaseLimit, ValueError) as error:
        return VerificationResult(
            VerificationStatus.MODEL_INCOMPLETE,
            reasons=(f"ALIAS_MODEL_INCOMPLETE:{error}",),
        )
    while True:
        try:
            scenario = next(scenario_iterator)
        except StopIteration:
            break
        except (AliasCaseLimit, ValueError) as error:
            return VerificationResult(
                VerificationStatus.MODEL_INCOMPLETE,
                reasons=(f"ALIAS_MODEL_INCOMPLETE:{error}",),
            )
        if deadline is not None and time.monotonic() >= deadline:
            return VerificationResult(
                VerificationStatus.INCONCLUSIVE,
                reasons=("ALIAS_CAMPAIGN_TIMEOUT",),
            )
        memory = (*common_memory, *scenario.initial_memory)
        scenario_options = dict(execution_options)
        scenario_observed = (
            *observed_memory,
            *((address, value.size() // 8) for address, value in scenario.initial_memory),
        )
        reference_options = dict(scenario_options)
        if deadline is not None:
            remaining = max(0.001, deadline - time.monotonic())
            configured = reference_options.get("timeout_seconds")
            reference_options["timeout_seconds"] = min(
                float(configured) if configured is not None else remaining / 2,
                remaining / 2,
            )
        reference = execute(
            reference_code, scenario.arguments, reference_calls, call_results,
            memory, base=reference_base, signature=signature,
            frontend_issues=frontend_issues,
            **reference_options,
        )
        candidate_options = dict(scenario_options)
        if deadline is not None:
            remaining = max(0.001, deadline - time.monotonic())
            configured = candidate_options.get("timeout_seconds")
            candidate_options["timeout_seconds"] = min(
                float(configured) if configured is not None else remaining,
                remaining,
            )
        candidate = execute(
            candidate_code, scenario.arguments, candidate_calls, call_results,
            memory, base=candidate_base, signature=signature,
            frontend_issues=frontend_issues,
            **candidate_options,
        )
        extra_regions = bounded_external_regions(
            (reference, candidate), scenario_observed,
        )
        if extra_regions:
            extra_memory = tuple(
                (address, claripy.BVS(
                    f"alias_bounded_{address:x}_{size}", size * 8,
                    explicit_name=True,
                ))
                for address, size in extra_regions
            )
            complete_memory = (*memory, *extra_memory)
            retry_reference_options = dict(scenario_options)
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return VerificationResult(
                        VerificationStatus.INCONCLUSIVE,
                        reasons=("ALIAS_CAMPAIGN_TIMEOUT",),
                    )
                configured = retry_reference_options.get("timeout_seconds")
                retry_reference_options["timeout_seconds"] = min(
                    float(configured) if configured is not None else remaining / 2,
                    remaining / 2,
                )
            reference = execute(
                reference_code, scenario.arguments, reference_calls, call_results,
                complete_memory, base=reference_base, signature=signature,
                frontend_issues=frontend_issues,
                **retry_reference_options,
            )
            retry_candidate_options = dict(scenario_options)
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return VerificationResult(
                        VerificationStatus.INCONCLUSIVE,
                        reasons=("ALIAS_CAMPAIGN_TIMEOUT",),
                    )
                configured = retry_candidate_options.get("timeout_seconds")
                retry_candidate_options["timeout_seconds"] = min(
                    float(configured) if configured is not None else remaining,
                    remaining,
                )
            candidate = execute(
                candidate_code, scenario.arguments, candidate_calls, call_results,
                complete_memory, base=candidate_base, signature=signature,
                frontend_issues=frontend_issues,
                **retry_candidate_options,
            )
            scenario_observed = (*scenario_observed, *extra_regions)
        symbolic_inputs = tuple(
            value for value in scenario.arguments if value.symbolic
        ) + tuple(value for _, value in scenario.initial_memory)
        result = verify_equivalence(
            reference, candidate, symbolic_inputs,
            observed_memory=scenario_observed,
            return_pointer=signature.return_type.pointer,
        )
        if result.status == VerificationStatus.NOT_EQUIVALENT:
            return VerificationResult(
                result.status, result.counterexample,
                (f"ALIAS_SCENARIO:{scenario.name}", *result.reasons),
            )
        if result.status != VerificationStatus.EQUIVALENT and incomplete is None:
            incomplete = VerificationResult(
                result.status, result.counterexample,
                (f"ALIAS_SCENARIO:{scenario.name}", *result.reasons),
            )
        processed_cases += 1
        del reference, candidate, result
        if processed_cases % 8 == 0:
            gc.collect()
    return incomplete or VerificationResult(VerificationStatus.EQUIVALENT)


def rel32(instruction_address: int, target: int) -> bytes:
    return struct.pack("<i", target - (instruction_address + 5))


def call_fixture(register_variant: bool, callee: int) -> bytes:
    if not register_variant:
        # eax = helper(x + 1) + 3
        prefix = bytes.fromhex("8b442404 40 50 e8")
        suffix = bytes.fromhex("83c404 83c003 c3")
    else:
        # Same computation, but use ecx and LEA.
        prefix = bytes.fromhex("8b4c2404 83c101 51 e8")
        suffix = bytes.fromhex("83c404 8d4003 c3")
    call_address = BASE + len(prefix) - 1
    return prefix + rel32(call_address, callee) + suffix


def check(name: str, reference_code: bytes, candidate_code: bytes,
          reference_call: CallTarget | None = None,
          candidate_call: CallTarget | None = None,
          observed_memory: tuple[tuple[int, int], ...] = ()) -> bool:
    x = claripy.BVS(f"{name}_x", 32, explicit_name=True)
    y = claripy.BVS(f"{name}_y", 32, explicit_name=True)
    external_result = claripy.BVS(f"{name}_external_result", 32, explicit_name=True)
    initial_memory = tuple(
        (address, claripy.BVS(f"{name}_memory_{address:x}", size * 8, explicit_name=True))
        for address, size in observed_memory
    )

    ref_calls = (reference_call,) if reference_call else ()
    cand_calls = (candidate_call,) if candidate_call else ()
    ref_results = (external_result,) if reference_call else ()
    cand_results = (external_result,) if candidate_call else ()
    args = (x,) if reference_call or candidate_call else (x, y)

    reference = execute(reference_code, args, ref_calls, ref_results, initial_memory)
    candidate = execute(candidate_code, args, cand_calls, cand_results, initial_memory)
    model = counterexample(reference, candidate, args, observed_memory)
    if model is None:
        print(f"EQUIVALENT: {name}")
        return True
    rendered = ", ".join(f"arg{i}=0x{value:08x}" for i, value in enumerate(model))
    print(f"NOT_EQUIVALENT: {name} ({rendered})")
    return False


def main() -> int:
    # Both return x + 2*y, with different registers and stack-frame shape.
    arithmetic_reference = bytes.fromhex(
        "55 89e5 8b4508 8b550c 8d0450 5d c3"
    )
    arithmetic_candidate = bytes.fromhex(
        "53 8b442408 8b4c240c 01c9 01c8 5b c3"
    )
    # Deliberately wrong: x + y.
    arithmetic_wrong = bytes.fromhex(
        "8b442404 03442408 c3"
    )

    helper_address = 0x110000
    other_address = 0x120000
    helper = CallTarget(helper_address, "?helper@@YAHH@Z")
    other = CallTarget(other_address, "?other@@YAHH@Z")
    call_reference = call_fixture(False, helper_address)
    call_candidate = call_fixture(True, helper_address)
    wrong_call_candidate = call_fixture(True, other_address)

    # if (x != 0) value = x * 3; else value = 7;
    # global = value; return value. The candidate lays out the branches in the
    # opposite order.
    branch_reference = bytes.fromhex(
        "8b442404 85c0 7409 6bc003 a300002000 c3 "
        "b807000000 a300002000 c3"
    )
    branch_candidate = bytes.fromhex(
        "8b4c2404 83f900 7507 b807000000 eb03 "
        "6bc103 a300002000 c3"
    )
    # Same returned value, but writes a different global object.
    branch_wrong_global = bytes.fromhex(
        "8b4c2404 83f900 7507 b807000000 eb03 "
        "6bc103 a304002000 c3"
    )
    globals_to_compare = ((0x200000, 4), (0x200004, 4))

    outcomes = [
        check("register-and-stack", arithmetic_reference, arithmetic_candidate),
        not check("arithmetic-negative-control", arithmetic_reference, arithmetic_wrong),
        check("decorated-call", call_reference, call_candidate, helper, helper),
        not check("call-symbol-negative-control", call_reference, wrong_call_candidate, helper, other),
        check("branch-and-memory", branch_reference, branch_candidate,
              observed_memory=globals_to_compare),
        not check("global-identity-negative-control", branch_reference, branch_wrong_global,
                  observed_memory=globals_to_compare),
    ]
    if all(outcomes):
        print("PROTOTYPE_RESULT: PASS")
        return 0
    print("PROTOTYPE_RESULT: FAIL")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
