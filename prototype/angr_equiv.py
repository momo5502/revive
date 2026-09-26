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
import itertools
import re
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

from pdb_frontend import ABISignature, ABIType, ParameterHome, standard_parameter_homes


BASE = 0x100000
RETURN_SENTINEL = 0xF0000000
STACK_BASE = 0x7FFF0000
STACK_LOW = STACK_BASE - 0x100000
# Largest symbolic-address range treated as a bounded table access.
MAXIMUM_BOUNDED_REGION = 1 << 20


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
    # x87 stack entries the callee consumes (e.g. __ftol2_sse pops ST0).
    x87_pops: int = 0
    # Entry homes when they differ from the declared convention (MSVC custom
    # conventions for TU-local functions); None means the declared one.
    entry_homes: tuple[ParameterHome, ...] | None = None


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
    # The function's own bytes: readable, e.g. by in-function jump tables.
    code_region: tuple[int, int] | None = None
    # Callee-owned stack: locals, the return address and incoming arguments.
    # Everything above belongs to the caller and is external memory.
    private_stack: tuple[int, int] = (STACK_LOW, STACK_BASE + 4)
    # Some parameter had several possible entry locations.
    ambiguous_entry: bool = False
    # Where unmodeled pointers came from (see alias_model.DerivedPointer).
    pointer_sources: tuple[tuple, ...] = ()


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


@dataclass(frozen=True)
class CallEvent:
    """One ordered, externally visible event of an execution.

    ``escaped_memory`` holds callee-visible private stack bytes whose extent
    is established by a declared allocation. ``uncertain`` holds values whose
    observability depends on an unknown contract (an indirect call's register
    arguments, bytes beyond a guessed escape extent). A difference there makes
    the model incomplete instead of proving or refuting equivalence.
    """

    name: str
    arguments: tuple[claripy.ast.BV, ...] = ()
    snapshot: tuple[claripy.ast.BV, ...] = ()
    pointer_mask: tuple[bool, ...] = ()
    argument_memory: tuple[claripy.ast.BV | None, ...] = ()
    escaped_memory: tuple[tuple[str, claripy.ast.BV], ...] = ()
    uncertain: tuple[tuple[str, claripy.ast.BV], ...] = ()
    # Touched undeclared bytes and the epoch whose symbols stand for the rest.
    lazy_memory: tuple[tuple[int, claripy.ast.BV], ...] = ()
    lazy_epoch: int = 0


@dataclass(frozen=True)
class EscapedRegion:
    """Private stack bytes that external code can reach.

    ``key`` is the logical identity shared by corresponding executions. A
    ``definite`` region is a declared allocation; otherwise the extent is the
    conservative distance from the escaping pointer to the end of its frame
    area, keyed by where the pointer first escaped.
    """

    key: str
    start: int
    end: int
    definite: bool


_EXECUTION_TAGS = itertools.count()


def _private_stack(state: angr.SimState) -> tuple[int, int]:
    return state.globals.get("private_stack", (STACK_LOW, STACK_BASE + 4))


def _stack_escape(state: angr.SimState, value: claripy.ast.BV,
                  root: str) -> EscapedRegion | None:
    """Return the private region reachable through ``value``, if any.

    Only values that must address the private stack are escapes. Incoming
    registers and other unconstrained inputs cannot point into a frame that
    did not exist when the caller produced them.
    """
    if value.size() != 32:
        return None
    low, high = _private_stack(state)
    if value.concrete:
        address = value.concrete_value
        if not low <= address < high:
            return None
    else:
        if not _may_address_stack(state, value):
            return None
        inside = claripy.And(value >= low, value < high)
        if not state.solver.is_true(inside):
            return None
        address = state.solver.min(value)
        if state.solver.max(value) >= high:
            return None
    for region in state.globals.get("escaped", ()):
        if region.start <= address < region.end:
            return region
    for allocation in state.globals.get("stack_allocations", ()):
        if allocation.address <= address < allocation.address + allocation.size:
            return EscapedRegion(
                f"alloc:{allocation.logical_id}", allocation.address,
                allocation.address + allocation.size, True,
            )
    end = STACK_BASE if address < STACK_BASE else high
    return EscapedRegion(f"escape:{root}", address, end, False)


def _add_escape(state: angr.SimState, region: EscapedRegion) -> None:
    """Record ``region`` and every private region reachable from its words."""
    pending = [region]
    while pending:
        current = pending.pop()
        known = state.globals.get("escaped", ())
        if any(item.key == current.key for item in known):
            continue
        state.globals["escaped"] = (*known, current)
        # Pointers stored inside escaped memory escape with it.
        for offset in range(0, (current.end - current.start) & ~3, 4):
            word = state.memory.load(
                current.start + offset, 4, endness=state.arch.memory_endness,
                disable_actions=True, inspect=False,
            )
            if word.concrete:
                nested = _stack_escape(state, word, f"{current.key}+{offset}")
                if nested is not None:
                    pending.append(nested)


def _lazy_symbol(address: int, epoch: int) -> claripy.ast.BV:
    return claripy.BVS(f"lazy_{address:x}_{epoch}", 8, explicit_name=True)


def _outside_lazy_memory(state: angr.SimState, start: int, end: int) -> bool:
    """True when [start, end) lies wholly in explicitly modeled storage."""
    low, high = _private_stack(state)
    if low <= start and end <= high:
        return True
    code_start, code_size = state.globals.get("code_region", (0, 0))
    if code_start <= start and end <= code_start + code_size:
        return True
    return any(region_start <= start and end <= region_end
               for region_start, region_end in state.globals.get("declared_ranges", ()))


def _lazy_byte(state: angr.SimState, address: int) -> bool:
    return not _outside_lazy_memory(state, address, address + 1)


def _materialize_lazy(state: angr.SimState, address: int, length: int) -> None:
    """Give never-touched undeclared bytes their shared, address-named value.

    Named globals resolve to the same address on both sides, so a byte at a
    concrete address is the same storage in both executions. Its value is a
    symbol named by address and call epoch, identical on both sides, instead
    of a declared object: nothing is modeled until it is touched.
    """
    if length <= 0 or _outside_lazy_memory(state, address, address + length):
        return
    live = state.globals.get("lazy_live", frozenset())
    epoch = state.globals.get("lazy_epoch", 0)
    slots = state.globals.get("pointer_slots") or {}
    if slots:
        # A modeled pointer slot holds its case's pointer value, not bytes of
        # an arbitrary value.
        injected: set[int] = set()
        for start in range(address - 3, address + length):
            value = slots.get((start, epoch))
            if value is None or any(start + index in live for index in range(4)):
                continue
            state.memory.store(
                start, claripy.BVV(value, 32), endness=state.arch.memory_endness,
                inspect=False, disable_actions=True,
            )
            injected.update(range(start, start + 4))
        if injected:
            live = live | frozenset(injected)
            state.globals["lazy_live"] = live
    new = [
        byte for byte in range(address, address + length)
        if byte not in live and _lazy_byte(state, byte)
    ]
    for byte in new:
        state.memory.store(byte, _lazy_symbol(byte, epoch), inspect=False, disable_actions=True)
    if new:
        state.globals["lazy_live"] = live | frozenset(new)


def _lazy_value(state: angr.SimState, byte: int, epoch: int | None = None) -> claripy.ast.BV:
    """Current value of a lazily modeled byte, touched or not."""
    if byte in state.globals.get("lazy_live", frozenset()):
        return state.memory.load(byte, 1, inspect=False, disable_actions=True)
    return _lazy_symbol(byte, state.globals.get("lazy_epoch", 0) if epoch is None else epoch)


def _lazy_snapshot(state: angr.SimState) -> tuple[tuple[int, claripy.ast.BV], ...]:
    return tuple(
        (byte, state.memory.load(byte, 1, inspect=False, disable_actions=True))
        for byte in sorted(state.globals.get("lazy_live", frozenset()))
    )


def _region_chunks(region: EscapedRegion):
    size = region.end - region.start
    for offset in range(0, size, 4):
        yield offset, min(4, size - offset)


def _escaped_observations(state: angr.SimState):
    definite: list[tuple[str, claripy.ast.BV]] = []
    uncertain: list[tuple[str, claripy.ast.BV]] = []
    for region in state.globals.get("escaped", ()):
        for offset, width in _region_chunks(region):
            value = state.memory.load(
                region.start + offset, width, endness=state.arch.memory_endness,
            )
            (definite if region.definite else uncertain).append(
                (f"{region.key}:{offset}", value),
            )
    return tuple(definite), tuple(uncertain)


def _havoc_escaped(state: angr.SimState, prefix: str) -> None:
    for region in state.globals.get("escaped", ()):
        for offset, width in _region_chunks(region):
            state.memory.store(
                region.start + offset,
                claripy.BVS(f"{prefix}_{region.key}_{offset}", width * 8, explicit_name=True),
                endness=state.arch.memory_endness,
            )


def _external_event(
    state: angr.SimState, name: str, arguments: tuple[claripy.ast.BV, ...],
    memory_regions: tuple[tuple[object, int], ...], *,
    pointer_mask: tuple[bool, ...] = (),
    pointee_sizes: tuple[int | None, ...] = (),
    uncertain_registers: tuple[tuple[str, claripy.ast.BV], ...] = (),
    havoc_memory: bool = True,
) -> tuple[int, str]:
    """Record an external call and apply its conservative effects.

    The callee may read and write declared memory, every pointee it receives,
    and every private stack region that has escaped so far. It also clobbers
    the caller-saved registers ECX and EDX.
    """
    calls = state.globals.get("calls", ())
    ordinal = len(calls)
    digest = hashlib.sha256(name.encode("utf-8")).hexdigest()[:12]
    pointer_mask = pointer_mask or tuple(False for _ in arguments)
    pointee_sizes = pointee_sizes or tuple(None for _ in arguments)
    if len(pointer_mask) != len(arguments) or len(pointee_sizes) != len(arguments):
        raise ValueError(f"call summary for {name} has inconsistent pointer metadata")

    # Any argument, typed or not, that addresses the private stack escapes.
    for index, value in enumerate((*arguments, *(item for _, item in uncertain_registers))):
        region = _stack_escape(state, value, f"{ordinal}.{index}")
        if region is not None:
            _add_escape(state, region)

    snapshot = tuple(
        state.memory.load(address, size, endness=state.arch.memory_endness)
        for address, size in memory_regions
    )
    argument_memory = tuple(
        state.memory.load(argument, size, endness=state.arch.memory_endness)
        if is_pointer and size else None
        for argument, is_pointer, size in zip(arguments, pointer_mask, pointee_sizes, strict=True)
    )
    escaped, guessed = _escaped_observations(state)
    state.globals["calls"] = (*calls, CallEvent(
        name, tuple(arguments), snapshot, tuple(pointer_mask), argument_memory,
        escaped, (*uncertain_registers, *guessed),
        _lazy_snapshot(state), state.globals.get("lazy_epoch", 0),
    ))

    if havoc_memory:
        state.globals["inside_external_call"] = True
        for index, (address, size) in enumerate(memory_regions):
            state.memory.store(
                address,
                claripy.BVS(f"external_memory_{ordinal}_{index}_{digest}", size * 8,
                            explicit_name=True),
                endness=state.arch.memory_endness,
            )
        for index, (argument, is_pointer, size) in enumerate(zip(
                arguments, pointer_mask, pointee_sizes, strict=True)):
            if is_pointer and size:
                state.memory.store(
                    argument,
                    claripy.BVS(f"external_pointee_{ordinal}_{index}_{digest}", size * 8,
                                explicit_name=True),
                    endness=state.arch.memory_endness,
                )
        _havoc_escaped(state, f"external_escaped_{ordinal}_{digest}")
        # Every undeclared byte may have changed: start a new epoch.
        state.globals["lazy_live"] = frozenset()
        state.globals["lazy_epoch"] = state.globals.get("lazy_epoch", 0) + 1
        state.globals["inside_external_call"] = False
    for register in ("ecx", "edx"):
        setattr(state.regs, register, claripy.BVS(
            f"external_clobber_{ordinal}_{digest}_{register}", 32, explicit_name=True,
        ))
    return ordinal, digest


class RecordedCall(angr.SimProcedure):
    def __init__(self, decorated_symbol: str, result: claripy.ast.BV,
                 argument_count: int, argument_registers: tuple[str, ...],
                 fresh_result: bool, havoc_memory: bool,
                 memory_regions: tuple[tuple[object, int], ...],
                 return_register: str,
                 argument_pointer_mask: tuple[bool, ...],
                 argument_pointee_sizes: tuple[int | None, ...],
                 callsite_argument_counts: tuple[tuple[int, int], ...],
                 x87_pops: int = 0,
                 homes: tuple[ParameterHome, ...] = (),
                 widths: tuple[int, ...] = (),
                 cc=None, prototype=None):
        # The prototype only describes the stack words the callee may pop
        # and the return value; arguments are read from their entry homes.
        super().__init__(num_args=len(prototype.args) if prototype else 0,
                         cc=cc, prototype=prototype)
        self.homes = homes
        self.widths = widths
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
        self.x87_pops = x87_pops

    def _read_homes(self, count: int):
        arguments: list[claripy.ast.BV] = []
        uncertain: list[tuple[str, claripy.ast.BV]] = []
        ambiguous: set[int] = set()
        esp = self.state.regs.esp
        for index, (home, width) in enumerate(zip(self.homes[:count], self.widths)):
            values = [
                (register, getattr(self.state.regs, register)[width - 1:0])
                for register in home.registers
            ]
            if home.stack_offset is not None:
                values.append((f"stack{home.stack_offset}", self.state.memory.load(
                    esp + home.stack_offset, width // 8, endness=self.state.arch.memory_endness,
                )))
            if len(values) == 1:
                arguments.append(values[0][1])
                continue
            # The PDB admits several entry ABIs: whichever the caller used,
            # the others hold unrelated bytes. None is a definite observable.
            ambiguous.add(index)
            arguments.append(claripy.BVV(0, width))
            uncertain.extend(
                (f"ambiguous:{index}:{location}", value) for location, value in values
            )
        return tuple(arguments), tuple(uncertain), ambiguous

    def run(self, *_):  # type: ignore[no-untyped-def]
        callsite = self.state.callstack.call_site_addr
        uncertain: tuple[tuple[str, claripy.ast.BV], ...] = ()
        ambiguous: set[int] = set()
        if self.argument_registers:
            arguments = tuple(
                x87_st0(self.state) if register == "x87_st0" else
                getattr(self.state.regs, register)
                for register in self.argument_registers
            )
        else:
            count = self.callsite_argument_counts.get(callsite, len(self.homes))
            arguments, uncertain, ambiguous = self._read_homes(count)
        argument_count = len(arguments)
        pointer_mask = tuple(
            flag and index not in ambiguous
            for index, flag in enumerate(self.argument_pointer_mask[:argument_count])
        ) if self.argument_pointer_mask else ()
        pointee_sizes = (
            self.argument_pointee_sizes[:argument_count]
            if self.argument_pointee_sizes else ()
        )
        ordinal, digest = _external_event(
            self.state, self.decorated_symbol, tuple(arguments), self.memory_regions,
            pointer_mask=pointer_mask, pointee_sizes=pointee_sizes,
            uncertain_registers=uncertain,
            havoc_memory=self.havoc_memory,
        )
        for _ in range(self.x87_pops):
            x87_pop(self.state)
        modeled = (self.state.globals.get("pointer_returns") or {}).get((ordinal, digest))
        if modeled is not None and self.result.size() == 32:
            result = claripy.BVV(modeled, 32)
        elif self.fresh_result:
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
            x87_push(self.state, result)
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


class UnmodeledPointerAccess(angr.errors.SimMemoryAddressError):
    """A memory access through a pointer the model does not bound.

    ``source`` identifies where the pointer came from, when derivable. It is
    carried on the error because angr records the pre-step state.
    """

    def __init__(self, message: str, source: tuple | None = None):
        super().__init__(message)
        self.source = source


class _RejectUnboundedAddress(angr.concretization_strategies.SimConcretizationStrategy):
    """Last concretization strategy: refuse instead of picking a value.

    angr's defaults end with strategies that concretize an unconstrained
    address to one arbitrary solver model and add that equality to the path.
    The chosen model varies between runs and between the two executions, so
    verdicts became nondeterministic. Accesses that no enumerating strategy
    handled are reported as unmodeled instead.
    """

    def _concretize(self, memory, addr, **kwargs):
        raise UnmodeledPointerAccess(
            f"unbounded symbolic address {addr}", pointer_source(memory.state, addr),
        )


LAZY_NAME = re.compile(r"^lazy_([0-9a-f]+)_(\d+)$")
RETURN_NAME = re.compile(r"^external_return_(\d+)_([0-9a-f]+)$")


def pointer_source(state: angr.SimState, address: claripy.ast.BV) -> tuple | None:
    """Identify where the pointer inside ``address`` was loaded from.

    A pointer read from lazily modeled memory is a 4-byte slot at a known
    address and epoch; it is keyed relative to the entity whose pointee
    contains it, or absolutely for other storage. A callee's return value is
    keyed by call ordinal and callee. Anything else is not derivable.
    """
    slots: dict[int, set[int]] = {}
    returns: set[tuple] = set()
    for name in address.variables:
        if match := LAZY_NAME.match(name):
            slots.setdefault(int(match.group(2)), set()).add(int(match.group(1), 16))
        elif match := RETURN_NAME.match(name):
            returns.add(("return", int(match.group(1)), match.group(2)))
    candidates = [
        (epoch, start) for epoch, addresses in slots.items()
        for start in addresses if all(start + index in addresses for index in range(4))
        and start - 1 not in addresses
    ]
    if len(candidates) + len(returns) != 1:
        return None
    if returns:
        return next(iter(returns))
    epoch, slot = candidates[0]
    for key, start, size in state.globals.get("pointer_layout", ()):
        if start <= slot < start + size:
            return ("slot", ("entity", key), slot - start, epoch)
    return ("slot", ("global",), slot, epoch)


def word_homes(sizes) -> tuple[ParameterHome, ...]:
    """cdecl stack homes for untyped arguments of the given byte sizes."""
    homes: list[ParameterHome] = []
    offset = 4
    for size in sizes:
        homes.append(ParameterHome((), offset))
        offset += (size + 3) & ~3
    return tuple(homes)


def _homes_with_varargs(homes: tuple[ParameterHome, ...], count: int) -> tuple[ParameterHome, ...]:
    end = max((home.stack_offset + 4 for home in homes if home.stack_offset is not None), default=4)
    extra = tuple(ParameterHome((), end + 4 * index) for index in range(count - len(homes)))
    return (*homes, *extra)


def _stack_bytes(homes, widths) -> int:
    return max(
        (home.stack_offset + ((width // 8 + 3) & ~3) - 4
         for home, width in zip(homes, widths) if home.stack_offset is not None),
        default=0,
    )


def project(code: bytes, base: int = BASE) -> angr.Project:
    return angr.load_shellcode(code, arch="x86", load_address=base)


# VEX x86 guest state: eight F64 registers, one tag byte per register, and an
# unmasked TOP counter that VEX reduces modulo 8 on every use.
X87_REGISTERS = 72
X87_TAGS = 136


def _x87_physical(state: angr.SimState, depth: int) -> claripy.ast.BV:
    return (state.regs.ftop + depth) & 7


def x87_load(state: angr.SimState, depth: int = 0) -> claripy.ast.BV:
    index = _x87_physical(state, depth)
    values = [state.registers.load(X87_REGISTERS + item * 8, 8) for item in range(8)]
    result = values[7]
    for item in reversed(range(7)):
        result = claripy.If(index == item, values[item], result)
    return result


def x87_store(state: angr.SimState, depth: int, value: claripy.ast.BV,
              tag: int | None = None) -> None:
    index = _x87_physical(state, depth)
    for item in range(8):
        selected = index == item
        state.registers.store(
            X87_REGISTERS + item * 8,
            claripy.If(selected, value, state.registers.load(X87_REGISTERS + item * 8, 8)),
        )
        if tag is not None:
            state.registers.store(
                X87_TAGS + item,
                claripy.If(selected, claripy.BVV(tag, 8),
                           state.registers.load(X87_TAGS + item, 1)),
            )


def x87_push(state: angr.SimState, value: claripy.ast.BV) -> None:
    state.regs.ftop = state.regs.ftop - 1
    x87_store(state, 0, value, tag=1)


def x87_pop(state: angr.SimState) -> None:
    x87_store(state, 0, x87_load(state, 0), tag=0)
    state.regs.ftop = state.regs.ftop + 1


def x87_st0(state: angr.SimState) -> claripy.ast.BV:
    return x87_load(state, 0)


def pure_operation(state: angr.SimState, operation: str,
                   arguments: tuple[claripy.ast.BV, ...],
                   widths: tuple[int, ...]) -> tuple[claripy.ast.BV, ...]:
    """Apply an uninterpreted deterministic operation.

    Results are fresh symbols unique to this application. The verifier adds
    functional-consistency constraints across every application in both
    executions, so equal inputs yield equal outputs regardless of order.
    """
    tag = state.globals["execution_tag"]
    application = next(state.globals["pure_counter"])
    results = tuple(
        claripy.BVS(f"pure_{operation}_{tag}_{application}_{index}", width,
                    explicit_name=True)
        for index, width in enumerate(widths)
    )
    state.globals["pure_operations"] = (
        *state.globals.get("pure_operations", ()),
        (operation, tuple(arguments), results),
    )
    return results


def _x87_partial_trig(state: angr.SimState, value: claripy.ast.BV,
                      result: claripy.ast.BV) -> claripy.ast.BV:
    """Apply FSIN/FCOS/FSINCOS/FPTAN range reduction failure semantics.

    For |x| >= 2**63 the instruction sets C2 and leaves the operand intact.
    """
    exponent = value[62:52]
    out_of_range = claripy.And(exponent >= 0x43E, exponent != 0x7FF)
    state.regs.fc3210 = claripy.If(
        out_of_range, state.regs.fc3210 | 0x400, state.regs.fc3210 & 0xFFFFFBFF,
    )
    return claripy.If(out_of_range, value, result)


def _x87_semantic(operation: str):
    def hook(state: angr.SimState) -> None:
        rounding = state.regs.fpround
        top = x87_load(state, 0)
        if operation in ("fsin", "fcos", "fsqrt", "f2xm1"):
            (result,) = pure_operation(state, operation, (top, rounding), (64,))
            if operation in ("fsin", "fcos"):
                result = _x87_partial_trig(state, top, result)
            x87_store(state, 0, result)
        elif operation == "fsincos":
            (sine,) = pure_operation(state, "fsin", (top, rounding), (64,))
            (cosine,) = pure_operation(state, "fcos", (top, rounding), (64,))
            reduced_sine = _x87_partial_trig(state, top, sine)
            if state.solver.is_true((state.regs.fc3210 & 0x400) == 0):
                x87_store(state, 0, reduced_sine)
                x87_push(state, cosine)
            else:
                # Out of range: operand unchanged and nothing is pushed.
                in_range = (state.regs.fc3210 & 0x400) == 0
                x87_store(state, 0, reduced_sine)
                state.regs.ftop = claripy.If(in_range, state.regs.ftop - 1, state.regs.ftop)
                x87_store(state, 0, claripy.If(in_range, cosine, reduced_sine), tag=1)
        elif operation == "fptan":
            (tangent,) = pure_operation(state, operation, (top, rounding), (64,))
            reduced = _x87_partial_trig(state, top, tangent)
            x87_store(state, 0, reduced)
            # Out of range: C2 is set, the operand stays, and nothing is pushed.
            in_range = (state.regs.fc3210 & 0x400) == 0
            one = claripy.BVV(0x3FF0000000000000, 64)
            if state.solver.is_true(in_range):
                x87_push(state, one)
            elif not state.solver.is_false(in_range):
                state.regs.ftop = claripy.If(in_range, state.regs.ftop - 1, state.regs.ftop)
                x87_store(state, 0, claripy.If(in_range, one, reduced), tag=1)
        elif operation in ("fpatan", "fyl2x", "fyl2xp1"):
            (result,) = pure_operation(
                state, operation, (x87_load(state, 1), top, rounding), (64,),
            )
            x87_store(state, 1, result)
            x87_pop(state)
        elif operation == "fscale":
            (result,) = pure_operation(
                state, operation, (top, x87_load(state, 1), rounding), (64,),
            )
            x87_store(state, 0, result)
        else:
            raise ValueError(f"unknown x87 semantic operation {operation}")
    return hook


# Two-byte x87 encodings that PyVEX lowers to IR operations angr cannot run.
X87_SEMANTIC_OPERATIONS = {
    b"\xd9\xfe": "fsin",
    b"\xd9\xff": "fcos",
    b"\xd9\xfb": "fsincos",
    b"\xd9\xf2": "fptan",
    b"\xd9\xf3": "fpatan",
    b"\xd9\xf0": "f2xm1",
    b"\xd9\xf1": "fyl2x",
    b"\xd9\xf9": "fyl2xp1",
    b"\xd9\xfd": "fscale",
    b"\xd9\xfa": "fsqrt",
}


def _debugbreak(memory_regions: tuple[tuple[object, int], ...]):
    def hook(state: angr.SimState) -> None:
        # __debugbreak is an ordered observable event. Execution continues as
        # it does when a debugger resumes; the memory it could inspect is part
        # of the event.
        state.globals["calls"] = (*state.globals.get("calls", ()), CallEvent(
            "__debugbreak", (), tuple(
                state.memory.load(address, size, endness=state.arch.memory_endness)
                for address, size in memory_regions
            ),
            lazy_memory=_lazy_snapshot(state),
            lazy_epoch=state.globals.get("lazy_epoch", 0),
        ))
    return hook


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


def _scan(code: bytes, pattern: bytes):
    # Linear disassembly can lose synchronization on embedded jump-table
    # bytes, so hook every occurrence. Executed code reaches only genuine
    # instruction boundaries; a hook inside another instruction is inert.
    start = 0
    while (offset := code.find(pattern, start)) >= 0:
        yield offset
        start = offset + 1


def _install_semantic_instruction_hooks(
    proj: angr.Project, code: bytes, base: int,
    memory_regions: tuple[tuple[object, int], ...],
) -> None:
    for pattern, operation in X87_SEMANTIC_OPERATIONS.items():
        for offset in _scan(code, pattern):
            proj.hook(base + offset, _x87_semantic(operation), length=len(pattern))
    for offset in _scan(code, b"\xcc"):
        proj.hook(base + offset, _debugbreak(memory_regions), length=1)

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
            # Without the function-pointer type, ECX and EDX may carry
            # thiscall/fastcall arguments. They are compared as uncertain
            # observables and may also carry escaping stack addresses.
            ordinal, _ = _external_event(
                state, "__indirect_call", (target, *arguments), memory_regions,
                uncertain_registers=(
                    ("register:ecx", state.regs.ecx), ("register:edx", state.regs.edx),
                ),
            )
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


# x87 instructions that neither VEX/angr nor a semantic hook can execute.
# FPREM/FPREM1 report partial remainders through C2 and are normally looped.
UNSUPPORTED_X87_INSTRUCTIONS = {
    "fprem", "fprem1", "fxtract", "fxam", "fbld", "fbstp",
    "fstenv", "fnstenv", "fldenv", "fsave", "fnsave", "frstor",
}


def unsupported_instructions(code: bytes, base: int) -> tuple[str, ...]:
    engine = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    engine.detail = True
    issues: list[str] = []
    consumed = 0
    for instruction in engine.disasm(code, base):
        consumed += instruction.size
        if 0xF0 in instruction.prefix or (
                # XCHG with a memory operand is implicitly locked.
                instruction.mnemonic == "xchg" and any(
                    operand.type == capstone.x86_const.X86_OP_MEM
                    for operand in instruction.operands)):
            issues.append(f"UNSUPPORTED_ATOMIC_INSTRUCTION:0x{instruction.address:x}")
        if instruction.mnemonic in UNSUPPORTED_X87_INSTRUCTIONS:
            issues.append(
                f"UNSUPPORTED_X87_INSTRUCTION:{instruction.mnemonic}:0x{instruction.address:x}"
            )
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
    entry_homes: tuple[ParameterHome, ...] | None = None,
    pointer_slots: dict[tuple[int, int], int] | None = None,
    pointer_returns: dict[tuple[int, str], int] | None = None,
    pointer_layout: tuple[tuple[tuple, int, int], ...] = (),
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
            if target.signature:
                _prototype(proj, target.signature, target.argument_count)  # validates arity
                homes = target.entry_homes or standard_parameter_homes(target.signature)
                widths = tuple(item.size * 8 for item in target.signature.parameters)
            else:
                homes = word_homes((4,) * target.argument_count)
                widths = ()
            homes = _homes_with_varargs(homes, target.argument_count)
            widths = (*widths, *(32,) * (len(homes) - len(widths)))
            if any(home.registers and width > 32 for home, width in zip(homes, widths)):
                raise ValueError("register parameter wider than 32 bits")
            convention = (target.signature.calling_convention.lower()
                          if target.signature else "nearc")
            callee_cleanup = convention not in ("nearc", "cdecl", "nearvector")
            target_cc = (angr.calling_conventions.SimCCStdcall(proj.arch) if callee_cleanup
                         else angr.calling_conventions.SimCCMicrosoftCdecl(proj.arch))
            word = SimTypeNum(32, signed=False).with_arch(proj.arch)
            target_prototype = SimTypeFunction(
                [word] * (_stack_bytes(homes, widths) // 4),
                _sim_type(target.signature.return_type, proj.arch) if target.signature else word,
            ).with_arch(proj.arch)
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
            target.x87_pops, homes, widths, target_cc, target_prototype,
        ))

    try:
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
            homes = entry_homes or standard_parameter_homes(signature)
        else:
            homes = entry_homes or word_homes(argument.size() // 8 for argument in arguments)
        if len(homes) != len(arguments):
            raise ValueError("entry homes do not match the arguments")
        if any(home.registers and argument.size() > 32
               for home, argument in zip(homes, arguments)):
            raise ValueError("register parameter wider than 32 bits")
    except ValueError as error:
        return Execution(
            [], False, (f"UNSUPPORTED_PDB_ABI:{error}",), constraints,
            memory_regions, signature,
            stack_allocations,
        )
    state = proj.factory.call_state(
        base,
        cc=angr.calling_conventions.SimCCMicrosoftCdecl(proj.arch),
        prototype=SimTypeFunction([], SimTypeBottom(label="void")).with_arch(proj.arch),
        ret_addr=RETURN_SENTINEL,
        stack_base=STACK_BASE,
    )
    # Both programs execute from the same incoming machine state.  Letting
    # angr lazily create unconstrained register values is unsound here: its
    # process-global name allocator gives the two executions different symbols,
    # so even identical `ret` functions can appear to return different EAX
    # values.  Explicit names also make proofs independent of exploration and
    # test order.  ESP/EIP are established by call_state; parameter homes
    # below override these defaults.
    for register in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp"):
        setattr(
            state.regs, register,
            claripy.BVS(f"incoming_{register}", 32, explicit_name=True),
        )
    # Place every argument in each of its entry homes. Bits a narrow value
    # does not define are shared, unconstrained garbage.
    argument_end = 4
    ambiguous_entry = False
    for index, (argument, home) in enumerate(zip(arguments, homes, strict=True)):
        width = argument.size()
        # With several possible entry locations, the argument goes to the one
        # the PDB records (the register) and every other location receives an
        # independent value: a caller of either ABI sets only one of them.
        # Equivalence over independent values holds for every real caller.
        primary = home.registers[-1] if home.registers else "stack"
        ambiguous_entry |= home.locations > 1

        def value_for(location: str):
            if location == primary:
                return argument
            return claripy.BVS(f"ambiguous_home_{index}_{location}", width, explicit_name=True)

        for register in home.registers:
            value = value_for(register)
            setattr(state.regs, register, value if width == 32 else claripy.Concat(
                claripy.BVS(f"incoming_{register}_upper", 32 - width, explicit_name=True),
                value,
            ))
        if home.stack_offset is not None:
            address = STACK_BASE + home.stack_offset
            state.memory.store(address, value_for("stack"), endness=proj.arch.memory_endness)
            slot = (width // 8 + 3) & ~3
            if slot > width // 8:
                state.memory.store(
                    address + width // 8,
                    claripy.BVS(f"incoming_stack_padding_{home.stack_offset}",
                                (slot - width // 8) * 8, explicit_name=True),
                )
            argument_end = max(argument_end, home.stack_offset + slot)
    # The callee owns its frame, the return-address slot and its incoming
    # argument slots. Bytes above the arguments belong to the caller.
    private_stack = (STACK_LOW, STACK_BASE + argument_end)
    code_region = (base, len(code))
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
    state.globals["private_stack"] = private_stack
    state.globals["escaped"] = ()
    state.globals["execution_tag"] = next(_EXECUTION_TAGS)
    # Shared (not copied) by every path of this execution, so each pure
    # operation application receives a unique result symbol.
    state.globals["pure_counter"] = itertools.count()
    state.globals["pure_operations"] = ()
    state.solver.add(*constraints)
    for register, value in initial_registers:
        setattr(state.regs, register, value)
    for address, value in initial_memory:
        state.memory.store(address, value, endness=proj.arch.memory_endness)
    allocation_ids: set[str] = set()
    allocation_ranges: list[tuple[int, int]] = []
    for allocation in stack_allocations:
        if (allocation.logical_id in allocation_ids or allocation.size <= 0 or
                not private_stack[0] <= allocation.address or
                allocation.address + allocation.size > private_stack[1] or
                any(allocation.address < end and start < allocation.address + allocation.size
                    for start, end in allocation_ranges)):
            return Execution(
                [], False, (f"UNMODELED_STACK_ALLOCATION:{allocation.logical_id}",),
                constraints, memory_regions, signature, stack_allocations,
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
    state.globals["memory_reads"] = None
    state.globals["memory_writes"] = None
    state.globals["code_region"] = code_region
    state.globals["declared_ranges"] = tuple(sorted(
        (address, address + value.size() // 8) for address, value in initial_memory
    ))
    state.globals["lazy_live"] = frozenset()
    state.globals["lazy_epoch"] = 0
    state.globals["pointer_slots"] = dict(pointer_slots or {})
    state.globals["pointer_returns"] = dict(pointer_returns or {})
    state.globals["pointer_layout"] = tuple(pointer_layout)
    state.memory.read_strategies = [
        angr.concretization_strategies.SimConcretizationStrategyRange(1024),
        _RejectUnboundedAddress(),
    ]
    state.memory.write_strategies = [
        angr.concretization_strategies.SimConcretizationStrategyRange(128),
        _RejectUnboundedAddress(),
    ]

    def record_read(current: angr.SimState) -> None:
        address = current.inspect.attrs.mem_read_address
        length = current.inspect.attrs.mem_read_length
        if address is not None and length is not None:
            size = _as_length(length)
            if getattr(address, "concrete", False) and size is not None:
                _materialize_lazy(current, address.concrete_value, size)
            current.globals["memory_reads"] = (
                (address, length), current.globals.get("memory_reads"),
            )

    def record_write(current: angr.SimState) -> None:
        if current.globals.get("inside_external_call", False):
            return
        address = current.inspect.attrs.mem_write_address
        length = current.inspect.attrs.mem_write_length
        if address is not None and length is not None:
            size = _as_length(length)
            if getattr(address, "concrete", False) and size is not None:
                # Materialize first so a partial write overlays the shared value.
                _materialize_lazy(current, address.concrete_value, size)
            # Publishing a private stack address in external memory lets any
            # later callee reach that object.
            stored = current.inspect.attrs.mem_write_expr
            low, high = _private_stack(current)
            external = not getattr(address, "concrete", False) or not (
                low <= address.concrete_value < high)
            if external and stored is not None and stored.size() == 32:
                root = (f"store@{address.concrete_value:x}"
                        if getattr(address, "concrete", False) else "store@symbolic")
                region = _stack_escape(current, stored, root)
                if region is not None:
                    _add_escape(current, region)
            current.globals["memory_writes"] = (
                (address, length), current.globals.get("memory_writes"),
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
                "UNMODELED_POINTER_ACCESS"
                if isinstance(item.error, UnmodeledPointerAccess) else
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
    sources = tuple(dict.fromkeys(
        item.error.source for item in manager.errored
        if isinstance(item.error, UnmodeledPointerAccess) and item.error.source is not None
    ))
    return Execution(
        list(manager.returned), not issues, tuple(dict.fromkeys(issues)),
        initialized_constraints, memory_regions, signature, stack_allocations,
        code_region, private_stack, ambiguous_entry, sources,
    )


def path_condition(state: angr.SimState) -> claripy.ast.Bool:
    return claripy.And(*state.solver.constraints)


class _Differences:
    """Definite observable differences plus differences whose observability
    depends on an unknown contract, grouped by the missing contract."""

    def __init__(self) -> None:
        self.definite: list[claripy.ast.Bool] = []
        self.uncertain: dict[str, list[claripy.ast.Bool]] = {}

    def add(self, difference: claripy.ast.Bool) -> None:
        self.definite.append(difference)

    def maybe(self, kind: str, difference: claripy.ast.Bool) -> None:
        self.uncertain.setdefault(kind, []).append(difference)


def _may_address_stack(state: angr.SimState, value: claripy.ast.BV) -> bool:
    """Cheap structural test before asking the solver.

    ESP is concrete, so a symbolic expression can only denote a private stack
    address when it is built from a constant in the private stack range.
    """
    low, high = _private_stack(state)
    return any(
        leaf.op == "BVV" and low <= leaf.args[0] < high
        for leaf in value.leaf_asts()
    )


def _logical_pointer(state: angr.SimState, value: claripy.ast.BV) -> tuple:
    """Map a private stack address to allocation identity plus offset."""
    if value.size() != 32:
        return ("raw", value)
    if value.concrete:
        concrete = value.concrete_value
    elif not _may_address_stack(state, value) or not state.solver.unique(value):
        return ("raw", value)
    else:
        concrete = state.solver.eval(value)
    low, high = _private_stack(state)
    if not low <= concrete < high:
        return ("raw", value)
    for allocation in state.globals.get("stack_allocations", ()):
        if allocation.address <= concrete < allocation.address + allocation.size:
            return ("allocation", allocation.logical_id, concrete - allocation.address)
    for region in state.globals.get("escaped", ()):
        if region.start <= concrete < region.end:
            return ("escape", region.key, concrete - region.start)
    return ("stack", concrete)


def _compare_values(
    differences: _Differences,
    left_state: angr.SimState, left: claripy.ast.BV,
    right_state: angr.SimState, right: claripy.ast.BV,
) -> None:
    """Compare values that may be private stack addresses.

    Stack layouts are not observable, so such addresses are compared by
    logical identity. An address inside no known object has no identity.
    """
    if left.size() != right.size():
        differences.add(claripy.true())
        return
    lhs = _logical_pointer(left_state, left)
    rhs = _logical_pointer(right_state, right)
    if lhs[0] == "raw" and rhs[0] == "raw":
        differences.add(left != right)
    elif lhs[0] == "stack" or rhs[0] == "stack":
        differences.maybe("UNIDENTIFIED_STACK_ADDRESS", claripy.true())
    else:
        differences.add(claripy.BoolV(lhs != rhs))


def _pointer_difference(
    left_state: angr.SimState, left: claripy.ast.BV,
    right_state: angr.SimState, right: claripy.ast.BV,
) -> claripy.ast.Bool:
    differences = _Differences()
    _compare_values(differences, left_state, left, right_state, right)
    return _or(differences.definite + sum(differences.uncertain.values(), []))


_UNCERTAIN_KINDS = {
    "register": "INDIRECT_CALL_REGISTER_ARGUMENTS",
    "ambiguous": "AMBIGUOUS_PARAMETER_HOME",
    "escape": "ESCAPED_STACK_EXTENT_UNKNOWN",
}


def calls_differ(left: angr.SimState, right: angr.SimState,
                 differences: _Differences | None = None) -> claripy.ast.Bool:
    """Compare ordered external events; return the definite difference."""
    differences = differences if differences is not None else _Differences()
    lhs = left.globals.get("calls", ())
    rhs = right.globals.get("calls", ())
    if len(lhs) != len(rhs):
        differences.add(claripy.true())
        return claripy.true()
    for lhs_call, rhs_call in zip(lhs, rhs, strict=True):
        if (lhs_call.name != rhs_call.name or
                len(lhs_call.arguments) != len(rhs_call.arguments) or
                lhs_call.pointer_mask != rhs_call.pointer_mask or
                len(lhs_call.snapshot) != len(rhs_call.snapshot)):
            differences.add(claripy.true())
            continue
        for lhs_value, rhs_value in zip(lhs_call.arguments, rhs_call.arguments, strict=True):
            _compare_values(differences, left, lhs_value, right, rhs_value)
        for lhs_value, rhs_value in zip(lhs_call.snapshot, rhs_call.snapshot, strict=True):
            differences.add(lhs_value != rhs_value)
        for lhs_value, rhs_value in zip(
                lhs_call.argument_memory, rhs_call.argument_memory, strict=True):
            if lhs_value is None or rhs_value is None:
                differences.add(claripy.BoolV((lhs_value is None) != (rhs_value is None)))
            elif lhs_value.size() != rhs_value.size():
                differences.add(claripy.true())
            else:
                differences.add(lhs_value != rhs_value)
        lhs_escaped = dict(lhs_call.escaped_memory)
        rhs_escaped = dict(rhs_call.escaped_memory)
        for key in lhs_escaped.keys() & rhs_escaped.keys():
            _compare_values(differences, left, lhs_escaped[key], right, rhs_escaped[key])
        if lhs_escaped.keys() != rhs_escaped.keys():
            differences.maybe("ESCAPED_OBJECT_EXTENT_MISMATCH", claripy.true())
        _compare_lazy(differences, left, lhs_call.lazy_memory, lhs_call.lazy_epoch,
                      right, rhs_call.lazy_memory, rhs_call.lazy_epoch)
        lhs_uncertain = dict(lhs_call.uncertain)
        rhs_uncertain = dict(rhs_call.uncertain)
        for key in lhs_uncertain.keys() | rhs_uncertain.keys():
            kind = _UNCERTAIN_KINDS.get(key.split(":", 1)[0], "UNCERTAIN_OBSERVABLE")
            if key in lhs_uncertain and key in rhs_uncertain:
                lhs_value, rhs_value = lhs_uncertain[key], rhs_uncertain[key]
                differences.maybe(
                    kind,
                    lhs_value != rhs_value if lhs_value.size() == rhs_value.size()
                    else claripy.true(),
                )
            else:
                differences.maybe(kind, claripy.true())
    return _or(differences.definite)


def _compare_lazy(differences: _Differences,
                  left: angr.SimState, lhs: tuple, lhs_epoch: int,
                  right: angr.SimState, rhs: tuple, rhs_epoch: int) -> None:
    """Compare lazily modeled bytes touched by either side.

    A byte one side never touched in this epoch still holds that epoch's
    shared symbol there.
    """
    lhs_values, rhs_values = dict(lhs), dict(rhs)
    for byte in sorted(lhs_values.keys() | rhs_values.keys()):
        left_value = lhs_values.get(byte, _lazy_symbol(byte, lhs_epoch))
        right_value = rhs_values.get(byte, _lazy_symbol(byte, rhs_epoch))
        differences.add(left_value != right_value)


def _pure_applications(states) -> list[tuple[str, tuple, tuple]]:
    unique: dict[str, tuple[str, tuple, tuple]] = {}
    for state in states:
        for application in state.globals.get("pure_operations", ()):
            unique.setdefault(application[2][0].args[0], application)
    return list(unique.values())


def functional_consistency(states) -> claripy.ast.Bool:
    """Ackermann constraints: equal pure-operation inputs give equal outputs."""
    applications = _pure_applications(states)
    constraints: list[claripy.ast.Bool] = []
    for index, (operation, arguments, results) in enumerate(applications):
        for other_operation, other_arguments, other_results in applications[index + 1:]:
            if operation != other_operation or len(arguments) != len(other_arguments):
                continue
            constraints.append(claripy.Or(
                *(left != right for left, right in zip(arguments, other_arguments)),
                claripy.And(*(left == right for left, right in zip(results, other_results))),
            ))
    return claripy.And(*constraints) if constraints else claripy.true()


def _or(values: list[claripy.ast.Bool]) -> claripy.ast.Bool:
    return claripy.Or(*values) if values else claripy.false()


def access_log(state: angr.SimState, key: str):
    """Recorded (address, length) accesses, newest first.

    Logs are immutable linked lists: appending is O(1) and forked paths share
    their common prefix instead of copying a tuple on every access.
    """
    node = state.globals.get(key)
    while node is not None:
        yield node[0]
        node = node[1]


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
    low, high = execution.private_stack
    stack_regions: tuple[tuple[object, int], ...] = ((low, high - low),)
    code_regions = (execution.code_region,) if execution.code_region else ()
    readable = execution.readable_regions + stack_regions + code_regions
    writable: tuple[tuple[object, int], ...] = tuple(observed_memory) + stack_regions
    for state in execution.states:
        # One solver per path; each access is an extra-constraint query.
        solver = None
        checked: set[tuple] = set()
        for kind, regions in (("READ", readable), ("WRITE", writable)):
            accesses = access_log(state, f"memory_{kind.lower()}s")
            for address, raw_length in accesses:
                length = _as_length(raw_length)
                if length is None:
                    issues.append(f"SYMBOLIC_{kind}_SIZE")
                    continue
                # Concrete undeclared addresses are modeled lazily by address,
                # except that the function's own code is not writable.
                if getattr(address, "concrete", False):
                    start = address.concrete_value
                    code_start, code_size = execution.code_region or (0, 0)
                    if not (kind == "WRITE" and start < code_start + code_size and
                            code_start < start + length):
                        continue
                key = (kind, address.hash() if hasattr(address, "hash") else address, length)
                if key in checked:
                    continue
                checked.add(key)
                covered = _or([
                    _inside_region(address, length, start, size)
                    for start, size in regions
                ])
                if solver is None:
                    solver = claripy.Solver()
                    solver.add(path_condition(state))
                if solver.satisfiable(extra_constraints=(claripy.Not(covered),)):
                    issues.append(f"UNMODELED_EXTERNAL_{kind}")
    return tuple(dict.fromkeys(issues))


def bounded_external_regions(
    executions: tuple[Execution, ...],
    known_regions: tuple[tuple[int, int], ...] = (),
    maximum_region_size: int = MAXIMUM_BOUNDED_REGION,
) -> tuple[tuple[int, int], ...]:
    """Discover finite concrete ranges behind symbolic memory accesses.

    This covers bounded table indexing while refusing unconstrained pointers,
    whose 32-bit range would exceed the cap and remains model-incomplete.
    """
    discovered: list[tuple[int, int]] = []
    known = list(known_regions)
    for execution in executions:
        low, high = execution.private_stack
        known.append((low, high - low))
        # Reads of the function's own bytes (jump tables) are modeled by the
        # code itself; declaring them as symbolic memory would erase them.
        if execution.code_region:
            known.append(execution.code_region)
    for execution in executions:
        for state in execution.states:
            for kind in ("reads", "writes"):
                for address, raw_length in access_log(state, f"memory_{kind}"):
                    length = _as_length(raw_length)
                    if length is None:
                        continue
                    if getattr(address, "concrete", False):
                        continue  # modeled lazily by address
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
        functional_consistency((*reference.states, *candidate.states)),
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

    if return_register not in ("eax", "x87_st0", "edx_eax"):
        return VerificationResult(
            VerificationStatus.UNSUPPORTED,
            reasons=(f"UNSUPPORTED_RETURN_REGISTER:{return_register}",),
        )
    solver = claripy.Solver()
    mismatches: list[claripy.ast.Bool] = []
    uncertain: dict[str, list[claripy.ast.Bool]] = {}
    for lhs in reference.states:
        for rhs in candidate.states:
            shared_path = claripy.And(path_condition(lhs), path_condition(rhs))
            differences = _Differences()
            calls_differ(lhs, rhs, differences)
            # Stale x87 condition codes (C0-C3) are not part of the contract;
            # VEX keeps TOP unreduced, so compare it modulo the stack size.
            for difference in (
                lhs.regs.fptag != rhs.regs.fptag,
                lhs.regs.fpround != rhs.regs.fpround,
                (lhs.regs.ftop & 7) != (rhs.regs.ftop & 7),
                lhs.regs.sseround != rhs.regs.sseround,
            ):
                differences.add(difference)
            if compare_return:
                if return_register == "eax":
                    lhs_return = lhs.regs.eax[return_bits - 1:0]
                    rhs_return = rhs.regs.eax[return_bits - 1:0]
                    if return_pointer:
                        _compare_values(differences, lhs, lhs_return, rhs, rhs_return)
                    else:
                        differences.add(lhs_return != rhs_return)
                elif return_register == "x87_st0":
                    differences.add(x87_st0(lhs) != x87_st0(rhs))
                else:
                    differences.add(
                        claripy.Concat(lhs.regs.edx, lhs.regs.eax) !=
                        claripy.Concat(rhs.regs.edx, rhs.regs.eax)
                    )
            _compare_lazy(
                differences,
                lhs, _lazy_snapshot(lhs), lhs.globals.get("lazy_epoch", 0),
                rhs, _lazy_snapshot(rhs), rhs.globals.get("lazy_epoch", 0),
            )
            for address, size in observed_memory:
                differences.add(
                    lhs.memory.load(address, size, endness=lhs.arch.memory_endness) !=
                    rhs.memory.load(address, size, endness=rhs.arch.memory_endness)
                )
            for address, size in pointer_observations:
                _compare_values(
                    differences,
                    lhs, lhs.memory.load(address, size, endness=lhs.arch.memory_endness),
                    rhs, rhs.memory.load(address, size, endness=rhs.arch.memory_endness),
                )
            mismatches.append(claripy.And(shared_path, _or(differences.definite)))
            for kind, values in differences.uncertain.items():
                uncertain.setdefault(kind, []).append(claripy.And(shared_path, _or(values)))
    solver.add(claripy.And(assumptions, _or(mismatches)))
    if solver.satisfiable():
        if reference.ambiguous_entry or candidate.ambiguous_entry:
            # The difference may only reflect the two sides reading different
            # candidate locations of a parameter whose real ABI is unknown.
            return VerificationResult(
                VerificationStatus.MODEL_INCOMPLETE, reasons=("AMBIGUOUS_PARAMETER_HOME",),
            )
        return VerificationResult(
            VerificationStatus.NOT_EQUIVALENT,
            tuple(solver.eval(value, 1)[0] for value in inputs),
        )
    # No definite difference exists. A possible difference in an observable
    # whose contract is unknown leaves the model incomplete, never equivalent.
    unresolved = []
    for kind, values in sorted(uncertain.items()):
        uncertain_solver = claripy.Solver()
        uncertain_solver.add(claripy.And(assumptions, _or(values)))
        if uncertain_solver.satisfiable():
            unresolved.append(kind)
    if unresolved:
        return VerificationResult(VerificationStatus.MODEL_INCOMPLETE, reasons=tuple(unresolved))
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


# Executions per alias case while undeclared bounded regions keep appearing.
DISCOVERY_ROUNDS = 6
# Pointers discovered during execution that may become alias entities.
MAXIMUM_DERIVED_POINTERS = 6
# Pointee extent assumed when the PDB does not type a discovered pointer.
DEFAULT_POINTEE_SIZE = 64


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
    maximum_cases: int | None = 4096,
    global_objects: tuple[object, ...] = (),
    pointer_globals: tuple[object, ...] = (),
    execute_options: dict[str, object] | None = None,
    total_timeout_seconds: float | None = None,
    reference_stack_allocations: tuple[LogicalAllocation, ...] = (),
    candidate_stack_allocations: tuple[LogicalAllocation, ...] = (),
    placements=None,
    reference_entry_homes: tuple[ParameterHome, ...] | None = None,
    candidate_entry_homes: tuple[ParameterHome, ...] | None = None,
    pointer_types=None,
    maximum_derived_pointers: int = MAXIMUM_DERIVED_POINTERS,
) -> VerificationResult:
    """Prove every null/alias/placement/order case admitted by PDB types.

    A signature without pointers yields a single fully symbolic case, so this
    is the one driver for every function. Each case executes both sides,
    declares bounded tables they index, and re-executes when needed.

    Pointers the function loads from memory or receives from callees are
    discovered during execution. Each becomes a further alias-model entity
    (null, a fresh object, or aliasing a compatible object) and enumeration
    restarts, up to ``maximum_derived_pointers``. ``pointer_types(type,
    offset)`` returns the PDB (pointee type, pointee size) of a pointer field.
    """
    from alias_model import AliasCaseLimit, DerivedPointer, iter_alias_scenarios

    options = dict(execute_options or {})
    deadline = (
        time.monotonic() + total_timeout_seconds
        if total_timeout_seconds is not None else None
    )
    # Pointer-valued globals are pointer slots discovered up front.
    derived: list[DerivedPointer] = [
        DerivedPointer(
            ("slot", ("global",), item.address, 0), item.pointee_size,
            getattr(item, "pointee_type", None),
        )
        for item in pointer_globals
    ]
    parameter_types = {
        ("param", index): (parameter.pointee_type, parameter.pointee_size)
        for index, parameter in enumerate(signature.parameters) if parameter.pointer
    }

    def describe(source: tuple) -> DerivedPointer:
        """Type a discovered pointer from the PDB where its origin allows."""
        described = None
        if source[0] == "return":
            for call in reference_calls:
                digest = hashlib.sha256(call.decorated_symbol.encode("utf-8")).hexdigest()[:12]
                if digest == source[2] and call.signature and call.signature.return_type.pointer:
                    returned = call.signature.return_type
                    described = (returned.pointee_type, returned.pointee_size)
        elif pointer_types is not None:
            _, root, offset, _ = source
            if root == ("global",):
                owner = next((
                    item for item in global_objects
                    if item.address <= offset < item.address + item.size
                ), None)
                if owner is not None and owner.type_index is not None:
                    described = pointer_types(owner.type_index, offset - owner.address)
            else:
                parent = parameter_types.get(root[1]) or next((
                    (item.pointee_type, item.pointee_size)
                    for item in derived if item.key == root[1]
                ), None)
                if parent is not None and parent[0] is not None:
                    described = pointer_types(parent[0], offset)
        pointee_type, pointee_size = described or (None, None)
        return DerivedPointer(source, pointee_size or DEFAULT_POINTEE_SIZE, pointee_type)

    def pointer_model(scenario):
        values = dict(scenario.pointer_values)
        sizes = {
            **{key: size for key, (_, size) in parameter_types.items()},
            **{item.key: item.pointee_size for item in derived},
        }
        layout = tuple(
            (key, value, sizes[key]) for key, value in scenario.pointer_values
            if value and key in sizes
        )
        slots: dict[tuple[int, int], int] = {}
        returns: dict[tuple[int, str], int] = {}
        for item in derived:
            if item.key[0] == "slot":
                _, root, offset, epoch = item.key
                base = 0 if root == ("global",) else values.get(root[1], 0)
                slots[(base + offset, epoch)] = values[item.key]
            else:
                returns[(item.key[1], item.key[2])] = values[item.key]
        return {"pointer_slots": slots, "pointer_returns": returns, "pointer_layout": layout}

    def run(code, calls, base, allocations, homes, arguments, memory, share, model):
        run_options = dict(options)
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            configured = run_options.get("timeout_seconds")
            budget = remaining * share
            run_options["timeout_seconds"] = (
                min(float(configured), budget) if configured is not None else budget
            )
        return execute(
            code, arguments, calls, call_results, memory, base=base,
            signature=signature, frontend_issues=frontend_issues,
            stack_allocations=allocations, entry_homes=homes, **model, **run_options,
        )

    while True:
        known = {item.key for item in derived}
        try:
            scenarios = iter(iter_alias_scenarios(
                signature, globals=global_objects,
                maximum_cases=maximum_cases, placements=placements,
                derived=tuple(derived),
            ))
        except ValueError as error:
            return VerificationResult(
                VerificationStatus.MODEL_INCOMPLETE,
                reasons=(f"ALIAS_MODEL_INCOMPLETE:{error}",),
            )
        incomplete: VerificationResult | None = None
        processed_cases = 0
        restart = False
        while True:
            try:
                scenario = next(scenarios)
            except StopIteration:
                break
            except (AliasCaseLimit, ValueError) as error:
                return VerificationResult(
                    VerificationStatus.MODEL_INCOMPLETE,
                    reasons=(f"ALIAS_MODEL_INCOMPLETE:{error}",),
                )
            model = pointer_model(scenario)
            memory = (*common_memory, *scenario.initial_memory)
            observed = (
                *observed_memory,
                *((address, value.size() // 8) for address, value in scenario.initial_memory),
            )
            executions = None
            for attempt in range(DISCOVERY_ROUNDS):
                reference = run(reference_code, reference_calls, reference_base,
                                reference_stack_allocations, reference_entry_homes,
                                scenario.arguments, memory, 0.5, model)
                candidate = run(candidate_code, candidate_calls, candidate_base,
                                candidate_stack_allocations, candidate_entry_homes,
                                scenario.arguments, memory, 1.0, model)
                if reference is None or candidate is None:
                    return VerificationResult(
                        VerificationStatus.INCONCLUSIVE, reasons=("ALIAS_CAMPAIGN_TIMEOUT",),
                    )
                executions = (reference, candidate)
                extra_regions = (
                    bounded_external_regions(executions, observed)
                    if attempt + 1 < DISCOVERY_ROUNDS else ()
                )
                if not extra_regions:
                    break
                # Accesses to undeclared bounded ranges (tables) reveal finite
                # regions; declare them as shared, observed memory and execute
                # again until none remain. Whatever is still undeclared fails
                # the access check.
                memory = (*memory, *(
                    (address, claripy.BVS(
                        f"alias_bounded_{address:x}_{size}", size * 8, explicit_name=True,
                    ))
                    for address, size in extra_regions
                ))
                observed = (*observed, *extra_regions)
            discovered = [
                source for execution in executions for source in execution.pointer_sources
                if source not in known
            ]
            if discovered:
                discovered = list(dict.fromkeys(discovered))
                if len(derived) + len(discovered) > maximum_derived_pointers:
                    return VerificationResult(
                        VerificationStatus.MODEL_INCOMPLETE,
                        reasons=(f"ALIAS_SCENARIO:{scenario.name}", "POINTER_DEPTH_LIMIT"),
                    )
                derived.extend(describe(source) for source in discovered)
                restart = True
                break
            symbolic_inputs = tuple(
                value for value in scenario.arguments if value.symbolic
            ) + tuple(value for _, value in scenario.initial_memory)
            result = verify_equivalence(
                *executions, symbolic_inputs,
                observed_memory=observed,
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
            if result.status == VerificationStatus.INCONCLUSIVE:
                # The function can no longer be proved. Later cases could only
                # find a counterexample, and a case that exhausted its limits
                # predicts the rest will too; stop spending the budget.
                return incomplete
            processed_cases += 1
            del executions, result
            if processed_cases % 8 == 0:
                gc.collect()
        if not restart:
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
