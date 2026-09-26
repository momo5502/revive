"""Finite relational allocation cases derived from PDB pointer types.

Each case uses the same concrete allocation addresses on both executions while
keeping all bytes symbolic.  Enumerating nullability, set partitions, and
allocation order covers pointer equality, legal aliasing, and relational
ordering without asking angr to emulate a symbolic-address heap.
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import product
from typing import Iterable

import claripy

from pdb_frontend import ABISignature


@dataclass(frozen=True)
class GlobalObject:
    logical_id: str
    address: int
    size: int


@dataclass(frozen=True)
class PointerGlobal:
    logical_id: str
    address: int
    pointee_size: int


@dataclass(frozen=True)
class AliasScenario:
    name: str
    arguments: tuple[claripy.ast.BV, ...]
    initial_memory: tuple[tuple[int, claripy.ast.BV], ...]
    pointer_partition: tuple[int | None, ...]
    constraints: tuple[claripy.ast.Bool, ...] = ()


class AliasCaseLimit(ValueError):
    pass


def symbolic_alias_scenario(
    signature: ABISignature,
    *,
    globals: tuple[GlobalObject, ...] = (),
    pointer_globals: tuple[PointerGlobal, ...] = (),
    allocation_base: int = 0x300000,
    allocation_stride: int = 0x10000,
    include_null: bool = True,
) -> AliasScenario:
    """Represent every finite null/alias/order case in one solver domain.

    Each pointer chooses a null value, any canonical fresh allocation, or any
    size-compatible typed global.  Sharing a choice expresses aliasing.  Since
    pointers independently choose any fresh slot, every allocation ordering is
    represented without eagerly enumerating Bell partitions and permutations.
    """
    pointer_positions = [
        index for index, value in enumerate(signature.parameters) if value.pointer
    ]
    for index in pointer_positions:
        if signature.parameters[index].pointee_size is None:
            raise ValueError(
                f"pointer argument {index} ({signature.parameters[index].name}) "
                "has unknown pointee size"
            )
    entity_sizes = [
        signature.parameters[position].pointee_size or 0
        for position in pointer_positions
    ] + [item.pointee_size for item in pointer_globals]
    entity_count = len(entity_sizes)
    if not entity_count:
        arguments = tuple(
            claripy.BVS(f"abi_arg_{index}", parameter.size * 8, explicit_name=True)
            for index, parameter in enumerate(signature.parameters)
        )
        return AliasScenario("symbolic", arguments, (), (), ())

    maximum_size = max(entity_sizes)
    if maximum_size <= 0:
        raise ValueError("pointer model requires a positive pointee size")
    allocation_stride = max(
        allocation_stride, (maximum_size + 0xFFF) & ~0xFFF,
    )
    fresh_addresses = tuple(
        allocation_base + index * allocation_stride for index in range(entity_count)
    )
    pointers = tuple(
        claripy.BVS(f"alias_pointer_{index}", 32, explicit_name=True)
        for index in range(entity_count)
    )
    constraints: list[claripy.ast.Bool] = []
    for pointer, size in zip(pointers, entity_sizes, strict=True):
        choices = [*fresh_addresses]
        choices.extend(item.address for item in globals if item.size >= size)
        if include_null:
            choices.append(0)
        constraints.append(claripy.Or(*(pointer == value for value in choices)))

    restricted = {
        ordinal for ordinal, position in enumerate(pointer_positions)
        if signature.parameters[position].restrict
    }
    for restricted_ordinal in restricted:
        for other in range(entity_count):
            if other == restricted_ordinal:
                continue
            constraints.append(claripy.Or(
                pointers[restricted_ordinal] == 0,
                pointers[other] == 0,
                pointers[restricted_ordinal] != pointers[other],
            ))

    arguments: list[claripy.ast.BV] = []
    pointer_ordinal = 0
    for index, parameter in enumerate(signature.parameters):
        if parameter.pointer:
            arguments.append(pointers[pointer_ordinal])
            pointer_ordinal += 1
        else:
            arguments.append(claripy.BVS(
                f"abi_arg_{index}", parameter.size * 8, explicit_name=True,
            ))
    memory = [
        (address, claripy.BVS(
            f"alias_object_{index}_{maximum_size}", maximum_size * 8,
            explicit_name=True,
        ))
        for index, address in enumerate(fresh_addresses)
    ]
    memory.extend(
        (item.address, pointers[index])
        for index, item in enumerate(pointer_globals, start=len(pointer_positions))
    )
    return AliasScenario(
        "symbolic", tuple(arguments), tuple(memory),
        tuple(None for _ in pointer_positions), tuple(constraints),
    )


def _partitions(count: int, restricted: frozenset[int]) -> Iterable[tuple[int, ...]]:
    groups: list[int] = []

    def visit(index: int, next_group: int):
        if index == count:
            yield tuple(groups)
            return
        choices = range(next_group + 1)
        for group in choices:
            if group < next_group:
                members = [position for position, existing in enumerate(groups) if existing == group]
                if index in restricted or any(member in restricted for member in members):
                    continue
            groups.append(group)
            yield from visit(index + 1, max(next_group, group + 1))
            groups.pop()

    yield from visit(0, 0)


def iter_alias_scenarios(
    signature: ABISignature,
    *,
    globals: tuple[GlobalObject, ...] = (),
    pointer_globals: tuple[PointerGlobal, ...] = (),
    allocation_base: int = 0x300000,
    allocation_stride: int = 0x10000,
    include_null: bool = True,
    maximum_cases: int | None = None,
) -> Iterable[AliasScenario]:
    pointer_positions = [index for index, value in enumerate(signature.parameters) if value.pointer]
    for index in pointer_positions:
        if signature.parameters[index].pointee_size is None:
            raise ValueError(
                f"pointer argument {index} ({signature.parameters[index].name}) has unknown pointee size"
            )
    entity_sizes = [
        signature.parameters[position].pointee_size or 0
        for position in pointer_positions
    ] + [item.pointee_size for item in pointer_globals]
    restricted = frozenset(
        ordinal for ordinal, position in enumerate(pointer_positions)
        if signature.parameters[position].restrict
    )
    entity_count = len(entity_sizes)
    allocation_stride = max(
        allocation_stride,
        ((max(entity_sizes, default=1) + 0xFFF) & ~0xFFF),
    )
    generated = 0
    null_masks = product((False, True), repeat=entity_count) if include_null else [(False,) * entity_count]
    for null_mask in null_masks:
        live_ordinals = [index for index, is_null in enumerate(null_mask) if not is_null]
        live_restricted = frozenset(
            live_ordinals.index(index) for index in live_ordinals if index in restricted
        )
        for partition in _partitions(len(live_ordinals), live_restricted):
            group_count = max(partition, default=-1) + 1
            fresh_addresses = tuple(
                allocation_base + index * allocation_stride for index in range(group_count)
            )
            group_sizes = tuple(
                max(
                    entity_sizes[live_ordinals[i]]
                    for i, value in enumerate(partition) if value == group
                )
                for group in range(group_count)
            )
            global_by_address = {item.address: item for item in globals}
            choices = tuple(
                (*fresh_addresses, *(item.address for item in globals
                                     if item.size == group_sizes[group]))
                for group in range(group_count)
            )
            address_sets = product(*choices) if choices else [()]
            for addresses in address_sets:
                # Distinct partition groups are distinct allocations.
                if len(set(addresses)) != len(addresses):
                    continue
                pointer_values: list[int | None] = [None] * entity_count
                live_index = 0
                for ordinal, is_null in enumerate(null_mask):
                    if is_null:
                        pointer_values[ordinal] = 0
                    else:
                        pointer_values[ordinal] = addresses[partition[live_index]]
                        live_index += 1
                arguments: list[claripy.ast.BV] = []
                for index, parameter in enumerate(signature.parameters):
                    if parameter.pointer:
                        ordinal = pointer_positions.index(index)
                        arguments.append(claripy.BVV(pointer_values[ordinal], 32))
                    else:
                        arguments.append(claripy.BVS(
                            f"abi_arg_{index}", parameter.size * 8, explicit_name=True,
                        ))
                memory: list[tuple[int, claripy.ast.BV]] = []
                for group, address in enumerate(addresses):
                    size = group_sizes[group]
                    global_choice = global_by_address.get(address)
                    if global_choice:
                        size = max(size, global_choice.size)
                    memory.append((address, claripy.BVS(
                        f"alias_object_{group}_{size}", size * 8, explicit_name=True,
                    )))
                for ordinal, pointer_global in enumerate(
                    pointer_globals, start=len(pointer_positions),
                ):
                    memory.append((
                        pointer_global.address,
                        claripy.BVV(pointer_values[ordinal], 32),
                    ))
                description = "null=" + "".join("1" if item else "0" for item in null_mask)
                description += ";partition=" + ",".join(map(str, partition))
                selected_globals = [global_by_address[address].logical_id
                                    for address in addresses if address in global_by_address]
                if selected_globals:
                    description += ";globals=" + ",".join(selected_globals)
                if pointer_globals:
                    description += ";pointer-globals=" + ",".join(
                        f"{item.logical_id}:{pointer_values[index]}"
                        for index, item in enumerate(
                            pointer_globals, start=len(pointer_positions),
                        )
                    )
                yield AliasScenario(
                    description, tuple(arguments), tuple(memory),
                    tuple(pointer_values[:len(pointer_positions)]),
                )
                generated += 1
                if maximum_cases is not None and generated >= maximum_cases:
                    raise AliasCaseLimit(
                        f"PDB alias model requires more than {maximum_cases} cases"
                    )


def alias_scenarios(
    signature: ABISignature,
    *,
    globals: tuple[GlobalObject, ...] = (),
    pointer_globals: tuple[PointerGlobal, ...] = (),
    allocation_base: int = 0x300000,
    allocation_stride: int = 0x10000,
    include_null: bool = True,
    maximum_cases: int = 4096,
) -> tuple[AliasScenario, ...]:
    """Materialized compatibility wrapper used by small unit tests."""
    return tuple(iter_alias_scenarios(
        signature, globals=globals, pointer_globals=pointer_globals,
        allocation_base=allocation_base, allocation_stride=allocation_stride,
        include_null=include_null, maximum_cases=maximum_cases,
    ))
