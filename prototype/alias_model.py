"""Finite relational allocation cases derived from PDB pointer types.

Each case uses the same concrete allocation addresses on both executions while
keeping all bytes symbolic.  Enumerating nullability, set partitions, interior
placements, and allocation order covers pointer equality, legal aliasing,
partial overlap, and relational ordering without asking angr to emulate a
symbolic-address heap.
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import permutations, product
from typing import Callable, Iterable

import claripy

from pdb_frontend import ABISignature


# Fresh allocations live far from the image, the synthetic constant and TLS
# ranges (0x20000000-0x24000000), and the modeled stack (below 0x7FFF0000).
ALLOCATION_BASE = 0x40000000
ALLOCATION_LIMIT = 0x7F000000


@dataclass(frozen=True)
class GlobalObject:
    logical_id: str
    address: int
    size: int
    type_index: int | None = None


@dataclass(frozen=True)
class PointerGlobal:
    logical_id: str
    address: int
    pointee_size: int
    pointee_type: int | None = None


@dataclass(frozen=True)
class DerivedPointer:
    """A pointer discovered during execution rather than declared up front.

    ``key`` names where the pointer value lives: ``("slot", root, offset,
    epoch)`` for a pointer stored in memory, where ``root`` is ``("global",)``
    (``offset`` is then an absolute address) or ``("entity", key)`` (inside
    another entity's pointee), or ``("return", ordinal, symbol)`` for a
    callee's return value.
    """

    key: tuple
    pointee_size: int
    pointee_type: int | None = None


@dataclass(frozen=True)
class AliasScenario:
    name: str
    arguments: tuple[claripy.ast.BV, ...]
    initial_memory: tuple[tuple[int, claripy.ast.BV], ...]
    pointer_partition: tuple[int | None, ...]
    constraints: tuple[claripy.ast.Bool, ...] = ()
    # Every entity's pointer value, keyed ("param", index) or by derived key.
    pointer_values: tuple[tuple[tuple, int], ...] = ()


class AliasCaseLimit(ValueError):
    pass


# (outer type, outer size, inner type, inner size) -> offsets at which an
# object of the inner type may lie inside the outer object, or None when the
# types are unknown and every aligned offset must be considered.
Placements = Callable[[int | None, int, int | None, int], "tuple[int, ...] | None"]


def aligned_offsets(outer_size: int, inner_size: int) -> tuple[int, ...]:
    """Every naturally aligned offset of an inner object inside an outer one."""
    if inner_size > outer_size:
        return ()
    alignment = 1
    while alignment < 4 and alignment * 2 <= inner_size and inner_size % (alignment * 2) == 0:
        alignment *= 2
    return tuple(range(0, outer_size - inner_size + 1, alignment))


def _interior_offsets(placements: Placements | None, outer: tuple[int, int | None],
                      inner: tuple[int, int | None]) -> tuple[int, ...]:
    """Offsets for ``inner`` inside ``outer``.

    Equal-sized objects may always coincide: MSVC does not exploit type-based
    aliasing, so full overlap is admitted regardless of declared types.
    Interior placements follow the PDB layout when both types are known.
    """
    outer_size, outer_type = outer
    inner_size, inner_type = inner
    offsets: set[int] = {0} if outer_size == inner_size else set()
    typed = (
        placements(outer_type, outer_size, inner_type, inner_size)
        if placements is not None else None
    )
    offsets.update(aligned_offsets(outer_size, inner_size) if typed is None else typed)
    return tuple(sorted(offset for offset in offsets if offset + inner_size <= outer_size))


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


def straddling_offsets(outer_size: int, inner_size: int) -> tuple[int, ...]:
    """Aligned offsets where an inner object partially overlaps an outer one
    without being contained in it (starting before it or ending after it)."""
    alignment = aligned_offsets(max(inner_size, 1) * 2, max(inner_size, 1))
    step = alignment[1] - alignment[0] if len(alignment) > 1 else 1
    return tuple(
        offset for offset in range(-inner_size + step, outer_size, step)
        if (offset < 0 or offset + inner_size > outer_size) and
        offset < outer_size and offset + inner_size > 0
    )


def _group_layouts(members: list[int], entities: list[tuple[int, int | None]],
                   placements: Placements | None):
    """Yield (host entity, {member: offset}) for one alias group.

    Members are placed relative to the group's largest pointee (the host).
    With PDB types for both, only layout-contained placements are used:
    distinct complete C++ objects do not partially overlap. Without types,
    members may also straddle the host (start before it or run past its end),
    so partial overlaps are enumerated.
    """
    host = max(members, key=lambda member: entities[member][0])
    options = []
    for member in members:
        if member == host:
            offsets: tuple[int, ...] = (0,)
        else:
            offsets = _interior_offsets(placements, entities[host], entities[member])
            typed = placements is not None and placements(
                entities[host][1], entities[host][0], entities[member][1], entities[member][0],
            ) is not None
            if not typed:
                offsets = (*offsets, *straddling_offsets(entities[host][0], entities[member][0]))
        if not offsets:
            return
        options.append(offsets)
    for chosen in product(*options):
        yield host, dict(zip(members, chosen, strict=True))



def iter_alias_scenarios(
    signature: ABISignature,
    *,
    globals: tuple[GlobalObject, ...] = (),
    pointer_globals: tuple[PointerGlobal, ...] = (),
    allocation_base: int = ALLOCATION_BASE,
    allocation_stride: int = 0x10000,
    include_null: bool = True,
    maximum_cases: int | None = None,
    placements: Placements | None = None,
    derived: tuple[DerivedPointer, ...] = (),
) -> Iterable[AliasScenario]:
    pointer_positions = [index for index, value in enumerate(signature.parameters) if value.pointer]
    for index in pointer_positions:
        if signature.parameters[index].pointee_size is None:
            raise ValueError(
                f"pointer argument {index} ({signature.parameters[index].name}) has unknown pointee size"
            )
    entities: list[tuple[int, int | None]] = [
        (signature.parameters[position].pointee_size or 0,
         signature.parameters[position].pointee_type)
        for position in pointer_positions
    ] + [(item.pointee_size, item.pointee_type) for item in pointer_globals] + [
        (item.pointee_size, item.pointee_type) for item in derived
    ]
    keys = (
        *(("param", position) for position in pointer_positions),
        *(("pointer-global", item.address) for item in pointer_globals),
        *(item.key for item in derived),
    )
    restricted = frozenset(
        ordinal for ordinal, position in enumerate(pointer_positions)
        if signature.parameters[position].restrict
    )
    entity_count = len(entities)
    # A group with a straddling member spans up to twice the largest pointee.
    allocation_stride = max(
        allocation_stride,
        ((2 * max((size for size, _ in entities), default=1) + 0xFFF) & ~0xFFF),
    )
    if allocation_base + entity_count * allocation_stride > ALLOCATION_LIMIT:
        raise ValueError("fresh pointer allocations exceed the reserved address range")
    fresh_addresses = tuple(
        allocation_base + index * allocation_stride for index in range(entity_count)
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
            groups = [
                [live_ordinals[i] for i, value in enumerate(partition) if value == group]
                for group in range(group_count)
            ]
            layouts = [list(_group_layouts(members, entities, placements)) for members in groups]
            for layout in product(*layouts):
                hosts = [entities[host] for host, _ in layout]
                # Each group is either a distinct fresh allocation, in every
                # relative order, or lies inside a referenced global.
                global_choices = [
                    tuple(
                        (item.address + offset, item)
                        for item in globals
                        for offset in _interior_offsets(
                            placements, (item.size, item.type_index), host,
                        )
                    )
                    for host in hosts
                ]
                for global_mask in product((False, True), repeat=group_count):
                    if any(mask and not global_choices[group]
                           for group, mask in enumerate(global_mask)):
                        continue
                    fresh_groups = [group for group in range(group_count) if not global_mask[group]]
                    for order in permutations(range(len(fresh_groups))):
                        options: list[tuple] = [()] * group_count
                        for position, group in enumerate(fresh_groups):
                            options[group] = ((fresh_addresses[order[position]], None),)
                        for group in range(group_count):
                            if global_mask[group]:
                                options[group] = global_choices[group]
                        for chosen in product(*options):
                            scenario = _scenario(
                                signature, pointer_positions, pointer_globals,
                                null_mask, partition, layout, hosts, chosen, keys,
                                entities,
                            )
                            if scenario is None:
                                continue
                            yield scenario
                            generated += 1
                            if maximum_cases is not None and generated >= maximum_cases:
                                raise AliasCaseLimit(
                                    f"PDB alias model requires more than {maximum_cases} cases"
                                )


def _scenario(signature, pointer_positions, pointer_globals, null_mask, partition,
              layout, hosts, chosen, keys, entities) -> AliasScenario | None:
    bases = []
    extents = []
    for group, (address, owner) in enumerate(chosen):
        offsets = layout[group][1]
        low = min(offset for offset in offsets.values())
        high = max(offset + entities[member][0] for member, offset in offsets.items())
        # A fresh group starts at its slot even when a member straddles the
        # host from below; inside a global, the host keeps its placement.
        base = address - min(low, 0) if owner is None else address
        bases.append(base)
        extents.append((base + low, base + high))
    # Distinct groups are distinct, non-overlapping objects.
    if any(left[0] < right[1] and right[0] < left[1]
           for index, left in enumerate(extents) for right in extents[index + 1:]):
        return None
    pointer_values: list[int] = [0] * len(null_mask)
    for group, (_, offsets) in enumerate(layout):
        for member, offset in offsets.items():
            pointer_values[member] = bases[group] + offset
    arguments: list[claripy.ast.BV] = []
    for index, parameter in enumerate(signature.parameters):
        if parameter.pointer:
            arguments.append(claripy.BVV(pointer_values[pointer_positions.index(index)], 32))
        else:
            arguments.append(claripy.BVS(
                f"abi_arg_{index}", parameter.size * 8, explicit_name=True,
            ))
    # Pointee contents are modeled lazily by address like any other memory,
    # so pointers stored inside them can themselves be followed.
    memory: list[tuple[int, claripy.ast.BV]] = []
    for ordinal, pointer_global in enumerate(pointer_globals, start=len(pointer_positions)):
        memory.append((pointer_global.address, claripy.BVV(pointer_values[ordinal], 32)))
    description = "null=" + "".join("1" if item else "0" for item in null_mask)
    description += ";partition=" + ",".join(map(str, partition))
    interior = [
        f"{member}+{offset}" for _, offsets in layout
        for member, offset in sorted(offsets.items()) if offset
    ]
    if interior:
        description += ";interior=" + ",".join(interior)
    description += ";bases=" + ",".join(f"{base:x}" for base in bases)
    selected_globals = [
        f"{item.logical_id}+{address - item.address}"
        for address, item in chosen if item is not None
    ]
    if selected_globals:
        description += ";globals=" + ",".join(selected_globals)
    if pointer_globals:
        description += ";pointer-globals=" + ",".join(
            f"{item.logical_id}:{pointer_values[index]}"
            for index, item in enumerate(pointer_globals, start=len(pointer_positions))
        )
    return AliasScenario(
        description, tuple(arguments), tuple(memory),
        tuple(pointer_values[:len(pointer_positions)]),
        pointer_values=tuple(zip(keys, pointer_values, strict=True)),
    )


def alias_scenarios(
    signature: ABISignature,
    *,
    globals: tuple[GlobalObject, ...] = (),
    pointer_globals: tuple[PointerGlobal, ...] = (),
    allocation_base: int = ALLOCATION_BASE,
    allocation_stride: int = 0x10000,
    include_null: bool = True,
    maximum_cases: int = 4096,
    placements: Placements | None = None,
    derived: tuple[DerivedPointer, ...] = (),
) -> tuple[AliasScenario, ...]:
    """Materialized compatibility wrapper used by small unit tests."""
    return tuple(iter_alias_scenarios(
        signature, globals=globals, pointer_globals=pointer_globals,
        allocation_base=allocation_base, allocation_stride=allocation_stride,
        include_null=include_null, maximum_cases=maximum_cases,
        placements=placements, derived=derived,
    ))
