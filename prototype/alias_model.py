"""Finite relational allocation cases derived from PDB pointer types.

Each case uses the same concrete allocation addresses on both executions while
keeping all bytes symbolic.  Enumerating nullability, set partitions, interior
placements, and allocation order covers pointer equality, legal aliasing,
partial overlap, and relational ordering without asking angr to emulate a
symbolic-address heap.
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import product
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
    bias: int = 0


@dataclass(frozen=True)
class AliasScenario:
    name: str
    arguments: tuple[claripy.ast.BV, ...]
    initial_memory: tuple[tuple[int, claripy.ast.BV], ...]
    pointer_partition: tuple[int | None, ...]
    constraints: tuple[claripy.ast.Bool, ...] = ()
    # Every entity's pointer value, keyed ("param", index) or by derived key.
    pointer_values: tuple[tuple[tuple, object], ...] = ()
    # Symbolic fresh-object bases and the canonical address storing each.
    address_map: tuple[tuple[claripy.ast.BV, int], ...] = ()
    # (entity key, canonical pointer, lowest, highest byte offset) per entity.
    objects: tuple[tuple[tuple, int, int, int], ...] = ()
    allocation_stride: int = 0


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
            offsets = _interior_offsets(placements, entities[host][:2], entities[member][:2])
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
    extents: dict[tuple, tuple[int, int, int | None]] | None = None,
    reserved: tuple[tuple[int, int], ...] = (),
) -> Iterable[AliasScenario]:
    """Enumerate null, alias-partition, placement and global cases.

    A fresh object has a symbolic base address constrained only by what real
    allocations guarantee: not null, no wrap-around, and no overlap with the
    other fresh objects, the referenced globals or ``reserved`` ranges. Its
    bytes are stored at a canonical address (``address_map``), so pointer
    arithmetic and comparisons stay symbolic while memory stays concrete.

    ``extents`` overrides an entity's (size, bias, type): the pointer
    addresses ``bias`` bytes into an object of ``size`` bytes.
    """
    pointer_positions = [index for index, value in enumerate(signature.parameters) if value.pointer]
    for index in pointer_positions:
        if signature.parameters[index].pointee_size is None:
            raise ValueError(
                f"pointer argument {index} ({signature.parameters[index].name}) has unknown pointee size"
            )
    keys = (
        *(("param", position) for position in pointer_positions),
        *(("pointer-global", item.address) for item in pointer_globals),
        *(item.key for item in derived),
    )
    declared = [
        (signature.parameters[position].pointee_size or 0, 0,
         signature.parameters[position].pointee_type)
        for position in pointer_positions
    ] + [(item.pointee_size, 0, item.pointee_type) for item in pointer_globals] + [
        (item.pointee_size, item.bias, item.pointee_type) for item in derived
    ]
    overrides = extents or {}
    # (size, type, bias), the order _group_layouts expects.
    entities: list[tuple[int, int | None, int]] = []
    for key, (size, bias, type_index) in zip(keys, declared, strict=True):
        size, bias, type_index = overrides.get(key, (size, bias, type_index))
        entities.append((max(size, 1), type_index, bias))
    restricted = frozenset(
        ordinal for ordinal, position in enumerate(pointer_positions)
        if signature.parameters[position].restrict
    )
    entity_count = len(entities)
    # A group with a straddling member spans up to twice the largest pointee;
    # each canonical object is centred in a window of twice that, so accesses
    # just outside an object are attributable to it.
    allocation_stride = max(
        allocation_stride,
        ((4 * max((size for size, _, _ in entities), default=1) + 0xFFF) & ~0xFFF),
    )
    if allocation_base + (entity_count + 1) * allocation_stride > ALLOCATION_LIMIT:
        raise ValueError("fresh pointer allocations exceed the reserved address range")
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
                # Each group is a distinct fresh object or lies inside a
                # referenced global.
                global_choices = [
                    tuple(
                        (item.address + offset, item)
                        for item in globals
                        for offset in _interior_offsets(
                            placements, (item.size, item.type_index), host[:2],
                        )
                    )
                    for host in hosts
                ]
                for global_mask in product((False, True), repeat=group_count):
                    if any(mask and not global_choices[group]
                           for group, mask in enumerate(global_mask)):
                        continue
                    options = [
                        global_choices[group] if global_mask[group] else ((None, None),)
                        for group in range(group_count)
                    ]
                    for chosen in product(*options):
                        scenario = _scenario(
                            signature, pointer_positions, pointer_globals,
                            null_mask, partition, layout, chosen, keys, entities,
                            globals, reserved, allocation_base, allocation_stride,
                        )
                        if scenario is None:
                            continue
                        yield scenario
                        generated += 1
                        if maximum_cases is not None and generated >= maximum_cases:
                            raise AliasCaseLimit(
                                f"PDB alias model requires more than {maximum_cases} cases"
                            )


def _disjoint(start, size: int, other_start, other_size: int) -> claripy.ast.Bool:
    return claripy.Or(
        claripy.ULE(start + size, other_start),
        claripy.UGE(start, other_start + other_size),
    )


def _scenario(signature, pointer_positions, pointer_globals, null_mask, partition,
              layout, chosen, keys, entities, globals, reserved,
              allocation_base, allocation_stride) -> AliasScenario | None:
    pointer_values: list = [claripy.BVV(0, 32)] * len(null_mask)
    canonical_pointers: list[int] = [0] * len(null_mask)
    address_map: list[tuple[claripy.ast.BV, int]] = []
    constraints: list[claripy.ast.Bool] = []
    fresh: list[tuple[claripy.ast.BV, int]] = []
    concrete_extents: list[tuple[int, int]] = []
    objects: list[tuple[tuple, int, int, int]] = []
    for group, ((_, offsets), (address, owner)) in enumerate(zip(layout, chosen, strict=True)):
        low = min(offsets.values())
        high = max(offset + entities[member][0] for member, offset in offsets.items())
        if owner is None:
            slot = len(fresh)
            canonical = allocation_base + slot * allocation_stride + allocation_stride // 2
            base = claripy.BVS(f"alias_base_{slot}", 32, explicit_name=True)
            extent = high - low
            constraints.extend((
                claripy.UGE(base, 0x10000),
                claripy.ULE(base, 0xFFFFFFFF - extent),
                *(_disjoint(base, extent, other, other_extent) for other, other_extent in fresh),
                *(_disjoint(base, extent, claripy.BVV(item.address, 32), item.size)
                  for item in globals),
                *(_disjoint(base, extent, claripy.BVV(start, 32), size) for start, size in reserved),
            ))
            fresh.append((base, extent))
            address_map.append((base, canonical))
            for member, offset in offsets.items():
                start = offset - low
                bias = entities[member][2]
                pointer_values[member] = base + (start + bias)
                canonical_pointers[member] = canonical + start + bias
        else:
            concrete_extents.append((address + low, address + high))
            for member, offset in offsets.items():
                bias = entities[member][2]
                pointer_values[member] = claripy.BVV(address + offset + bias, 32)
                canonical_pointers[member] = address + offset + bias
        for member in offsets:
            size, _, bias = entities[member]
            objects.append((keys[member], canonical_pointers[member], -bias, size - bias))
    # Distinct groups placed in globals are distinct, non-overlapping objects.
    if any(left[0] < right[1] and right[0] < left[1]
           for index, left in enumerate(concrete_extents)
           for right in concrete_extents[index + 1:]):
        return None
    arguments: list[claripy.ast.BV] = []
    for index, parameter in enumerate(signature.parameters):
        if parameter.pointer:
            arguments.append(pointer_values[pointer_positions.index(index)])
        else:
            arguments.append(claripy.BVS(
                f"abi_arg_{index}", parameter.size * 8, explicit_name=True,
            ))
    memory: list[tuple[int, claripy.ast.BV]] = [
        (pointer_global.address, pointer_values[ordinal])
        for ordinal, pointer_global in enumerate(pointer_globals, start=len(pointer_positions))
    ]
    description = "null=" + "".join("1" if item else "0" for item in null_mask)
    description += ";partition=" + ",".join(map(str, partition))
    interior = [
        f"{member}{offset:+d}" for _, offsets in layout
        for member, offset in sorted(offsets.items()) if offset
    ]
    if interior:
        description += ";interior=" + ",".join(interior)
    selected_globals = [
        f"{item.logical_id}+{address - item.address}"
        for address, item in chosen if item is not None
    ]
    if selected_globals:
        description += ";globals=" + ",".join(selected_globals)
    return AliasScenario(
        description, tuple(arguments), tuple(memory),
        tuple(canonical_pointers[:len(pointer_positions)]),
        tuple(constraints),
        pointer_values=tuple(zip(keys, pointer_values, strict=True)),
        address_map=tuple(address_map),
        objects=tuple(objects),
        allocation_stride=allocation_stride,
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
